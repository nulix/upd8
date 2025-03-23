use anyhow::{Result, Context};
use log::{info, debug, error};
use std::process::exit;
use std::thread::sleep;
use std::time::Duration;

mod config;
mod ostree;

use config::load_config;
use ostree::{
    init_ostree, list_refs, add_remote, list_remotes, get_remote_url, pull, resolve_checksum,
    log_commit, list_deployments, deploy, admin_status,
};

fn main() -> Result<()> {
    // Initialize logging with a default RUST_LOG value.
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }
    env_logger::init();

    let config = load_config("/etc/upd8/config.yml")
        .with_context(|| "Failed to load configuration")?;
    info!(
        "Loaded config: remote_name={}, server_url={}, branch={}, update_interval={}",
        config.remote_name, config.server_url, config.branch, config.update_interval
    );

    let ostree = init_ostree()
        .with_context(|| "Failed to initialize ostree")?;

    // Add remote (do this only once at startup)
    add_remote(&ostree, &config.remote_name, &config.server_url)
        .with_context(|| format!("Failed to add remote {}", config.remote_name))?;

    let remotes = list_remotes(&ostree)
        .with_context(|| "Failed to list remotes")?;
    for r in remotes {
        debug!("Remote: {}", r);
    }

    let remote_url = get_remote_url(&ostree, &config.remote_name)
        .with_context(|| format!("Failed to get URL for remote {}", config.remote_name))?;
    debug!("Remote {} URL: {}", config.remote_name, remote_url);

    debug!("Listing local refs in the repository:");
    let refs = list_refs(&ostree)?;
    for r in refs {
        debug!("{}", r);
    }

    info!("ostree admin status:");
    if let Err(e) = admin_status(&ostree) {
        error!("Failed to get ostree admin status: {}", e);
    }

    info!("Starting update loop");
    loop {
        // Pull updates
        if let Err(e) = pull(&ostree, &config.remote_name, &config.branch, &config.username, &config.password) {
            error!("Failed to pull updates: {}", e);
            // Continue to the next iteration, don't exit the loop
            sleep(Duration::from_secs(config.update_interval));
            continue;
        }
        debug!("Pulled {}:{} into repo", config.remote_name, config.branch);

        let refspec = format!("{}:{}", config.remote_name, config.branch);
        let checksum = resolve_checksum(&ostree, &refspec)
            .with_context(|| format!("Failed to resolve checksum for {}", refspec))?;
        debug!("Resolved checksum: {}", checksum);

        info!("Commit log for {}:", refspec);
        if let Err(e) = log_commit(&ostree, &checksum) {
            error!("Failed to log commit: {}", e);
            // Decide if this is a fatal error or not.  For now, continue.
        }

        let existing_deployments = list_deployments(&ostree)
            .with_context(|| "Failed to list deployments")?;
        debug!("Existing deployments count: {}", existing_deployments.len());

        let mut already_deployed = false;
        for (osname, csum) in &existing_deployments {
            debug!("Current deployment: osname={}, csum={}", osname, csum);
            if csum == &checksum {
                already_deployed = true;
                info!("Commit {} is already deployed.", checksum);
                break;
            }
        }

        if !already_deployed {
            let osname = &config.remote_name;
            if let Err(e) = deploy(&ostree, &refspec, &checksum, osname) {
                error!("Failed to deploy {}: {}", refspec, e);
                exit(1); // Exit on deployment failure.  Deployment failure is considered fatal.
            }
            info!(
                "Deployed ref {}: osname={}, csum={}",
                refspec, osname, checksum
            );

            let deployments = list_deployments(&ostree)
                .with_context(|| "Failed to list deployments after deploy")?;
            for (osname, csum) in deployments {
                debug!("Deployment: {} (checksum: {})", osname, csum);
            }
        } else {
            info!("No new commit to deploy.");
        }
        sleep(Duration::from_secs(config.update_interval));
    }
}
