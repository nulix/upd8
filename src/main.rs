use anyhow::{Result, Context};
use log::{info, debug, warn, error};
use std::process::exit;
use std::thread::sleep;
use std::time::Duration;
use nix::sys::reboot::{reboot, RebootMode};

mod auth;
mod config;
mod curl;
mod machine;
mod ostree;
mod utils;

use auth::TokenManager;
use config::load_config;
use ostree::{
    init_ostree, list_refs, add_remote, list_remotes, get_remote_url, pull, resolve_checksum,
    log_commit, get_os_version_from_commit, list_deployments, admin_status, deploy, undeploy,
    is_rollback_deployment_active,
};
use utils::exec_cmd;

const CONFIG_FILE_PATH: &str = "/etc/upd8/config.yml";

fn main() -> Result<()> {
    // Initialize logging with a default RUST_LOG value
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }
    env_logger::init();

    // Parse the yaml config file
    let config = load_config(CONFIG_FILE_PATH)
        .map_err(|e| {
            error!("Failed to load configuration from {}: {:?}", CONFIG_FILE_PATH, e);
            e
        })?;
    info!(
        "Loaded config: api_url={}, remote_name={}, branch={}, update_interval={}, max_deployments={}, auto_reboot={}",
        config.api_url, config.remote_name, config.branch, config.update_interval, config.max_deployments, config.auto_reboot
    );

    // Initialize the machine
    let machine: machine::Machine = machine::init()
        .with_context(|| "Machine initialization failed")?;

    // Register the machine on the platform if not already registered
    if let Err(e) = machine::register(&config.api_url, machine.uuid(), machine.name(), machine.description()) {
        error!("Failed to register machine: {}", e);
        exit(1); // Exit if registration fails
    }

    // Init bearer token manager
    let mut token_manager = TokenManager::new(config.api_url.clone());

    // Send currently booted OS version to the platform
    if let Err(e) = machine::os_version(&config.api_url, machine.os_version(), &mut token_manager) {
        error!("Failed to send OS version: {}", e);
    }

    // Initialize ostree repository
    let ostree = init_ostree()
        .with_context(|| "Failed to initialize ostree")?;

    // Add remote (do this only once at startup)
    add_remote(&ostree, &config.remote_name, &config.api_url)
        .with_context(|| format!("Failed to add remote {}", config.remote_name))?;

    // List remotes
    let remotes = list_remotes(&ostree)
        .with_context(|| "Failed to list remotes")?;
    for r in remotes {
        debug!("Existing remote(s): {}", r);
    }

    // And their URLs
    let remote_url = get_remote_url(&ostree, &config.remote_name)
        .with_context(|| format!("Failed to get URL for remote {}", config.remote_name))?;
    debug!("Remote \"{}\", URL: {}", config.remote_name, remote_url);

    // List local refs
    debug!("Listing local refs in the repository:");
    let refs = list_refs(&ostree)?;
    for r in refs {
        debug!("{}", r);
    }

    // Mimic ostree admin status
    info!("ostree admin status:");
    if let Err(e) = admin_status(&ostree) {
        error!("Failed to get admin status: {}", e);
    }

    // Check if we just booted into a rollback deployment or not
    let mut rollback_deployment = false;
    if is_rollback_deployment_active(&ostree)? {
        info!("Booted into a rollback deployment");

        rollback_deployment = true;

        // Update OTA status on the platform
        if let Err(e) = machine::ota_status(&config.api_url, &(machine::OtaUpdateStatus::Rollback as u8), machine.os_version(), &mut token_manager) {
            error!("Failed to send OTA status: {}", e);
        }
    } else {
        info!("Booted into a normal deployment");

        // Update OTA status on the platform
        if let Err(e) = machine::ota_status(&config.api_url, &(machine::OtaUpdateStatus::Ok as u8), machine.os_version(), &mut token_manager) {
            error!("Failed to send OTA status: {}", e);
        }
    }

    // Check number of deployments
    let deployments = list_deployments(&ostree)
        .with_context(|| "Failed to list deployments")?;
    debug!("Existing deployments count: {}", deployments.len());

    // Remove previous deployments
    if deployments.len() > config.max_deployments {
        debug!("Deployments count > {}, will attempt to undeploy unused deployments", config.max_deployments);

        let mut indexes_to_undeploy: Vec<usize> =
            (config.max_deployments..deployments.len()).collect();

        // Crucial: Sort in descending order to avoid index shifting problems.
        // When you undeploy index 2, what was index 3 becomes the new index 2.
        // By going 4 -> 3 -> 2, you always target the correct original index.
        indexes_to_undeploy.sort_by(|a, b| b.cmp(a));

        for idx in indexes_to_undeploy {
            // Retrieve details for logging from the original list (if available).
            if let Some((osname, checksum)) = deployments.get(idx) {
                info!(
                    "Attempting to undeploy: index={}, OS='{}', commit='{}'",
                    idx,
                    osname,
                    checksum
                );
            } else {
                info!("Attempting to undeploy: index={}", idx);
            }

            match undeploy(idx) {
                Ok(_) => {
                    info!("Index {} undeployed", idx);
                },
                Err(e) => {
                    error!("Failed to clean up deployment at index {}: {}", idx, e);
                }
            }
        }

        // List deployments again after undeploying
        let deployments = list_deployments(&ostree)
            .with_context(|| "Failed to list deployments after undeploy")?;
        debug!("Current deployments after undeploy:");
        for (i, (osname, csum)) in deployments.into_iter().enumerate() {
            debug!("[{}]: OS={}, csum={}", i, osname, csum);
        }
    }

    // Command to execute: `fw_setenv upgrade_available 0`
    let cmd = "fw_setenv";
    let args = vec!["upgrade_available", "0"];
    exec_cmd(cmd, &args)
        .with_context(|| "Failed to execute `fw_setenv upgrade_available 0`")?;
    // Command to execute: `fw_setenv bootcount 0`
    let cmd = "fw_setenv";
    let args = vec!["bootcount", "0"];
    exec_cmd(cmd, &args)
        .with_context(|| "Failed to execute `fw_setenv bootcount 0`")?;

    info!("Starting update loop");
    loop {
        // Send heartbeat to the platform
        if let Err(e) = machine::heartbeat(&config.api_url, &mut token_manager) {
            error!("Failed to send heartbeat: {}", e);
        }

        // Check if we should rollback
        let rollback_triggered = if let Ok(status) = machine::get_rollback_trigger_status(&config.api_url, &mut token_manager) {
            debug!("Successfully retrieved rollback trigger status: {}", status);
            status // Assign the status from the Ok variant
        } else {
            false // Assign a default/fallback value on error
        };

        // Process the rollback trigger if requested by the user
        if rollback_triggered {
            // Reset the rollback trigger status on the platform
            if let Err(e) = machine::reset_rollback_trigger_status(&config.api_url, &mut token_manager) {
                error!("Failed to reset the rollback trigger status: {}", e);
            }

            if !rollback_deployment && deployments.len() > 1 {
                info!("Rollback triggered by the user, switching to the previous deployment");

                // Command to execute: `fw_setenv rollback 1`
                let cmd = "fw_setenv";
                let args = vec!["rollback", "1"];
                exec_cmd(cmd, &args)
                    .with_context(|| "Failed to execute `fw_setenv rollback 1`")?;

                // Exit the loop to allow the system to reboot into the previous deployment
                break;
            } else if rollback_deployment {
                warn!("Rollback already active, skipping further rollback actions");
            } else {
                warn!("Rollback triggered by the user, but no previous deployment available for rollback");
            }
        }

        // Update OTA status on the platform
        if let Err(e) = machine::ota_status(&config.api_url, &(machine::OtaUpdateStatus::Pulling as u8), "latest", &mut token_manager) {
            error!("Failed to send OTA status: {}", e);
        }

        // Pull updates
        if let Err(e) = pull(&ostree, &config.remote_name, &config.branch, &mut token_manager) {
            error!("Failed to pull updates: {}", e);

            // Update OTA status on the platform
            if let Err(e) = machine::ota_status(&config.api_url, &(machine::OtaUpdateStatus::Failed as u8), "latest", &mut token_manager) {
                error!("Failed to send OTA status: {}", e);
            }

            // Continue to the next iteration, don't exit the loop
            sleep(Duration::from_secs(config.update_interval));
            continue;
        }
        debug!("Pulled {}:{} into repo", config.remote_name, config.branch);

        let refspec = format!("{}:{}", config.remote_name, config.branch);
        let checksum = resolve_checksum(&ostree, &refspec)
            .with_context(|| format!("Failed to resolve checksum for {}", refspec))?;
        debug!("Pulled commit ID: {}", checksum);

        info!("Commit log for {}:", checksum);
        if let Err(e) = log_commit(&ostree, &checksum) {
            error!("Failed to log commit: {}", e);
        }

        // Get OS version string from the pulled commit
        let os_version = get_os_version_from_commit(&ostree, &checksum)
            .with_context(|| format!("Failed to get OS version from commit {}", checksum))?;
        debug!("OS version from commit {}: {}", checksum, os_version);

        // Is the pulled commit already deployed?
        // Check against the latest deployed commit (typically at index 0).
        let mut already_deployed = false;
        let (osname, csum) = &deployments[0];
        debug!("Latest deployment: OS={}, csum={}", osname, csum);
        if csum == &checksum {
            already_deployed = true;
            info!("Commit {} is already deployed", checksum);
        }

        // If the commit is not already deployed, proceed with deployment
        if !already_deployed {
            info!("Deploying commit {}", checksum);

            // Update OTA status on the platform
            if let Err(e) = machine::ota_status(&config.api_url, &(machine::OtaUpdateStatus::Deploying as u8), &os_version, &mut token_manager) {
                error!("Failed to send OTA status: {}", e);
            }

            let osname = &config.remote_name;
            if let Err(e) = deploy(&ostree, &refspec, &checksum, osname) {
                error!("Failed to deploy commit {}: {}", checksum, e);

                // Update OTA status on the platform
                if let Err(e) = machine::ota_status(&config.api_url, &(machine::OtaUpdateStatus::Failed as u8), &os_version, &mut token_manager) {
                    error!("Failed to send OTA status: {}", e);
                }

                // Continue to the next iteration, don't exit the loop
                continue;
            }
            info!("Deployed ref {}: OS={}, csum={}", refspec, osname, checksum);

            // Update OTA status on the platform
            if let Err(e) = machine::ota_status(&config.api_url, &(machine::OtaUpdateStatus::Deployed as u8), &os_version, &mut token_manager) {
                error!("Failed to send OTA status: {}", e);
            }

            // Get updated list of deployments
            let deployments = list_deployments(&ostree)
                .with_context(|| "Failed to list deployments after deploy")?;
            debug!("Current deployments after deploy:");
            for (i, (osname, csum)) in deployments.clone().into_iter().enumerate() {
                debug!("[{}]: OS={}, csum={}", i, osname, csum);
            }

            // In case of successful deployment, and if the rollback deployment was active,
            // undeploy the bad deployment (index 1 now).
            if deployments.len() > 2 && rollback_deployment {
                info!("Rollback deployment was active, undeploying bad deployment at index 1");

                if let Err(e) = undeploy(1) {
                    error!("Failed to undeploy broken deployment at index 1: {}", e);
                } else {
                    info!("Successfully undeployed broken deployment at index 1");
                }
            }

            // Command to execute: `fw_setenv upgrade_available 1`
            let cmd = "fw_setenv";
            let args = vec!["upgrade_available", "1"];
            exec_cmd(cmd, &args)
                .with_context(|| "Failed to execute `fw_setenv upgrade_available 1`")?;
            // Command to execute: `fw_setenv rollback 0`
            let cmd = "fw_setenv";
            let args = vec!["rollback", "0"];
            exec_cmd(cmd, &args)
                .with_context(|| "Failed to execute `fw_setenv rollback 0`")?;

            // Break the loop and reboot if enabled
            if config.auto_reboot {
                debug!("Auto-reboot enabled, initiating reboot now");
                break;
            }
        } else {
            info!("No new commit(s) to deploy.");

            // Update OTA status on the platform
            if rollback_deployment {
                if let Err(e) = machine::ota_status(&config.api_url, &(machine::OtaUpdateStatus::Rollback as u8), machine.os_version(), &mut token_manager) {
                    error!("Failed to send OTA status: {}", e);
                }
            } else {
                if let Err(e) = machine::ota_status(&config.api_url, &(machine::OtaUpdateStatus::InSync as u8), machine.os_version(), &mut token_manager) {
                    error!("Failed to send OTA status: {}", e);
                }
            }
        }

        // Wait for the next update interval
        sleep(Duration::from_secs(config.update_interval));
    }

    // Reboot on successful deployment if auto reboot is enabled
    info!("Initiating system reboot");

    // RB_AUTOBOOT is the standard mode for a clean reboot
    sleep(Duration::from_secs(1));
    reboot(RebootMode::RB_AUTOBOOT)
        .with_context(|| "Failed to reboot the system")?;

    // Return success after attempting reboot
    Ok(())
}
