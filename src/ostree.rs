use anyhow::Result;
use ostree::{Repo, Sysroot};
use glib::{prelude::ToVariant, Variant, VariantTy, VariantDict, KeyFile, GString};
use log::{debug, warn};
use std::path::Path;
use chrono::{DateTime, Utc};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

pub struct Ostree {
    pub sysroot: Sysroot,
    pub repo: Repo,
}

pub fn init_ostree() -> Result<Ostree> {
    let sysroot_path = Path::new("/sysroot");
    let sysroot = Sysroot::new(Some(&gio::File::for_path(sysroot_path)));
    sysroot.load(None::<&gio::Cancellable>)?;

    let repo_path = sysroot_path.join("ostree/repo");
    let repo = Repo::new_for_path(&repo_path);
    repo.open(None::<&gio::Cancellable>)?;

    debug!("Sysroot loaded, repo opened at: {:?}", repo_path);

    Ok(Ostree { sysroot, repo })
}

pub fn list_refs(ostree: &Ostree) -> Result<Vec<String>> {
    let refs = ostree.repo.list_refs(None::<&str>, None::<&gio::Cancellable>)?;
    Ok(refs.keys().map(|s| s.to_string()).collect())
}

pub fn add_remote(ostree: &Ostree, name: &str, url: &str) -> Result<()> {
    let existing_remotes = ostree.repo.remote_list();
    if !existing_remotes.contains(&name.into()) {
        let options = VariantDict::new(None::<&glib::Variant>);
        options.insert("gpg-verify", &false.to_variant());
        ostree.repo.remote_add(name, Some(url), Some(&options.to_variant()), None::<&gio::Cancellable>)?;
        debug!("Remote added: {}", name);
    } else {
        debug!("Remote {} already exists, skipping addition", name);
    }
    Ok(())
}

pub fn list_remotes(ostree: &Ostree) -> Result<Vec<String>> {
    Ok(ostree.repo.remote_list().into_iter().map(|s| s.to_string()).collect())
}

pub fn get_remote_url(ostree: &Ostree, name: &str) -> Result<String> {
    Ok(ostree.repo.remote_get_url(name)?.to_string())
}

//
// This function mimics:
// $ BASE64_PWD=$(echo -n "username:your-secret-password" | base64 -w 0)
// $ ostree pull --http-header "Authorization=Basic $BASE64_PWD" nulix:1/stable/rpi3
//
// Enable HTTP debug logs:
// $ export OSTREE_DEBUG_HTTP=1
//
pub fn pull(ostree: &Ostree, remote_name: &str, branch: &str, username: &str, password: &str) -> Result<()> {
    debug!("Pulling from remote: {}, branch: {}, user: {}", remote_name, branch, username);

    let pull_options = VariantDict::new(None::<&glib::Variant>);
    pull_options.insert("refs", &vec![branch.to_string()].to_variant());
    pull_options.insert("override-remote-name", &remote_name.to_variant());

    // Add the Authorization header.
    let auth_value = format!("Basic {}", BASE64.encode(format!("{}:{}", username, password)));
    let header_tuple = ("Authorization", auth_value.as_str()).to_variant();

    // Construct the http-headers Variant correctly.
    let element_ty = VariantTy::new("(ss)").map_err(|e| glib::Error::new(glib::FileError::Inval, &e.to_string()))?;
    let headers_array = vec![header_tuple];
    let http_headers = Variant::array_from_iter_with_type(&element_ty, headers_array.into_iter());

    pull_options.insert("http-headers", &http_headers);

    ostree.repo.pull_with_options(
        remote_name,
        &pull_options.to_variant(),
        None::<&ostree::AsyncProgress>,
        None::<&gio::Cancellable>,
    )?;

    debug!("Pulled {} branch from {} remote", branch, remote_name);
    Ok(())
}

pub fn resolve_checksum(ostree: &Ostree, refspec: &str) -> Result<String> {
    Ok(ostree.repo.resolve_rev(refspec, false)?
        .ok_or_else(|| anyhow::anyhow!("Failed to resolve {}", refspec))?.to_string())
}

pub fn log_commit(ostree: &Ostree, checksum: &str) -> Result<()> {
    let mut current_checksum = checksum.to_string();

    loop {
        let load_result = ostree.repo.load_commit(&current_checksum);
        match load_result {
            Ok((commit_variant, _)) => {
                println!("commit {}", current_checksum);

                // Parent checksum (index 1: ay)
                if let Some(parent_bytes) = commit_variant.child_value(1).get::<Vec<u8>>() {
                    if !parent_bytes.is_empty() {
                        let parent_hex = parent_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
                        println!("Parent:  {}", parent_hex);
                    }
                }

                // Content checksum
                let content_checksum = ostree::commit_get_content_checksum(&commit_variant)
                    .unwrap_or_else(|| GString::from("<invalid commit>"));

                println!("ContentChecksum:  {}", content_checksum);

                // Timestamp (index 5: t)
                let timestamp_variant = commit_variant.child_value(5);

                if let Some(timestamp_big_endian) = timestamp_variant.get::<u64>() {
                    let timestamp = u64::from_be(timestamp_big_endian);
                    let seconds = timestamp as i64;
                    let date = DateTime::<Utc>::from_timestamp(seconds, 0)
                        .unwrap_or_else(|| {
                            warn!(
                                "Failed to parse timestamp {} as seconds, defaulting to epoch",
                                timestamp
                            );
                            DateTime::<Utc>::from_timestamp(0, 0).unwrap()
                        });
                    println!("Date:  {}", date.format("%Y-%m-%d %H:%M:%S +0000"));
                } else {
                    warn!("Failed to get timestamp as u64");
                }

                // Metadata dictionary (index 0: a{sv}) for version
                let commit_dict: VariantDict = commit_variant
                    .child_value(0)
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Failed to convert commit metadata to VariantDict"))?;
                if let Some(version) = commit_dict.lookup_value("version", None) {
                    if let Some(version_str) = version.str() {
                        println!("Version: {}", version_str);
                    }
                }

                // Subject (index 3: s) and Body (index 4: s)
                let mut message_lines = Vec::new();
                if let Some(subject) = commit_variant.child_value(3).get::<String>() {
                    if !subject.is_empty() {
                        message_lines.push(subject);
                    }
                }
                if let Some(body) = commit_variant.child_value(4).get::<String>() {
                    if !body.is_empty() {
                        if !message_lines.is_empty() {
                            message_lines.push(String::new());
                        }
                        message_lines.push(body);
                    }
                }
                if !message_lines.is_empty() {
                    println!("\n    {}", message_lines.join("\n    "));
                }
                println!();

                // Move to parent
                if let Some(parent_bytes) = commit_variant.child_value(1).get::<Vec<u8>>() {
                    if parent_bytes.is_empty() {
                        break;
                    }
                    current_checksum = parent_bytes
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<String>();
                } else {
                    break;
                }
            }
            Err(e) => {
                if e.to_string().contains("No such metadata object") {
                    break;
                } else {
                    return Err(anyhow::anyhow!("{}", e));
                }
            }
        }
    }

    Ok(())
}

pub fn list_deployments(ostree: &Ostree) -> Result<Vec<(String, String)>> {
    let deployments = ostree.sysroot.deployments();
    Ok(deployments
        .into_iter()
        .map(|d| (d.osname().to_string(), d.csum().to_string()))
        .collect())
}

pub fn deploy(ostree: &Ostree, refspec: &str, checksum: &str, osname: &str) -> Result<()> {
    let origin = KeyFile::new();
    origin.set_string("origin", "refspec", refspec);
    origin.set_string("origin", "remote", refspec.split(':').next().unwrap_or(""));

    let new_deployment = ostree.sysroot.deploy_tree(
        Some(osname),
        checksum,
        Some(&origin),
        None::<&ostree::Deployment>,
        &[],
        None::<&gio::Cancellable>,
    )?;

    let mut new_deployments = vec![new_deployment];
    let existing_deployments = ostree.sysroot.deployments();
    new_deployments.extend(existing_deployments.into_iter().filter(|d| d.csum() != checksum));
    ostree.sysroot.write_deployments(&new_deployments, None::<&gio::Cancellable>)?;
    Ok(())
}

pub fn admin_status(ostree: &Ostree) -> Result<()> {
    let deployments = ostree.sysroot.deployments();
    if deployments.is_empty() {
        println!("No deployments found.");
        return Ok(());
    }

    for deployment in deployments {
        let osname = deployment.osname();
        let checksum = deployment.csum();
        let origin = deployment.origin();

        println!("  {} {}", osname, checksum);

        // Get version
        let repo = &ostree.repo;
        let commit_variant = repo.load_commit(&checksum).ok().map(|(v, _)| v);

        if let Some(variant) = commit_variant {
             let commit_dict: VariantDict = variant
                .child_value(0)
                .try_into()
                .map_err(|_| anyhow::anyhow!("Failed to convert commit metadata to VariantDict"))?;
            if let Some(version) = commit_dict.lookup_value("version", None) {
                if let Some(version_str) = version.str() {
                    println!("    Version: {}", version_str);
                }
            }
        }

        // Get refspec
        if let Some(origin) = origin {
            match origin.string("origin", "refspec") {
                Ok(refspec_string) => println!("    origin refspec: {}", refspec_string),
                Err(e) => eprintln!("  Error getting refspec: {}", e), // handle the error
            }
        }
    }
    Ok(())
}
