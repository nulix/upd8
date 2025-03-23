use anyhow::{Result, Context};
use ostree::{Repo, Sysroot, Deployment};
use glib::{prelude::ToVariant, Variant, VariantTy, VariantDict, KeyFile, GString};
use log::{debug, warn};
use std::path::Path;
use chrono::{DateTime, Utc};

use crate::utils::exec_cmd;

const OSTREE_REPO_URL: &str = "/ota";
const OSTREE_SYSROOT_PATH: &str = "/";
const OSTREE_REPO_PATH: &str = "ostree/repo";

pub struct Ostree {
    pub sysroot: Sysroot,
    pub repo: Repo,
}

/// Initializes and returns an `Ostree` struct, setting up the OSTree sysroot and opening the repository.
///
/// This function performs the necessary steps to prepare for OSTree operations:
/// 1. It creates and loads a `Sysroot` object, rooted at `OSTREE_SYSROOT_PATH`.
/// 2. It then creates and opens an `Repo` object, located within the sysroot at `OSTREE_REPO_PATH`.
///
/// This setup is crucial for performing various OSTree-related tasks, such as
/// deploying updates, checking for updates, or querying system status.
///
/// # Returns
/// - `Ok(Ostree)` on success, containing the loaded `Sysroot` and opened `Repo` objects.
/// - `Err(anyhow::Error)` if:
///   - The `Sysroot` cannot be loaded (e.g., `OSTREE_SYSROOT_PATH` is invalid or inaccessible).
///   - The `Repo` cannot be opened (e.g., `OSTREE_REPO_PATH` is invalid, not an OSTree repository, or inaccessible).
///   - Any underlying GIO or OSTree operation fails.
pub fn init_ostree() -> Result<Ostree> {
    let sysroot_path = Path::new(OSTREE_SYSROOT_PATH);
    let sysroot = Sysroot::new(Some(&gio::File::for_path(sysroot_path)));
    sysroot.load(None::<&gio::Cancellable>)?;

    let repo_path = sysroot_path.join(OSTREE_REPO_PATH);
    let repo = Repo::new_for_path(&repo_path);
    repo.open(None::<&gio::Cancellable>)?;

    debug!("Sysroot loaded, repo opened at: {:?}", repo_path);

    Ok(Ostree { sysroot, repo })
}

/// Lists all available refs (references) in the OSTree repository.
///
/// This function queries the OSTree repository (represented by the `repo` field
/// within the provided `Ostree` struct) to retrieve a list of all known
/// commit refs. These refs typically point to different versions or branches
/// within the OSTree system.
///
/// # Arguments
/// * `ostree` - A reference to an `Ostree` struct, which must have its
///   repository successfully opened (e.g., via `init_ostree`).
///
/// # Returns
/// - `Ok(Vec<String>)` on success, containing a vector of strings, where each
///   string is the name of an OSTree ref (e.g., "my-os/stable/x86_64").
/// - `Err(anyhow::Error)` if there's an error listing the refs from the
///   repository, or if the underlying OSTree operation fails.
pub fn list_refs(ostree: &Ostree) -> Result<Vec<String>> {
    let refs = ostree.repo.list_refs(None::<&str>, None::<&gio::Cancellable>)?;
    Ok(refs.keys().map(|s| s.to_string()).collect())
}

/// Adds a new remote repository to the OSTree configuration if it doesn't already exist.
///
/// This function first checks the existing remotes in the OSTree repository.
/// If a remote with the given `name` is not found, it constructs the full
/// remote URL by combining the `api_url` with `OSTREE_REPO_URL`. It then
/// adds this new remote to the OSTree repository, setting the `gpg-verify`
/// option to `false` for this remote.
///
/// If a remote with the specified `name` already exists, the function
/// debug logs this fact and skips the addition process, returning `Ok(())`.
///
/// # Arguments
/// * `ostree` - A reference to an `Ostree` struct, which must contain a loaded
///   and opened OSTree repository.
/// * `name` - The desired name for the new remote (e.g., "production", "staging").
/// * `api_url` - The base URL of the API, which will be prepended to
///   `OSTREE_REPO_URL` to form the complete URL for the remote.
///
/// # Returns
/// - `Ok(())` if the remote was successfully added or if it already existed.
/// - `Err(anyhow::Error)` if there is an error during the process of adding
///   the remote (e.g., OSTree operation failure, invalid URL format).
///
/// # Security Note
/// The `gpg-verify` option is explicitly set to `false` when adding the remote.
/// In production environments, it is highly recommended to enable GPG verification
/// to ensure the integrity and authenticity of fetched content. This setting
/// should be used with caution and only if you have alternative robust verification
/// mechanisms in place.
pub fn add_remote(ostree: &Ostree, name: &str, api_url: &str) -> Result<()> {
    let existing_remotes = ostree.repo.remote_list();
    if !existing_remotes.contains(&name.into()) {
        let remote_url = format!("{}{}", api_url, OSTREE_REPO_URL);
        let options = VariantDict::new(None::<&glib::Variant>);
        options.insert("gpg-verify", &false.to_variant());
        ostree.repo.remote_add(name, Some(&remote_url), Some(&options.to_variant()), None::<&gio::Cancellable>)?;
        debug!("Remote added: [{}]:({})", name, remote_url);
    } else {
        debug!("Remote {} already exists, skipping addition", name);
    }
    Ok(())
}

/// Lists all configured remotes in the OSTree repository.
///
/// This function queries the OSTree repository to get a list of all remote
/// names that have been added to its configuration.
///
/// # Arguments
/// * `ostree` - A reference to an `Ostree` struct, which must have its
///   repository successfully opened.
///
/// # Returns
/// - `Ok(Vec<String>)` on success, containing a vector of strings where each
///   string is the name of a configured OSTree remote (e.g., "production", "testing").
/// - `Err(anyhow::Error)` if there's an underlying OSTree operation error
///   during the remote listing process.
pub fn list_remotes(ostree: &Ostree) -> Result<Vec<String>> {
    Ok(ostree.repo.remote_list().into_iter().map(|s| s.to_string()).collect())
}

/// Retrieves the URL associated with a specific OSTree remote.
///
/// This function looks up the URL configured for an OSTree remote identified
/// by its `name` within the repository.
///
/// # Arguments
/// * `ostree` - A reference to an `Ostree` struct, which must have its
///   repository successfully opened.
/// * `name` - The name of the remote whose URL you want to retrieve (e.g., "production").
///
/// # Returns
/// - `Ok(String)` on success, containing the URL of the specified remote.
/// - `Err(anyhow::Error)` if:
///   - The remote with the given `name` does not exist in the repository's configuration.
///   - There's an underlying OSTree operation error during the URL retrieval process.
pub fn get_remote_url(ostree: &Ostree, name: &str) -> Result<String> {
    Ok(ostree.repo.remote_get_url(name)?.to_string())
}

/// Pulls (fetches and imports) a specific branch from a given remote OSTree repository.
///
/// This function mimics:
/// $ ostree pull --http-header "Authorization=Bearer <token>" <branch>
///
/// Enable HTTP debug logs:
/// $ export OSTREE_DEBUG_HTTP=1
///
/// This function initiates an OSTree pull operation to synchronize a particular
/// branch from a remote repository into the local repository. It handles authentication
/// by obtaining an access token and including it as an `Authorization` header
/// in the HTTP request made during the pull process.
///
/// # Arguments
/// * `ostree` - A reference to an `Ostree` struct, which must have its
///   repository successfully opened and the remote configured.
/// * `remote_name` - The name of the configured remote from which to pull (e.g., "production").
/// * `branch` - The specific branch (ref) to pull (e.g., "my-os/stable/x86_64").
/// * `token_manager` - A mutable reference to your `TokenManager` to obtain an access token
///   for authenticating the pull request.
///
/// # Returns
/// - `Ok(())` if the pull operation completes successfully.
/// - `Err(anyhow::Error)` if:
///   - An access token cannot be obtained.
///   - The specified `remote_name` or `branch` does not exist or is inaccessible.
///   - The authentication fails.
///   - An underlying OSTree operation error occurs during the pull (e.g., network issues,
///     repository corruption, invalid GPG signature if enabled elsewhere).
pub fn pull(ostree: &Ostree, remote_name: &str, branch: &str, token_manager: &mut crate::auth::TokenManager) -> Result<()> {
    debug!("Pulling from remote: {}, branch: {}", remote_name, branch);

    // Get access token (synchronous)
    let access_token = token_manager.get_access_token()
        .context("Failed to get access token for resetting rollback trigger status")?;

    let pull_options = VariantDict::new(None::<&glib::Variant>);
    pull_options.insert("refs", &vec![branch.to_string()].to_variant());
    pull_options.insert("override-remote-name", &remote_name.to_variant());

    // Add the Authorization header
    let auth_value = format!("Bearer {}", access_token);
    let header_tuple = ("Authorization", auth_value.as_str()).to_variant();

    // Construct the http-headers Variant correctly
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

/// Resolves a refspec to its full commit checksum in the OSTree repository.
///
/// This function attempts to resolve an OSTree refspec (e.g., a branch name like
/// "my-os/stable/x86_64" or a partial commit ID) to its complete, unique
/// commit checksum.
///
/// # Arguments
/// * `ostree` - A reference to an `Ostree` struct, which must have its
///   repository successfully opened.
/// * `refspec` - The refspec (e.g., branch name, partial checksum) to resolve.
///
/// # Returns
/// - `Ok(String)` on success, containing the 64-character full commit checksum.
/// - `Err(anyhow::Error)` if the refspec cannot be resolved to a valid commit
///   (e.g., the refspec does not exist or is ambiguous), or if an underlying
///   OSTree operation fails.
pub fn resolve_checksum(ostree: &Ostree, refspec: &str) -> Result<String> {
    Ok(ostree.repo.resolve_rev(refspec, false)?
        .ok_or_else(|| anyhow::anyhow!("Failed to resolve {}", refspec))?.to_string())
}

/// Displays detailed information about an OSTree commit and its ancestors,
/// similar to `git log`.
///
/// This function iterates backward through the commit history starting from
/// the given `checksum`, printing details for each commit until it reaches
/// the initial commit (one with no parent). It extracts and displays the
/// commit checksum, its parent's checksum, content checksum, timestamp,
/// a 'version' from its metadata, and the commit's subject and body messages.
///
/// # Arguments
/// * `ostree` - A reference to an `Ostree` struct, which must have its
///   repository successfully opened.
/// * `checksum` - The starting 64-character commit checksum (ID) from which
///   to begin logging.
///
/// # Returns
/// - `Ok(())` if the commit log process completes successfully, even if no
///   commits are found or if the end of the history is reached.
/// - `Err(anyhow::Error)` if:
///   - There's an error loading a commit that isn't due to it not existing
///     (e.g., repository corruption, I/O error).
///   - Metadata for a commit cannot be converted to a `VariantDict`.
///   - Any underlying OSTree operation fails.
///
/// # Panics
/// This function will panic if `DateTime::<Utc>::from_timestamp` fails to
/// create a valid `DateTime` object when parsing the commit timestamp,
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

/// Gets the OS version string from the metadata of an OSTree commit.
///
/// This function resolves a refspec (like "my-os/x86_64/stable") to a commit ID,
/// loads the commit as a raw GVariant, and then extracts the "version" string
/// from its metadata.
///
/// Assumes the version string is stored under the key "version" in the commit metadata.
///
/// # Arguments
/// * `ostree` - A reference to an `Ostree` struct, which must have its
///   repository successfully opened.
/// * `refspec_or_checksum` - The refspec (e.g., "my-os/x86_64/stable") or a full commit checksum.
///
/// # Returns
/// A `Result` containing the version string on success, or an `anyhow::Error` on failure.
pub fn get_os_version_from_commit(ostree: &Ostree, refspec_or_checksum: &str) -> Result<String> {
    // Resolve the refspec to get the commit ID (checksum)
    let checksum = ostree.repo.resolve_rev(refspec_or_checksum, false)?
        .ok_or_else(|| anyhow::anyhow!("Failed to resolve refspec_or_checksum: {}", refspec_or_checksum))?
        .to_string();

    // Load the commit as a glib::Variant, consistent with your log_commit function
    let (commit_variant, _ref_variant) = ostree.repo.load_commit(&checksum)?;

    // Access the metadata dictionary. In the OSTree commit GVariant structure,
    // the metadata is typically at child index 0.
    let metadata_variant = commit_variant.child_value(0);

    // Try to convert the metadata Variant into a VariantDict
    let commit_dict: VariantDict = metadata_variant
        .try_into()
        .map_err(|_| anyhow::anyhow!("Failed to convert commit metadata to VariantDict for {}", checksum))?;

    // Look up the "version" key in the metadata dictionary
    if let Some(version_variant) = commit_dict.lookup_value("version", None) {
        // Extract the string value from the glib::Variant using .str()
        if let Some(version_str) = version_variant.str() {
            Ok(version_str.to_string()) // Convert to owned String for return
        } else {
            Err(anyhow::anyhow!("'version' metadata value is not a string for checksum {}", checksum))
        }
    } else {
        Err(anyhow::anyhow!("'version' key not found in commit metadata for checksum {}", checksum))
    }
}

/// Lists all deployed OSTree operating system versions in the sysroot.
///
/// This function queries the OSTree sysroot to retrieve information about all
/// currently deployed operating system instances. For each deployment, it
/// extracts and returns its operating system name and its associated commit checksum.
///
/// # Arguments
/// * `ostree` - A reference to an `Ostree` struct, which must have its
///   sysroot successfully loaded.
///
/// # Returns
/// - `Ok(Vec<(String, String)>)` on success, containing a vector of tuples.
///   Each tuple represents a deployment, where the first `String` is the OS name
///   and the second `String` is the 64-character commit checksum of that deployment.
/// - `Err(anyhow::Error)` if there's an underlying OSTree operation error
///   during the listing of deployments.
pub fn list_deployments(ostree: &Ostree) -> Result<Vec<(String, String)>> {
    let deployments = ostree.sysroot.deployments();
    Ok(deployments
        .into_iter()
        .map(|d| (d.osname().to_string(), d.csum().to_string()))
        .collect())
}

/// Displays a summary status of all OSTree deployments in the sysroot.
///
/// This function lists each deployed operating system, providing details such as
/// its OS name, commit checksum, unique deployment serial number, and origin refspec.
/// It marks the currently booted deployment with an asterisk (`*`) and indicates
/// the likely rollback deployment (typically the second one listed) with `(rollback)`.
/// It also attempts to extract and display the "Version" metadata from each deployment's commit.
///
/// # Arguments
/// * `ostree` - A reference to an `Ostree` struct, which must have its
///   sysroot successfully loaded and repository opened.
///
/// # Returns
/// - `Ok(())` if the deployment status is successfully retrieved and printed.
/// - `Err(anyhow::Error)` if:
///   - There are issues loading commit metadata (e.g., converting to `VariantDict`).
///   - Any underlying OSTree operation fails during the process of listing
///     deployments or retrieving their details.
pub fn admin_status(ostree: &Ostree) -> Result<()> {
    let deployments = ostree.sysroot.deployments();
    if deployments.is_empty() {
        debug!("No deployments found.");
        return Ok(());
    }

    let booted_csum = ostree.sysroot.booted_deployment()
        .map(|d| d.csum().to_string());

    for (i, deployment) in deployments.into_iter().enumerate() {
        let osname = deployment.osname();
        let checksum = deployment.csum();
        let deployserial = deployment.deployserial(); // Get the serial number!
        let origin = deployment.origin();

        // Determine prefix for current deployment
        let prefix = if let Some(ref csum) = booted_csum {
            if *csum == checksum {
                "*" // Current deployment
            } else {
                " " // Not current
            }
        } else {
            debug!("No booted deployment found by booted_deployment() method.");
            " " // No booted deployment found
        };

        // Determine if it's the rollback deployment (typically index 1)
        let rollback_suffix = if i == 1 {
            " (rollback)"
        } else {
            ""
        };

        // Modify the println! to include the deployment serial
        println!("{} {} {}.{}{}", prefix, osname, checksum, deployserial, rollback_suffix);

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

/// Deploys a specified OSTree commit as a new operating system instance in the sysroot.
///
/// The function first prepares origin metadata for the new deployment. It then calls
/// `ostree.sysroot.deploy_tree()` to perform the actual deployment. After deployment,
/// it updates the list of active deployments in the sysroot, ensuring that the new
/// deployment is recognized and any old deployments with the same checksum are removed
/// to prevent duplicates.
///
/// # Arguments
/// * `ostree` - A reference to an `Ostree` struct, which must have its sysroot successfully loaded.
/// * `refspec` - The OSTree refspec (e.g., "remote:branch") that identifies the origin of the deployment.
///   This is used to set the `refspec` and `remote` in the deployment's origin metadata.
/// * `checksum` - The 64-character commit checksum (ID) of the specific OS version to be deployed.
/// * `osname` - The name of the operating system associated with this deployment (e.g., "my-os").
///
/// # Returns
/// - `Ok(())` if the deployment process completes successfully.
/// - `Err(anyhow::Error)` if:
///   - There's an issue creating the origin metadata (`KeyFile`).
///   - The `deploy_tree` operation fails (e.g., the commit doesn't exist locally, permissions issues, or other OSTree errors).
///   - Writing the updated deployment list to the sysroot fails.
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

/// Undeploys a specific OSTree deployment by its numerical index using the `ostree admin undeploy <index>` command.
///
/// The `index` refers to the position of the deployment in the list returned by
/// `ostree admin status` (0-indexed, newest to oldest).
///
/// This function requires the application to be run with root privileges (e.g., via `sudo`).
///
/// # Arguments
/// * `index` - The numerical index of the deployment to undeploy.
///
/// # Returns
/// `Ok(())` if the undeploy operation was successful, otherwise an `anyhow::Error`.
pub fn undeploy(index: usize) -> Result<()> {
    debug!("Undeploying index {} using `ostree admin undeploy` command", index);

    // Command to execute: `ostree admin undeploy <index>`
    let cmd = "ostree";
    let index_str = index.to_string();
    let args = vec!["admin", "undeploy", index_str.as_str()];

    exec_cmd(cmd, &args)
        .with_context(|| format!("Failed to undeploy OSTree index {}", index))?;

    Ok(())
}

/// Checks if the currently booted OSTree deployment is the designated rollback deployment.
///
/// This function identifies the currently booted deployment and compares its checksum
/// against the deployment typically considered the rollback candidate (index 1 in `ostree admin status`).
///
/// # Arguments
/// * `ostree_sysroot` - A reference to the `ostree::Sysroot` instance.
///
/// # Returns
/// `Ok(true)` if the system is currently using the rollback deployment.
/// `Ok(false)` if it's using the primary/default deployment, if there are not enough
///            deployments to have a rollback candidate, or if the booted deployment
///            cannot be determined.
/// `Err(anyhow::Error)` if there's an underlying error retrieving deployment information
///            from the `Sysroot`.
pub fn is_rollback_deployment_active(ostree: &Ostree) -> Result<bool> {
    debug!("Checking if the currently active deployment is the rollback deployment");

    // Get the currently booted deployment
    let booted_deployment: Deployment = match ostree.sysroot.booted_deployment() {
        Some(d) => d,
        None => {
            warn!("Could not determine currently booted deployment. Assuming not a rollback.");
            return Ok(false);
        }
    };
    let booted_csum = booted_deployment.csum().to_string();
    debug!("Currently booted deployment checksum: {}", booted_csum);

    // Get all deployments, ordered by OSTree (newest first, so index 1 is typically rollback)
    let all_deployments = ostree.sysroot.deployments();

    // The rollback candidate is usually the second deployment (index 1) in the list.
    // If there are fewer than 2 deployments, a rollback scenario isn't present.
    if all_deployments.len() < 2 {
        debug!("Less than 2 deployments found (count: {}). Not in a distinct rollback state.", all_deployments.len());
        return Ok(false);
    }

    // Access the deployment at index 1, which represents the rollback candidate.
    let rollback_candidate_deployment = &all_deployments[1];
    let rollback_candidate_csum = rollback_candidate_deployment.csum().to_string();
    debug!("Rollback candidate deployment (index 1) checksum: {}", rollback_candidate_csum);

    // Compare checksums to see if the booted deployment matches the rollback candidate.
    if booted_csum == rollback_candidate_csum {
        debug!("The currently booted deployment (checksum {}) IS the rollback deployment", booted_csum);
        Ok(true)
    } else {
        debug!("The currently booted deployment (checksum {}) is NOT the rollback deployment", booted_csum);
        Ok(false)
    }
}
