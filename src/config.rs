use anyhow::Result;
use std::fs::File;
use std::io::BufReader;
use yaml_rust2::YamlLoader;

pub struct Config {
    pub api_url: String,
    pub remote_name: String,
    pub branch: String,
    pub update_interval: u64,
    pub max_deployments: usize,
    pub auto_reboot: bool,
}

/// Loads application configuration from a YAML file.
///
/// This function reads the file specified by `path`, parses its YAML content,
/// and extracts various configuration parameters such as API URL, remote name,
/// branch, update interval, maximum deployments, and auto-reboot setting.
///
/// # Arguments
/// * `path` - A string slice representing the path to the YAML configuration file.
///
/// # Returns
/// - `Ok(Config)` on successful loading and parsing of the configuration,
///   returning a `Config` struct containing the retrieved values.
/// - `Err(anyhow::Error)` if:
///   - The file at the specified `path` cannot be opened or read.
///   - The file's content is not valid YAML.
///   - The YAML document is empty.
///   - Any required configuration field (`api_url`, `remote_name`, `branch`,
///     `update_interval`, `max_deployments`, `auto_reboot`) is missing, invalid,
///     or of the wrong type.
pub fn load_config(path: &str) -> Result<Config> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let yaml_content = std::io::read_to_string(reader)?;
    let docs = YamlLoader::load_from_str(&yaml_content)?;
    let doc = docs
        .get(0)
        .ok_or_else(|| anyhow::anyhow!("Empty YAML document"))?;

    let api_url = doc["api_url"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'api_url'"))?
        .to_string();
    let remote_name = doc["remote_name"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'remote_name'"))?
        .to_string();
    let branch = doc["branch"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'branch'"))?
        .to_string();
    let update_interval = doc["update_interval"]
        .as_i64()
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'update_interval'"))?
        as u64;
    let max_deployments = doc["max_deployments"]
        .as_i64()
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'max_deployments'"))?
        as usize;
    let auto_reboot = doc["auto_reboot"]
        .as_bool()
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'auto_reboot'"))?
        as bool;

    Ok(Config {
        api_url,
        remote_name,
        branch,
        update_interval,
        max_deployments,
        auto_reboot,
    })
}