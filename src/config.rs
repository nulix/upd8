use anyhow::Result;
use std::fs::File;
use std::io::BufReader;
use yaml_rust2::YamlLoader;

pub struct Config {
    pub remote_name: String,
    pub server_url: String,
    pub branch: String,
    pub username: String,
    pub password: String,
    pub update_interval: u64,
}

pub fn load_config(path: &str) -> Result<Config> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let yaml_content = std::io::read_to_string(reader)?;
    let docs = YamlLoader::load_from_str(&yaml_content)?;
    let doc = docs
        .get(0)
        .ok_or_else(|| anyhow::anyhow!("Empty YAML document"))?;

    let remote_name = doc["remote_name"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'remote_name'"))?
        .to_string();
    let server_url = doc["server_url"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'server_url'"))?
        .to_string();
    let branch = doc["branch"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'branch'"))?
        .to_string();
    let username = doc["username"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'username'"))?
        .to_string();
    let password = doc["password"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'password'"))?
        .to_string();
    let update_interval = doc["update_interval"]
        .as_i64()
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid 'update_interval'"))?
        as u64;

    Ok(Config {
        remote_name,
        server_url,
        branch,
        username,
        password,
        update_interval,
    })
}