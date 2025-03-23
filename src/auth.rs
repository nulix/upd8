use anyhow::{anyhow, Result, Context};
use age::{Decryptor, Encryptor, x25519};
use age::cli_common::{StdinGuard, read_identities};
use secrecy::{CloneableSecret, ExposeSecret};
use zeroize::Zeroize;
use std::fs::File;
use std::path::Path;
use std::io::{Read, Write, BufRead, BufReader, BufWriter};
use std::time::{Duration, Instant};

use crate::machine::get_bearer_token;

const UPD8_DIR_PATH: &str = "/var/local/upd8/";
const PRIVATE_KEY_FILE: &str = "key.txt";
const TOKEN_FILE: &str = "token.age";
const KEY_FILE: &str = "key.age";

// Define secret wrapper for registration token and ensure memory is zeroed on drop
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct RegToken(Vec<u8>);

impl CloneableSecret for RegToken {}

impl ExposeSecret<[u8]> for RegToken {
    fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for RegToken {
    fn from(data: Vec<u8>) -> Self {
        RegToken(data)
    }
}

// Define secret wrapper for API key and ensure memory is zeroed on drop
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct ApiKey(Vec<u8>);

impl CloneableSecret for ApiKey {}

impl ExposeSecret<[u8]> for ApiKey {
    fn expose_secret(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for ApiKey {
    fn from(data: Vec<u8>) -> Self {
        ApiKey(data)
    }
}

// Handle ephemeral bearer token
pub struct TokenManager {
    api_url: String,
    token: Option<String>,
    expiry: Option<Instant>,
}

impl TokenManager {
    /// Creates a new `TokenManager` instance.
    ///
    /// The manager is initialized without an active token; a token will be fetched
    /// on the first call to `get_access_token` or when the current token expires.
    ///
    /// # Arguments
    /// * `api_url` - The base URL of the API where access tokens can be requested
    ///   (e.g., "https://your-api.com").
    ///
    /// # Returns
    /// A new `TokenManager` instance.
    pub fn new(api_url: String) -> Self {
        Self {
            api_url,
            token: None,
            expiry: None,
        }
    }

    /// Provides a valid access token (bearer token) for API requests.
    ///
    /// This method checks if the current token is missing or has expired. If so,
    /// it automatically fetches a new token from the API using the `api_url`
    /// provided during initialization. The new token and its expiration time are
    /// then stored internally.
    ///
    /// # Returns
    /// - `Ok(&str)` containing a string slice of the valid bearer token.
    /// - `Err(anyhow::Error)` if there is a failure in fetching a new token
    ///   from the API (e.g., network error, API returns an error, invalid response format).
    pub fn get_access_token(&mut self) -> Result<&str> {
        let now = Instant::now();

        let is_expired = match self.expiry {
            Some(expiry_time) => now >= expiry_time,
            None => true, // token missing
        };

        if self.token.is_none() || is_expired {
            let (token, ttl) = self.fetch_access_token()
                .with_context(|| "Failed to fetch new bearer token")?;
            self.token = Some(token);
            self.expiry = Some(now + Duration::from_secs(ttl));
        }

        Ok(self.token.as_deref().unwrap())
    }

    /// Internal helper function to request a new access token from the API.
    ///
    /// This method calls the external `get_bearer_token` function, passing
    /// the stored `api_url` to perform the actual HTTP request.
    ///
    /// # Returns
    /// - `Ok((String, u64))` containing the newly fetched token as a `String`
    ///   and its time-to-live (TTL) in seconds as a `u64`.
    /// - `Err(anyhow::Error)` if the `get_bearer_token` call fails.
    fn fetch_access_token(&self) -> Result<(String, u64)> {
        let (token, ttl) = get_bearer_token(&self.api_url)?;
        Ok((token, ttl))
    }
}

/// Reads and decrypts secrets from an encrypted file using the device's private key.
///
/// This function is designed to securely retrieve encrypted secrets stored on the device.
/// It uses the `age` encryption library to decrypt the content, requiring access to
/// the device's private key.
///
/// # Type Parameters
/// * `T` - The target type to which the decrypted bytes should be converted.
///   This type must implement the `From<Vec<u8>>` trait. Common uses include
///   `String` (for decrypted text) or `Vec<u8>` (for raw decrypted bytes).
///
/// # Arguments
/// * `secret_path` - The path to the encrypted file containing the secret.
///
/// # Returns
/// - `Ok(T)` on successful decryption, returning the secret converted into the
///   specified type `T`.
/// - `Err(anyhow::Error)` if:
///   - The device's private key file (`PRIVATE_KEY_FILE` within `UPD8_DIR_PATH`) cannot be found or read.
///   - The `secret_path` file cannot be opened or read.
///   - Decryption fails (e.g., incorrect private key, corrupt encrypted file, invalid format).
///   - There are issues with `age`'s identity reading or decryption process.
fn get_secret<T: From<Vec<u8>>>(secret_path: &Path) -> Result<T> {
    let upd8_dir_path = Path::new(UPD8_DIR_PATH);
    let private_key_path = upd8_dir_path.join(PRIVATE_KEY_FILE);

    // Lock stdin using StdinGuard from the age crate
    let mut stdin_guard = StdinGuard::new(true);

    // Read the identities (using key file)
    let identities = read_identities(
        vec![private_key_path.display().to_string()],
        None,
        &mut stdin_guard,
    )?;

    // Open and prepare encrypted file
    let encrypted_file = File::open(secret_path)?;
    let decryptor = Decryptor::new(BufReader::new(encrypted_file))?;

    // Decrypt the content using identities
    let mut reader = decryptor.decrypt(identities.iter().map(|id| &**id))?;
    let mut decrypted = Vec::new();
    reader.read_to_end(&mut decrypted)?;

    // Wrap securely
    Ok(T::from(decrypted))
}

/// Extracts only the public key string from the device's private key file.
///
/// This function opens the private key file (located at `UPD8_DIR_PATH/PRIVATE_KEY_FILE`),
/// reads it line by line, and specifically looks for a line that starts with
/// `"# public key:"`. It then extracts the last whitespace-separated token from
/// that line, which is expected to be the actual public key string.
///
/// This is typically used for sending the device's public key to a server
/// for registration or identification purposes.
///
/// # Returns
/// - `Ok(String)` containing the extracted public key string on success.
/// - `Err(anyhow::Error)` if:
///   - The private key file cannot be opened or read.
///   - The expected public key line (`# public key:`) is not found in the file.
///   - The public key line is found but is malformed, preventing the extraction
///     of the key string.
fn extract_public_key() -> Result<String> {
    let upd8_dir_path = Path::new(UPD8_DIR_PATH);
    let private_key_path = upd8_dir_path.join(PRIVATE_KEY_FILE);

    let file = File::open(private_key_path)?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        if line.starts_with("# public key:") {
            return line
                .split_whitespace()
                .last()
                .map(|s| s.to_string())
                .ok_or_else(|| anyhow!("Malformed public key line"));
        }
    }

    Err(anyhow!("Public key not found in identity file"))
}

/// Returns the decrypted registration token from a secure file.
///
/// This function reads the encrypted registration token from the file specified
/// by `TOKEN_FILE` located within `UPD8_DIR_PATH`. It then uses the device's
/// private key (via the `get_secret` function) to decrypt the token.
///
/// # Returns
/// - `Ok(RegToken)` on successful decryption, providing the registration token
///   wrapped in a `RegToken` struct.
/// - `Err(anyhow::Error)` if:
///   - The token file cannot be found or read.
///   - The private key is inaccessible or invalid.
///   - Decryption fails for any reason (e.g., corrupt file, incorrect key).
pub fn get_reg_token() -> Result<RegToken> {
    let upd8_dir_path = Path::new(UPD8_DIR_PATH);
    let token_file_path = upd8_dir_path.join(TOKEN_FILE);

    let token: RegToken = get_secret(&token_file_path)?;
    Ok(token)
}

/// Returns the decrypted API key from a secure file.
///
/// This function reads the encrypted API key from the file specified by
/// `KEY_FILE` located within `UPD8_DIR_PATH`. It then uses the device's
/// private key (via the `get_secret` function) to decrypt the API key.
///
/// # Returns
/// - `Ok(ApiKey)` on successful decryption, providing the API key
///   wrapped in an `ApiKey` struct.
/// - `Err(anyhow::Error)` if:
///   - The API key file cannot be found or read.
///   - The device's private key is inaccessible or invalid.
///   - Decryption fails for any reason (e.g., corrupt file, incorrect key).
pub fn get_api_key() -> Result<ApiKey> {
    let upd8_dir_path = Path::new(UPD8_DIR_PATH);
    let key_file_path = upd8_dir_path.join(KEY_FILE);

    let key: ApiKey = get_secret(&key_file_path)?;
    Ok(key)
}

/// Encrypts the provided API key using the device's public key and saves it to a file.
///
/// This function securely encrypts the `api_key` string using the device's public
/// key (which is extracted from the corresponding private key file). The encrypted
/// content is then written to `KEY_FILE` located within `UPD8_DIR_PATH`.
///
/// # Arguments
/// * `api_key` - The API key string to be encrypted.
///
/// # Returns
/// - `Ok(())` if the API key is successfully encrypted and written to the file.
/// - `Err(anyhow::Error)` if:
///   - The device's public key cannot be extracted.
///   - The output file (`KEY_FILE`) cannot be created or written to.
///   - Any underlying encryption operation fails (e.g., `age` library errors).
///
/// # Panics
/// This function will panic if the string returned by `extract_public_key()`
/// is not a valid `age::x25519::Recipient` public key format. It is crucial
/// that `extract_public_key()` provides a correctly formatted public key.
pub fn encrypt_api_key(api_key: &str) -> Result<()> {
    let upd8_dir_path = Path::new(UPD8_DIR_PATH);
    let key_file_path = upd8_dir_path.join(KEY_FILE);

    // Parse recipient from string
    let recipient = extract_public_key()?
        .parse::<x25519::Recipient>()
        .expect("Invalid recipient");

    // Create an encryptor
    let recipients: Vec<Box<dyn age::Recipient>> = vec![Box::new(recipient)];
    let encryptor = Encryptor::with_recipients(recipients.iter().map(|r| &**r));

    // Open output file
    let file = File::create(key_file_path)?;
    let writer = BufWriter::new(file);
    let mut output = encryptor?.wrap_output(writer)?;

    // Write API key
    output.write_all(api_key.as_bytes())?;
    output.finish()?;

    Ok(())
}
