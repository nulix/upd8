use anyhow::{Result, Context, anyhow};
use curl::easy::{Easy, List};
use serde_json::Value;
use log::{debug, error};

/// Internal helper function to perform a generic cURL HTTP request.
///
/// This function handles the common setup, execution, response parsing, and error
/// handling for both GET and POST requests. Method-specific configurations
/// are injected via the `setup_easy` closure.
///
/// # Arguments
/// * `url` - The URL for the HTTP request.
/// * `http_headers` - A `curl::easy::List` containing HTTP headers.
/// * `setup_easy` - A closure that takes a mutable reference to `curl::easy::Easy`
///                  and performs method-specific configurations (e.g., `easy.post(true)`,
///                  `easy.post_fields_copy`). It should return `Ok(())` on success.
/// * `method_name` - A string slice indicating the HTTP method (e.g., "GET", "POST")
///                   used for logging and error messages.
///
/// # Returns
/// `Ok((response_code, parsed_json))` on success, where `response_code` is the HTTP status
/// code and `parsed_json` is the parsed JSON response body.
/// Returns `Err(anyhow::Error)` on network errors, HTTP error status codes (non-2xx),
/// or JSON parsing failures.
fn _curl_request<F>(
    url: &str,
    http_headers: List,
    setup_easy: F, // Closure for method-specific setup
    method_name: &str, // For logging and error messages
) -> Result<(u32, Value)>
where
    F: FnOnce(&mut Easy) -> Result<()>, // F is a closure that configures Easy
{
    let mut response_body = Vec::new();

    let mut easy = Easy::new();
    easy.url(url)?;
    easy.http_headers(http_headers)?;

    // Call the closure to set up method-specific options (e.g., POST, request body)
    setup_easy(&mut easy)?;

    {
        let mut transfer = easy.transfer();
        transfer.write_function(|data| {
            response_body.extend_from_slice(data);
            Ok(data.len())
        })?;

        debug!("Executing {} to: {}", method_name, url);
        transfer.perform()
            .with_context(|| format!("Curl {} request network operation failed for URL: {}", method_name, url))?;
    }

    let response_code = easy.response_code()?;
    debug!("{} Response status code: {}", method_name, response_code);

    if (200..300).contains(&response_code) {
        let parsed_json: Value = serde_json::from_slice(&response_body)
            .with_context(|| {
                format!(
                    "Failed to parse successful (status {}) {} response body as JSON. Body: '{}'",
                    response_code,
                    method_name,
                    String::from_utf8_lossy(&response_body)
                )
            })?;
        debug!("Successfully executed HTTP {} and parsed JSON response", method_name);
        Ok((response_code, parsed_json))
    } else {
        let body_str = String::from_utf8_lossy(&response_body);
        error!(
            "HTTP {} Error {} for URL: {}. Response body: {}",
            method_name, response_code, url, body_str
        );
        Err(anyhow!(
            "HTTP {} request failed with status {}. Response: {}",
            method_name,
            response_code,
            body_str
        ))
    }
}

// --- Public curl_post function ---
/// Performs an HTTP POST request to the specified URL.
/// Sends JSON data in the request body.
pub fn curl_post(url: &str, http_headers: List, json_data: &Value) -> Result<(u32, Value)> {
    // Convert Value to String outside the closure, then bytes are copied by curl
    let json_str = json_data.to_string();
    _curl_request(
        url,
        http_headers,
        |easy| {
            easy.post(true)?; // Set as POST
            easy.post_fields_copy(json_str.as_bytes())?; // Set POST body
            Ok(())
        },
        "POST",
    )
}

// --- Public curl_get function ---
/// Performs an HTTP GET request to the specified URL.
/// Does not send a request body.
pub fn curl_get(url: &str, http_headers: List) -> Result<(u32, Value)> {
    _curl_request(
        url,
        http_headers,
        |_easy| {
            // No specific setup for GET requests needed for curl::Easy
            // (GET is default, no post_fields_copy)
            Ok(())
        },
        "GET",
    )
}
