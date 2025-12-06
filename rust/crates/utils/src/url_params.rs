//!
//!
//!

use std::collections::HashMap;

///
pub fn params_from_url(url: &str) -> HashMap<String, String> {
    let Some((_base, params)) = url.split_once('?') else {
        return HashMap::new();
    };
    parse_url_params(params)
}

///
pub fn parse_url_params(input: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    for pair in input.split('&') {
        println!("pair: {}", pair);
        let (key, value) = pair.split_once('=').unwrap();
        params.insert(key.to_string(), value.to_string());
    }
    params
}

///
pub fn build_url_params(params: HashMap<String, String>) -> String {
    let mut keys = params.keys().collect::<Vec<_>>();
    keys.sort_unstable();
    let strs = keys
        .iter()
        .map(|key| format!("{}={}", key, params.get(key.as_str()).unwrap()))
        .collect::<Vec<_>>();
    strs.join("&")
}
