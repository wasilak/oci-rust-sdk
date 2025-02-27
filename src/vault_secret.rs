use crate::base_client::{encode_body, oci_signer};
use crate::identity::Identity;
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use reqwest::header::HeaderMap;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;

pub struct Vault {
    identity: Identity,
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct VaultSecretResponse {
    secret_bundle_content: VaultSecret,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct VaultSecret {
    pub content: String,
}

impl Vault {
    pub fn new(identity: Identity) -> Self {
        Vault { identity }
    }

    pub async fn get_secret(
        &self,
        secret_name: &str,
        vault_ocid: &str,
    ) -> Result<VaultSecret, Box<dyn std::error::Error>> {
        let url = format!(
            "https://secrets.vaults.{}.oci.oraclecloud.com",
            self.identity.get_auth_config().region
        );

        let path = format!(
            "/20190301/secretbundles/actions/getByName?secretName={}&vaultId={}",
            secret_name, vault_ocid
        );

        // Only needed in order to make it valid POST request
        let body_json = json!({});
        let body = body_json.to_string();

        let mut headers = HeaderMap::new();

        let now: DateTime<Utc> = Utc::now();
        headers.insert(
            "date",
            now.format("%a, %d %b %Y %H:%M:%S GMT")
                .to_string()
                .parse()
                .unwrap(),
        );

        headers.insert("x-content-sha256", encode_body(&body).parse().unwrap());
        headers.insert("content-length", body.len().to_string().parse().unwrap());
        headers.insert(
            "content-type",
            String::from("application/json").parse().unwrap(),
        );

        let parsed_url = reqwest::Url::parse(&url)?;
        let host = parsed_url.host_str().unwrap().to_string();

        oci_signer(
            &self.identity.get_auth_config(),
            &mut headers,
            "post".to_string(),
            &path,
            &host,
        );

        let client = reqwest::Client::new();

        let response = client
            .post(format!("{}{}", &url, path))
            .body(body)
            .headers(headers)
            .send()
            .await?;

        let secret_content: VaultSecretResponse = response.json::<VaultSecretResponse>().await?;

        return Ok(secret_content.secret_bundle_content);
    }
}

impl VaultSecret {
    pub fn decode(&self) -> String {
        match general_purpose::STANDARD.decode(&self.content) {
            Ok(decoded) => match String::from_utf8(decoded) {
                Ok(decoded_str) => decoded_str,
                Err(e) => format!("Error decoding secret: {:?}", e),
            },
            Err(e) => format!("Error decoding secret: {:?}", e),
        }
    }

    pub async fn get_json(&self) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
        let secret_content: HashMap<String, String> = serde_json::from_str(&self.decode())?;
        Ok(secret_content)
    }
}
