use crate::base_client::{encode_body, oci_signer};
use crate::identity::Identity;
use chrono::{DateTime, Utc};
use reqwest::header::HeaderMap;
use reqwest::Response;
use serde_json::json;

pub struct VaultSecret {
    identity: Identity,
}

impl VaultSecret {
    pub fn new(identity: Identity) -> Self {
        VaultSecret { identity }
    }

    pub async fn get_secret(
        &self,
        secret_name: &str,
        vault_ocid: &str,
    ) -> Result<Response, Box<dyn std::error::Error>> {
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

        return Ok(response);
    }
}
