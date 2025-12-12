use reqwest::{Client, Response};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::error::{Result, SdkError};

#[derive(Clone)]
pub struct ApiClient {
    client: Client,
    base_url: String,
    auth_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub kem_public_key: Vec<u8>,
    pub kem_encrypted_private: Vec<u8>,
    pub dsa_public_key: Vec<u8>,
    pub dsa_encrypted_private: Vec<u8>,
    pub key_salt: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterResponse {
    pub user_id: String,
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginResponse {
    pub user_id: String,
    pub token: String,
    pub kem_public_key: Vec<u8>,
    pub kem_encrypted_private: Vec<u8>,
    pub dsa_public_key: Vec<u8>,
    pub dsa_encrypted_private: Vec<u8>,
    pub key_salt: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct UserPublicKeys {
    pub user_id: String,
    pub username: String,
    pub kem_public_key: Vec<u8>,
    pub dsa_public_key: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct UploadPrekeysRequest {
    pub signed_prekey_public: Vec<u8>,
    pub signed_prekey_signature: Vec<u8>,
    pub one_time_prekeys: Vec<OneTimePrekeyUpload>,
}

#[derive(Debug, Serialize)]
pub struct OneTimePrekeyUpload {
    pub prekey_id: u32,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct PreKeyBundle {
    pub identity_key: Vec<u8>,
    pub signed_prekey_public: Vec<u8>,
    pub signed_prekey_signature: Vec<u8>,
    pub signed_prekey_id: u32,
    pub one_time_prekey: Option<OneTimePrekeyResponse>,
}

#[derive(Debug, Deserialize)]
pub struct OneTimePrekeyResponse {
    pub prekey_id: u32,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct PreKeyCountResponse {
    pub count: u32,
}

#[derive(Debug, Serialize)]
pub struct SendMessageRequest {
    pub conversation_id: String,
    pub encrypted_content: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct ApiError {
    pub error: String,
}

impl ApiClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.to_string(),
            auth_token: None,
        }
    }

    pub fn set_auth_token(&mut self, token: String) {
        self.auth_token = Some(token);
    }

    pub fn clear_auth_token(&mut self) {
        self.auth_token = None;
    }

    async fn handle_response<T: DeserializeOwned>(&self, response: Response) -> Result<T> {
        let status = response.status();

        if status.is_success() {
            response
                .json()
                .await
                .map_err(|e| SdkError::Deserialization(e.to_string()))
        } else {
            let error: ApiError = response.json().await.unwrap_or(ApiError {
                error: format!("HTTP error: {}", status),
            });
            Err(SdkError::Encryption(error.error))
        }
    }

    pub async fn register(&self, request: &RegisterRequest) -> Result<RegisterResponse> {
        let response = self
            .client
            .post(format!("{}/api/auth/register", self.base_url))
            .json(request)
            .send()
            .await
            .map_err(|e| SdkError::Encryption(e.to_string()))?;

        self.handle_response(response).await
    }

    pub async fn login(&self, request: &LoginRequest) -> Result<LoginResponse> {
        let response = self
            .client
            .post(format!("{}/api/auth/login", self.base_url))
            .json(request)
            .send()
            .await
            .map_err(|e| SdkError::Encryption(e.to_string()))?;

        self.handle_response(response).await
    }

    pub async fn logout(&self) -> Result<()> {
        let token = self
            .auth_token
            .as_ref()
            .ok_or(SdkError::SessionNotInitialized)?;

        let response = self
            .client
            .post(format!("{}/api/auth/logout", self.base_url))
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| SdkError::Encryption(e.to_string()))?;

        if response.status().is_success() {
            Ok(())
        } else {
            let error: ApiError = response.json().await.unwrap_or(ApiError {
                error: "Logout failed".to_string(),
            });
            Err(SdkError::Encryption(error.error))
        }
    }

    pub async fn get_user_public_keys(&self, user_id: &str) -> Result<UserPublicKeys> {
        let token = self
            .auth_token
            .as_ref()
            .ok_or(SdkError::SessionNotInitialized)?;

        let response = self
            .client
            .get(format!("{}/api/users/{}/keys", self.base_url, user_id))
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| SdkError::Encryption(e.to_string()))?;

        self.handle_response(response).await
    }

    pub async fn upload_prekeys(&self, request: &UploadPrekeysRequest) -> Result<()> {
        let token = self
            .auth_token
            .as_ref()
            .ok_or(SdkError::SessionNotInitialized)?;

        let response = self
            .client
            .post(format!("{}/api/keys/prekeys", self.base_url))
            .bearer_auth(token)
            .json(request)
            .send()
            .await
            .map_err(|e| SdkError::Encryption(e.to_string()))?;

        if response.status().is_success() {
            Ok(())
        } else {
            let error: ApiError = response.json().await.unwrap_or(ApiError {
                error: "Upload prekeys failed".to_string(),
            });
            Err(SdkError::Encryption(error.error))
        }
    }

    pub async fn get_prekey_count(&self) -> Result<u32> {
        let token = self
            .auth_token
            .as_ref()
            .ok_or(SdkError::SessionNotInitialized)?;

        let response = self
            .client
            .get(format!("{}/api/keys/prekeys/count", self.base_url))
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| SdkError::Encryption(e.to_string()))?;

        let count: PreKeyCountResponse = self.handle_response(response).await?;
        Ok(count.count)
    }

    pub async fn get_prekey_bundle(&self, user_id: &str) -> Result<PreKeyBundle> {
        let token = self
            .auth_token
            .as_ref()
            .ok_or(SdkError::SessionNotInitialized)?;

        let response = self
            .client
            .get(format!("{}/api/keys/prekeys/{}", self.base_url, user_id))
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| SdkError::Encryption(e.to_string()))?;

        self.handle_response(response).await
    }

    pub async fn send_message(&self, request: &SendMessageRequest) -> Result<()> {
        let token = self
            .auth_token
            .as_ref()
            .ok_or(SdkError::SessionNotInitialized)?;

        let response = self
            .client
            .post(format!("{}/api/messages", self.base_url))
            .bearer_auth(token)
            .json(request)
            .send()
            .await
            .map_err(|e| SdkError::Encryption(e.to_string()))?;

        if response.status().is_success() {
            Ok(())
        } else {
            let error: ApiError = response.json().await.unwrap_or(ApiError {
                error: "Send message failed".to_string(),
            });
            Err(SdkError::Encryption(error.error))
        }
    }
}
