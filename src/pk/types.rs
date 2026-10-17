use serde::{Deserialize, Serialize};

type BufferSource = Vec<u8>;
type CoseAlgorithmIdentifier = u32;

/// Everything prefixed with "PublicKeyCredential"
pub mod public_key_credential {
    use crate::pk::Challenge;

    use super::*;

    /// https://www.w3.org/TR/webauthn-2/#dictionary-makecredentialoptions
    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct CreationOptions {
        pub rp: RpEntity,
        pub user: UserEntity,
        pub challenge: Challenge,
        pub pub_key_cred_params: Vec<Parameters>,
        pub timeout: u32,
        pub exclude_credentials: Vec<Descriptor>,
        pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
        pub attestation: String,
        pub extensions: Option<AuthenticationExtensionsClientInputs>,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Entity {
        pub name: String,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct RpEntity {
        #[serde(flatten)]
        pub entity: Entity,
        pub id: Option<String>,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct UserEntity {
        #[serde(flatten)]
        pub entity: Entity,
        pub id: Vec<u8>,
        pub display_name: String,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Parameters {
        pub r#type: String,
        pub alg: CoseAlgorithmIdentifier,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Descriptor {
        pub r#type: String,
        pub id: BufferSource,
        pub transports: Option<Vec<String>>,
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorSelectionCriteria {
    pub authenticator_attachment: Option<String>,
    pub resident_key: Option<String>,
    pub require_resident_key: Option<bool>,
    pub user_verification: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationExtensionsClientInputs {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    pub client_data_json: Vec<u8>,
    pub attestation_object: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectedClientData {
    pub r#type: String,
    pub challenge: String,
    pub origin: String,
    #[serde(default)]
    pub cross_origin: bool,
    pub token_binding: Option<TokenBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenBinding {
    pub status: String,
    #[serde(default)]
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationObject<'a> {
    pub auth_data: &'a [u8],
    #[serde(flatten)]
    pub statement: AttestationStatement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "fmt", rename_all = "camelCase")]
pub enum AttestationStatement {
    None,
}
