use serde::Serialize;

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
        pub exclude_credentials: Option<Vec<Descriptor>>,
        pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
        pub attestation: Option<String>,
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
