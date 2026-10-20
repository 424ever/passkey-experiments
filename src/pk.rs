use anyhow::Context;
use axum::{
    Json, Router,
    extract::State,
    response::{Html, IntoResponse},
    routing::get,
};
use axum_extra::{TypedHeader, headers};
use rand::{Rng, rng};
use tracing::{Level, debug, info, span};

use crate::{
    AppState, DOMAIN, ORIGIN, SESSION_COOKIE,
    base64url::decode,
    cbor,
    error::{ApiError, AppError},
    pk::types::{
        AttestationObject, CollectedClientData, RegisterRequest,
        public_key_credential::{self},
    },
    session::Session,
    sha256,
    user::load_user_by_id,
};

mod types;

pub type Challenge = [u8; 16];

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/get-creation-options", get(get_creation_options))
        .route("/register", get(register_page).post(post_register))
}

// https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential
async fn register_page(_session: Session) -> impl IntoResponse {
    let mut res = String::new();
    res.push_str(r#"<h1>register passkey</h1>"#);
    res.push_str(r#"<p>something should aready be happening</p>"#);
    res.push_str(r#"<script type="module">"#);
    res.push_str(include_str!("pk/register.js"));
    res.push_str(r#"</script>"#);
    Html(res)
}

// https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential
async fn post_register(
    session: Session,
    Json(response): Json<RegisterRequest>,
) -> Result<(), ApiError> {
    let span = span!(Level::INFO, "register key", r#for = ?session.user);
    let _guard = span.enter();

    debug!(?response);

    let Some(session_challenge) = session.create_pk_challenge else {
        return Err("not in the register flow".into());
    };
    info!(?session_challenge);

    // 5. Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON.
    let json_text =
        str::from_utf8(&response.client_data_json).context("utf-8 decode clientDataJSON")?;
    info!(json_text);

    // 6. Let C, the client data claimed as collected during the credential creation, be the result
    // of running an implementation-specific JSON parser on JSONtext.
    let c =
        serde_json::from_str::<CollectedClientData>(json_text).context("json decode JSONText")?;
    info!(client_data = ?c);

    // 7. Verify that the value of C.type is webauthn.create.
    (c.r#type == "webauthn.create").ok_or("type does not match (7)")?;

    // 8. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
    (decode(&c.challenge).context("base64 decode challenge")? == session_challenge)
        .ok_or("challenge does not match (8)")?;

    // 9. Verify that the value of C.origin matches the Relying Party's origin.
    (c.origin == *ORIGIN.get().unwrap()).ok_or("origin does not match (9)")?;

    // 10. Verify that the value of C.tokenBinding.status matches the state of Token Binding for the
    // TLS connection over which the assertion was obtained. If Token Binding was used on that TLS
    // connection, also verify that C.tokenBinding.id matches the base64url encoding of the Token
    // Binding ID for the connection.
    (c.token_binding.is_none()).ok_or("token binding set (10) (we don't do TLS around here)")?;

    // 11. Let hash be the result of computing a hash over response.clientDataJSON using SHA-256.
    // TODO: hash

    // 12. Perform CBOR decoding on the attestationObject field of the
    // AuthenticatorAttestationResponse structure to obtain the attestation statement format fmt,
    // the authenticator data authData, and the attestation statement attStmt.
    let attestation_object = cbor::from_bytes::<AttestationObject>(&response.attestation_object)
        .context("cbor decode attestation object")?;
    info!(?attestation_object);
    let auth_data = attestation_object.auth_data;

    // 13. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the
    // Relying Party.
    let rp_id_hash = &auth_data[..32];

    let mut exp_hash = [0u8; 32];
    sha256::digest(DOMAIN.get().unwrap().as_bytes(), &mut exp_hash);
    (rp_id_hash == exp_hash).ok_or("rpIdHash does not match (13)")?;

    // 14. Verify that the User Present bit of the flags in authData is set.

    // 15. If user verification is required for this registration, verify that the User Verified bit
    // of the flags in authData is set.

    // 16. Verify that the "alg" parameter in the credential public key in authData matches the alg
    // attribute of one of the items in options.pubKeyCredParams.

    // 17. Verify that the values of the client extension outputs in clientExtensionResults and the
    // authenticator extension outputs in the extensions in authData are as expected, considering
    // the client extension input values that were given in options.extensions and any specific
    // policy of the Relying Party regarding unsolicited extensions, i.e., those that were not
    // specified as part of options.extensions. In the general case, the meaning of "are as
    // expected" is specific to the Relying Party and which extensions are in use.
    //
    // Note: Client platforms MAY enact local policy that sets additional authenticator extensions
    // or client extensions and thus cause values to appear in the authenticator extension outputs
    // or client extension outputs that were not originally specified as part of options.extensions.
    // Relying Parties MUST be prepared to handle such situations, whether it be to ignore the
    // unsolicited extensions or reject the attestation. The Relying Party can make this decision
    // based on local policy and the extensions in use.
    //
    // Note: Since all extensions are OPTIONAL for both the client and the authenticator, the
    // Relying Party MUST also be prepared to handle cases where none or not all of the requested
    // extensions were acted upon.

    // 18. Determine the attestation statement format by performing a USASCII case-sensitive match
    // on fmt against the set of supported WebAuthn Attestation Statement Format Identifier values.
    // An up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is
    // maintained in the IANA "WebAuthn Attestation Statement Format Identifiers" registry
    // [IANA-WebAuthn-Registries] established by [RFC8809].

    // 19. Verify that attStmt is a correct attestation statement, conveying a valid attestation
    // signature, by using the attestation statement format fmt’s verification procedure given
    // attStmt, authData and hash.
    //
    // Note: Each attestation statement format specifies its own verification procedure. See §8
    // Defined Attestation Statement Formats for the initially-defined formats, and
    // [IANA-WebAuthn-Registries] for the up-to-date list.

    // 20. If validation is successful, obtain a list of acceptable trust anchors (i.e. attestation
    // root certificates) for that attestation type and attestation statement format fmt, from a
    // trusted source or from policy. For example, the FIDO Metadata Service [FIDOMetadataService]
    // provides one way to obtain such information, using the aaguid in the attestedCredentialData
    // in authData.

    // 21. Assess the attestation trustworthiness using the outputs of the verification procedure in
    // step 19, as follows:
    //
    // - If no attestation was provided, verify that None attestation is acceptable under Relying
    // Party policy.
    //
    // - If self attestation was used, verify that self attestation is acceptable under Relying
    // Party policy.
    //
    // - Otherwise, use the X.509 certificates returned as the attestation trust path from the
    // verification procedure to verify that the attestation public key either correctly chains up
    // to an acceptable root certificate, or is itself an acceptable certificate (i.e., it and the
    // root certificate obtained in Step 20 may be the same).

    // 22. Check that the credentialId is not yet registered to any other user. If registration is
    // requested for a credential that is already registered to a different user, the Relying Party
    // SHOULD fail this registration ceremony, or it MAY decide to accept the registration, e.g.
    // while deleting the older registration.

    // 23. If the attestation statement attStmt verified successfully and is found to be
    // trustworthy, then register the new credential with the account that was denoted in
    // options.user:
    //
    // - Associate the user’s account with the credentialId and credentialPublicKey in
    // authData.attestedCredentialData, as appropriate for the Relying Party's system.
    //
    // - Associate the credentialId with a new stored signature counter value initialized to the value
    // of authData.signCount.
    //
    // It is RECOMMENDED to also:
    //
    // - Associate the credentialId with the transport hints returned by calling
    // credential.response.getTransports(). This value SHOULD NOT be modified before or after
    // storing it. It is RECOMMENDED to use this value to populate the transports of the
    // allowCredentials option in future get() calls to help the client know how to find a suitable
    // authenticator.

    // 24. If the attestation statement attStmt successfully verified but is not trustworthy per
    // step 21 above, the Relying Party SHOULD fail the registration ceremony.
    //
    // NOTE: However, if permitted by policy, the Relying Party MAY register the credential ID and
    // credential public key but treat the credential as one with self attestation (see §6.5.3
    // Attestation Types). If doing so, the Relying Party is asserting there is no cryptographic
    // proof that the public key credential has been generated by a particular authenticator model.
    // See [FIDOSecRef] and [UAFProtocol] for a more detailed discussion.

    Err("implementation incomplete".into())
}

async fn get_creation_options(
    State(state): State<AppState>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
) -> Result<Json<public_key_credential::CreationOptions>, AppError> {
    use public_key_credential::*;

    let cookie = cookies.get(SESSION_COOKIE).context("not in a session")?;
    let mut session = state.sessions.write().await;
    let session = session.get_mut(cookie).context("not a valid session")?;

    let mut challenge = [0u8; 16];
    rng().fill_bytes(&mut challenge);
    session.create_pk_challenge = Some(challenge);

    let user = load_user_by_id(&*state.db.lock().await, session.user)?;

    Ok(Json(CreationOptions {
        rp: RpEntity {
            entity: Entity {
                name: "424ever.awesome-network".into(),
            },
            id: None,
        },
        user: UserEntity {
            entity: Entity {
                name: user.name.clone(),
            },
            id: Vec::from(user.id.value().to_be_bytes()),
            display_name: user.name,
        },
        challenge,
        pub_key_cred_params: vec![],
        timeout: 30000,
        exclude_credentials: vec![],
        authenticator_selection: None,
        attestation: "none".into(),
        extensions: None,
    }))
}
