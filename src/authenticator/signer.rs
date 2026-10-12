//! Software ES256 authenticator. The broker owns presence, password verification,
//! request provenance and durable storage. Never pass `user_verified = true`
//! without verifying the configured password for this specific operation.
use crate::authenticator::cdp::{AttestationMode, KeyConfig};
use anyhow::{bail, ensure, Context, Result};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
};
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

/// All-zero model identifier chosen by the default/anonymous configuration.
#[cfg(test)]
pub const AAGUID: [u8; 16] = [0; 16];
pub struct CreatedCredential {
    pub response: Value,
    pub credential: Value,
}
pub struct Assertion {
    pub response: Value,
    pub credential: Value,
}
fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("missing {key}"))
}
fn binary(v: &Value, key: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(string(v, key)?)
        .with_context(|| format!("invalid base64url {key}"))
}
fn stored(v: &Value, key: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(string(v, key)?)
        .with_context(|| format!("invalid stored {key}"))
}
fn hash(bytes: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA256, bytes).as_ref().to_vec()
}
fn request_rp(options: &Value, create: bool) -> Result<&str> {
    if create {
        string(&options["rp"], "id")
    } else {
        string(options, "rpId")
    }
}
fn validate_rp_origin(rp: &str, origin: &str) -> Result<()> {
    let url = reqwest::Url::parse(origin).context("invalid origin")?;
    let host = url.host_str().context("origin has no host")?;
    ensure!(
        url.origin().ascii_serialization() == origin,
        "origin must be canonical and contain no path"
    );
    ensure!(
        url.scheme() == "https"
            || (url.scheme() == "http"
                && (host == "localhost" || host == "127.0.0.1" || host == "[::1]")),
        "insecure origin"
    );
    ensure!(
        !rp.is_empty() && !rp.ends_with('.') && rp == rp.to_ascii_lowercase(),
        "invalid RP ID"
    );
    // Chrome has already performed the public-suffix check before proxying.
    ensure!(
        host == rp || host.ends_with(&format!(".{rp}")),
        "RP ID does not match origin"
    );
    Ok(())
}
fn client_data(options: &Value, origin: &str, create: bool, uv: bool) -> Result<(String, Vec<u8>)> {
    if let Some(context) = options["extensions"].get("remoteDesktopClientOverride") {
        ensure!(context["origin"] == origin, "remote origin mismatch");
        ensure!(
            context["sameOriginWithAncestors"] == true,
            "cross-origin requests unsupported"
        );
    }
    let rp = request_rp(options, create)?;
    validate_rp_origin(rp, origin)?;
    let required = if create {
        &options["authenticatorSelection"]["userVerification"]
    } else {
        &options["userVerification"]
    };
    ensure!(required != "required" || uv, "user verification required");
    ensure!(
        options["extensions"].get("appid").is_none()
            && options["extensions"].get("appidExclude").is_none(),
        "legacy AppID unsupported"
    );
    let challenge = binary(options, "challenge")?;
    ensure!(!challenge.is_empty(), "empty challenge");
    // Broker supports same-origin top-level requests only. It must reject iframe
    // requests until it can supply trustworthy crossOrigin/topOrigin metadata.
    ensure!(
        options["crossOrigin"] != true,
        "cross-origin requests unsupported"
    );
    let data = serde_json::to_vec(
        &json!({"type": if create {"webauthn.create"} else {"webauthn.get"}, "challenge":URL_SAFE_NO_PAD.encode(challenge),"origin":origin,"crossOrigin":false}),
    )?;
    Ok((rp.to_owned(), data))
}
fn list_contains(options: &Value, name: &str, id: &[u8]) -> Result<bool> {
    let Some(list) = options.get(name) else {
        return Ok(false);
    };
    let list = list.as_array().with_context(|| format!("invalid {name}"))?;
    for item in list {
        if string(item, "type")? == "public-key" && binary(item, "id")? == id {
            return Ok(true);
        }
    }
    Ok(false)
}
/// Filter a stored credential before displaying the broker's account choice.
pub fn eligible_get(options: &Value, credential: &Value) -> bool {
    (|| -> Result<bool> {
        if request_rp(options, false)? != string(credential, "rpId")? {
            return Ok(false);
        }
        let id = stored(credential, "credentialId")?;
        if let Some(list) = options.get("allowCredentials") {
            if !list
                .as_array()
                .context("invalid allowCredentials")?
                .is_empty()
            {
                return list_contains(options, "allowCredentials", &id);
            }
        }
        Ok(credential["isResidentCredential"] == true)
    })()
    .unwrap_or(false)
}
fn auth_data(rp: &str, uv: bool, attested: bool, counter: u32) -> Vec<u8> {
    let mut data = hash(rp.as_bytes());
    data.push(0x01 | if uv { 0x04 } else { 0 } | if attested { 0x40 } else { 0 });
    data.extend_from_slice(&counter.to_be_bytes());
    data
}
// Minimal deterministic CBOR encoder for the fixed attestation/COSE schemas.
fn length(out: &mut Vec<u8>, major: u8, n: usize) {
    if n < 24 {
        out.push(major << 5 | n as u8)
    } else if n <= 255 {
        out.extend_from_slice(&[major << 5 | 24, n as u8])
    } else if n <= 65535 {
        out.push(major << 5 | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes())
    } else {
        out.push(major << 5 | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes())
    }
}
fn bytes(out: &mut Vec<u8>, b: &[u8]) {
    length(out, 2, b.len());
    out.extend_from_slice(b)
}
fn text(out: &mut Vec<u8>, s: &str) {
    length(out, 3, s.len());
    out.extend_from_slice(s.as_bytes())
}
fn cose(public: &[u8]) -> Vec<u8> {
    let mut out = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21]; // kty EC2, alg ES256, crv P256
    bytes(&mut out, &public[1..33]);
    out.push(0x22);
    bytes(&mut out, &public[33..65]);
    out
}
fn spki(public: &[u8]) -> Vec<u8> {
    let mut out = vec![
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    out.extend_from_slice(public);
    out
}
/// WebAuthn Level 2 gives residentKey precedence over requireResidentKey.
/// Keep this shared with broker candidate selection so unavailable keys are not
/// offered and later rejected by the signer.
pub fn resident_key_required(options: &Value) -> bool {
    match options["authenticatorSelection"]["residentKey"].as_str() {
        Some("required") => true,
        Some(_) => false,
        None => options["authenticatorSelection"]["requireResidentKey"] == true,
    }
}

#[cfg(test)]
pub fn create(
    options: &Value,
    origin: &str,
    user_verified: bool,
    existing_credentials: &[Value],
) -> Result<CreatedCredential> {
    let mut config: KeyConfig = serde_json::from_value(json!({
        "id":"test-key","name":"Test key","attachment":"cross-platform"
    }))?;
    config.credentials = existing_credentials.to_vec();
    create_with_config(options, origin, user_verified, &config)
}

/// Attestation conveyance and the self-declared model identifier are independent.
/// WebAuthn Level 3 does not zero AAGUID for `none`; see §5.1.3 and §18.1.1.
/// None/default and unsupported enterprise never send a signature or certificate.
/// Choosing the all-zero model UUID explicitly omits the model identifier.
pub fn effective_attestation(
    requested: &str,
    config: &KeyConfig,
) -> Result<(&'static str, String)> {
    let effective = if matches!(requested, "direct" | "indirect") {
        match config.attestation_mode {
            AttestationMode::None => "none",
            AttestationMode::SelfAttestation => "packed-self",
            AttestationMode::Basic => "packed-basic",
        }
    } else {
        "none"
    };
    Ok((
        effective,
        crate::authenticator::cdp::canonical_aaguid(&config.model_aaguid)?,
    ))
}

pub fn create_with_config(
    options: &Value,
    origin: &str,
    user_verified: bool,
    config: &KeyConfig,
) -> Result<CreatedCredential> {
    config.validate()?;
    let (rp, client) = client_data(options, origin, true, user_verified)?;
    ensure!(
        options["pubKeyCredParams"]
            .as_array()
            .context("missing algorithms")?
            .iter()
            .any(|p| p["type"] == "public-key" && p["alg"] == -7),
        "ES256 not offered"
    );
    let user = binary(&options["user"], "id")?;
    ensure!(
        !user.is_empty() && user.len() <= 64,
        "user handle must be 1 to 64 bytes"
    );
    for credential in &config.credentials {
        if credential["rpId"] == rp
            && list_contains(
                options,
                "excludeCredentials",
                &stored(credential, "credentialId")?,
            )?
        {
            bail!("credential excluded")
        }
    }
    let preference = options["authenticatorSelection"]["residentKey"].as_str();
    ensure!(
        preference.is_none_or(|value| matches!(value, "required" | "preferred" | "discouraged")),
        "invalid resident key preference"
    );
    let required = resident_key_required(options);
    ensure!(
        !required || config.resident_key_supported,
        "discoverable credentials are required but disabled for this key"
    );
    let resident = config.resident_key_supported && (required || preference == Some("preferred"));
    let requested_attestation = match options.get("attestation") {
        None => "none",
        Some(value) => value.as_str().context("Invalid attestation preference")?,
    };
    ensure!(
        matches!(
            requested_attestation,
            "none" | "direct" | "indirect" | "enterprise"
        ),
        "Invalid attestation preference"
    );
    let (effective, model) = effective_attestation(requested_attestation, config)?;
    let self_attestation = effective == "packed-self";
    let basic_attestation = effective == "packed-basic";
    let aaguid = *crate::authenticator::cdp::parse_aaguid(&model)?.as_bytes();
    if basic_attestation {
        config
            .attestation_identity
            .as_ref()
            .context("Basic attestation identity is missing")?
            .validate_current(&config.model_aaguid)?;
    }
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .map_err(|_| anyhow::anyhow!("key generation failed"))?;
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
        .map_err(|_| anyhow::anyhow!("invalid generated key"))?;
    let mut id = [0u8; 32];
    rng.fill(&mut id)
        .map_err(|_| anyhow::anyhow!("random generation failed"))?;
    let mut auth = auth_data(&rp, user_verified, true, 0);
    auth.extend_from_slice(&aaguid);
    auth.extend_from_slice(&(id.len() as u16).to_be_bytes());
    auth.extend_from_slice(&id);
    auth.extend_from_slice(&cose(key.public_key().as_ref()));
    let mut attestation = vec![0xa3];
    text(&mut attestation, "fmt");
    text(
        &mut attestation,
        if self_attestation || basic_attestation {
            "packed"
        } else {
            "none"
        },
    );
    text(&mut attestation, "attStmt");
    if self_attestation || basic_attestation {
        let mut message = auth.clone();
        message.extend_from_slice(&hash(&client));
        let signature = if basic_attestation {
            config
                .attestation_identity
                .as_ref()
                .context("Missing identity")?
                .sign(&message)?
        } else {
            key.sign(&rng, &message)
                .map_err(|_| anyhow::anyhow!("Self attestation signature failed"))?
                .as_ref()
                .to_vec()
        };
        attestation.push(if basic_attestation { 0xa3 } else { 0xa2 });
        text(&mut attestation, "alg");
        attestation.push(0x26);
        text(&mut attestation, "sig");
        bytes(&mut attestation, &signature);
        if basic_attestation {
            text(&mut attestation, "x5c");
            let chain = config
                .attestation_identity
                .as_ref()
                .context("Missing identity")?
                .certificate_chain()?;
            length(&mut attestation, 4, chain.len());
            for cert in chain {
                bytes(&mut attestation, &cert);
            }
        }
    } else {
        attestation.push(0xa0);
    }
    text(&mut attestation, "authData");
    bytes(&mut attestation, &auth);
    let mut extensions = json!({});
    if options["extensions"]["credProps"] == true {
        extensions["credProps"] = json!({"rk":resident});
    }
    // Record local registration time once, in UTC Unix milliseconds. Existing
    // credentials keep their original metadata and never acquire an inferred date.
    let registered_at = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("System clock precedes Unix epoch")?
            .as_millis(),
    )
    .context("Registration time is out of range")?;
    Ok(CreatedCredential {
        response: json!({"id":URL_SAFE_NO_PAD.encode(id),"rawId":URL_SAFE_NO_PAD.encode(id),"type":"public-key","clientExtensionResults":extensions,"response":{"clientDataJSON":URL_SAFE_NO_PAD.encode(client),"attestationObject":URL_SAFE_NO_PAD.encode(attestation),"authenticatorData":URL_SAFE_NO_PAD.encode(auth),"publicKey":URL_SAFE_NO_PAD.encode(spki(key.public_key().as_ref())),"publicKeyAlgorithm":-7,"transports":[]}}),
        credential: json!({"credentialId":STANDARD.encode(id),"privateKey":STANDARD.encode(pkcs8.as_ref()),"rpId":rp,"userHandle":STANDARD.encode(user),"signCount":0,"isResidentCredential":resident,"registrationAaguid":model,"registrationAttestation":effective,"registrationRequestedAttestation":requested_attestation,"registrationIdentity":{"providerLabel":config.provider_label,"modelAaguid":model,"attachment":config.attachment,"residentKeySupported":config.resident_key_supported,"attestationMode":config.attestation_mode},"userName":options["user"]["name"],"userDisplayName":options["user"]["displayName"],"registeredAt":registered_at}),
    })
}
pub fn get(
    options: &Value,
    origin: &str,
    user_verified: bool,
    credential: &Value,
) -> Result<Assertion> {
    let (rp, client) = client_data(options, origin, false, user_verified)?;
    ensure!(
        eligible_get(options, credential),
        "credential does not match RP/allow list or is not discoverable"
    );
    let count = credential["signCount"]
        .as_u64()
        .context("invalid sign counter")?;
    let count = u32::try_from(count)
        .context("invalid sign counter")?
        .checked_add(1)
        .context("sign counter exhausted")?;
    let auth = auth_data(&rp, user_verified, false, count);
    let mut message = auth.clone();
    message.extend_from_slice(&hash(&client));
    let rng = SystemRandom::new();
    let pkcs8 = stored(credential, "privateKey")?;
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8, &rng)
        .map_err(|_| anyhow::anyhow!("invalid stored ES256 private key"))?;
    let signature = key
        .sign(&rng, &message)
        .map_err(|_| anyhow::anyhow!("signature failed"))?;
    let id = URL_SAFE_NO_PAD.encode(stored(credential, "credentialId")?);
    let handle = credential
        .get("userHandle")
        .filter(|v| !v.is_null())
        .map(|_| stored(credential, "userHandle"))
        .transpose()?
        .map(|b| URL_SAFE_NO_PAD.encode(b));
    let mut updated = credential.clone();
    updated["signCount"] = json!(count);
    Ok(Assertion {
        response: json!({"id":id,"rawId":id,"type":"public-key","clientExtensionResults":{},"response":{"clientDataJSON":URL_SAFE_NO_PAD.encode(client),"authenticatorData":URL_SAFE_NO_PAD.encode(auth),"signature":URL_SAFE_NO_PAD.encode(signature.as_ref()),"userHandle":handle}}),
        credential: updated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
    fn creation() -> Value {
        json!({"rp":{"id":"example.com","name":"Example"},"user":{"id":"dXNlcg","name":"user","displayName":"User"},"challenge":"Y2hhbGxlbmdl","pubKeyCredParams":[{"type":"public-key","alg":-7}],"authenticatorSelection":{"residentKey":"required"},"extensions":{"credProps":true,"remoteDesktopClientOverride":{"origin":"https://login.example.com","sameOriginWithAncestors":true}}})
    }
    fn request() -> Value {
        json!({"rpId":"example.com","challenge":"bmV3LWNoYWxsZW5nZQ"})
    }
    fn configuration() -> KeyConfig {
        serde_json::from_value(json!({
            "id":"test-key","name":"Test key","attachment":"cross-platform"
        }))
        .unwrap()
    }
    const ORIGIN: &str = "https://login.example.com";
    // Independent decoder for the fixed definite-length CBOR output.
    fn cbor(input: &mut &[u8]) -> Value {
        let first = input[0];
        *input = &input[1..];
        let major = first >> 5;
        let n = match first & 31 {
            24 => {
                let n = input[0] as usize;
                *input = &input[1..];
                n
            }
            25 => {
                let n = u16::from_be_bytes([input[0], input[1]]) as usize;
                *input = &input[2..];
                n
            }
            n => n as usize,
        };
        match major {
            0 => json!(n),
            1 => json!(-1 - n as i64),
            2 => {
                let out = json!(STANDARD.encode(&input[..n]));
                *input = &input[n..];
                out
            }
            3 => {
                let out = json!(std::str::from_utf8(&input[..n]).unwrap());
                *input = &input[n..];
                out
            }
            4 => Value::Array((0..n).map(|_| cbor(input)).collect()),
            5 => {
                let mut out = serde_json::Map::new();
                for _ in 0..n {
                    let k = cbor(input);
                    let k = k
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| k.to_string());
                    out.insert(k, cbor(input));
                }
                Value::Object(out)
            }
            _ => panic!("unexpected CBOR"),
        }
    }
    #[test]
    fn registration_metadata_is_recorded_once_and_absent_history_stays_unknown() {
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let created = create(&creation(), ORIGIN, false, &[]).unwrap();
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let timestamp = created.credential["registeredAt"].as_u64().unwrap() as u128;
        assert!((before..=after).contains(&timestamp));
        assert_eq!(created.credential["userName"], "user");
        assert_eq!(created.credential["userDisplayName"], "User");
        let asserted = get(&request(), ORIGIN, false, &created.credential).unwrap();
        for field in [
            "registeredAt",
            "userName",
            "userDisplayName",
            "registrationIdentity",
        ] {
            assert_eq!(asserted.credential[field], created.credential[field]);
        }
        assert!(created.response.get("registeredAt").is_none());
        let mut legacy = created.credential;
        for field in ["registeredAt", "userName", "userDisplayName"] {
            legacy.as_object_mut().unwrap().remove(field);
        }
        let asserted = get(&request(), ORIGIN, false, &legacy).unwrap();
        for field in ["registeredAt", "userName", "userDisplayName"] {
            assert!(asserted.credential.get(field).is_none());
        }
    }

    #[test]
    fn registration_and_assertion_are_verifiable() {
        for uv in [false, true] {
            let created = create(&creation(), ORIGIN, uv, &[]).unwrap();
            let att = binary(&created.response["response"], "attestationObject").unwrap();
            let mut cursor = att.as_slice();
            let att = cbor(&mut cursor);
            assert!(cursor.is_empty());
            assert_eq!(att["fmt"], "none");
            assert_eq!(att["attStmt"], json!({}));
            let auth = STANDARD.decode(att["authData"].as_str().unwrap()).unwrap();
            assert_eq!(
                auth,
                binary(&created.response["response"], "authenticatorData").unwrap()
            );
            assert_eq!(&auth[..32], &hash(b"example.com"));
            assert_eq!(auth[32], if uv { 0x45 } else { 0x41 });
            assert_eq!(&auth[33..37], &[0; 4]);
            assert_eq!(&auth[37..53], &AAGUID);
            assert_eq!(u16::from_be_bytes([auth[53], auth[54]]), 32);
            assert_eq!(
                &auth[55..87],
                &stored(&created.credential, "credentialId").unwrap()
            );
            let mut cose_bytes = &auth[87..];
            let cose = cbor(&mut cose_bytes);
            assert!(cose_bytes.is_empty());
            assert_eq!(cose["1"], 2);
            assert_eq!(cose["3"], -7);
            assert_eq!(cose["-1"], 1);
            let mut public = vec![4];
            public.extend(STANDARD.decode(cose["-2"].as_str().unwrap()).unwrap());
            public.extend(STANDARD.decode(cose["-3"].as_str().unwrap()).unwrap());
            assert_eq!(
                binary(&created.response["response"], "publicKey").unwrap(),
                spki(&public)
            );
            assert_eq!(
                created.response["clientExtensionResults"],
                json!({"credProps":{"rk":true}})
            );
            let asserted = get(&request(), ORIGIN, uv, &created.credential).unwrap();
            let response = &asserted.response["response"];
            let auth = binary(response, "authenticatorData").unwrap();
            assert_eq!(auth.len(), 37);
            assert_eq!(&auth[..32], &hash(b"example.com"));
            assert_eq!(auth[32], if uv { 5 } else { 1 });
            assert_eq!(&auth[33..], &1u32.to_be_bytes());
            let client = binary(response, "clientDataJSON").unwrap();
            let parsed: Value = serde_json::from_slice(&client).unwrap();
            assert_eq!(parsed["type"], "webauthn.get");
            assert_eq!(parsed["origin"], ORIGIN);
            assert_eq!(parsed["challenge"], request()["challenge"]);
            let mut signed = auth;
            signed.extend(hash(&client));
            let signature = binary(response, "signature").unwrap();
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &public)
                .verify(&signed, &signature)
                .unwrap();
            signed[0] ^= 1;
            assert!(UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &public)
                .verify(&signed, &signature)
                .is_err());
            assert_eq!(asserted.credential["signCount"], 1);
            assert_eq!(created.credential["signCount"], 0);
        }
    }
    #[test]
    fn basic_attestation_uses_stable_x5c_identity_and_distinct_fresh_credential_keys() {
        let mut config = configuration();
        config.attestation_mode = AttestationMode::Basic;
        config.attestation_identity = Some(
            crate::authenticator::attestation::build_identity(
                crate::authenticator::attestation::AttestationInput::Generate {
                    country: "US".into(),
                    organization: "Synthetic lab".into(),
                    common_name: "Test software key".into(),
                    valid_days: 30,
                },
                &config.model_aaguid,
            )
            .unwrap(),
        );
        let mut options = creation();
        options["attestation"] = json!("direct");
        let first = create_with_config(&options, ORIGIN, false, &config).unwrap();
        let second = create_with_config(&options, ORIGIN, false, &config).unwrap();
        let chain = config
            .attestation_identity
            .as_ref()
            .unwrap()
            .certificate_chain()
            .unwrap();
        use x509_parser::prelude::FromDer;
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&chain[0]).unwrap();
        let verifier = UnparsedPublicKey::new(
            &ECDSA_P256_SHA256_ASN1,
            cert.public_key().subject_public_key.data.as_ref(),
        );
        for created in [&first, &second] {
            let encoded = binary(&created.response["response"], "attestationObject").unwrap();
            let mut cursor = encoded.as_slice();
            let att = cbor(&mut cursor);
            assert!(cursor.is_empty());
            assert_eq!(att["fmt"], "packed");
            assert_eq!(att["attStmt"]["alg"], -7);
            assert_eq!(att["attStmt"]["x5c"], json!([STANDARD.encode(&chain[0])]));
            assert_eq!(
                created.credential["registrationAttestation"],
                "packed-basic"
            );
            assert_eq!(
                created.credential["registrationRequestedAttestation"],
                "direct"
            );
            let mut signed = binary(&created.response["response"], "authenticatorData").unwrap();
            signed.extend(hash(
                &binary(&created.response["response"], "clientDataJSON").unwrap(),
            ));
            let signature = STANDARD
                .decode(att["attStmt"]["sig"].as_str().unwrap())
                .unwrap();
            verifier.verify(&signed, &signature).unwrap();
            let credential_public = binary(&created.response["response"], "publicKey").unwrap();
            assert!(UnparsedPublicKey::new(
                &ECDSA_P256_SHA256_ASN1,
                &credential_public[credential_public.len() - 65..]
            )
            .verify(&signed, &signature)
            .is_err());
            signed[0] ^= 1;
            assert!(verifier.verify(&signed, &signature).is_err());
        }
        assert_ne!(
            first.credential["privateKey"],
            second.credential["privateKey"]
        );
        for requested in ["none", "enterprise"] {
            options["attestation"] = json!(requested);
            let created = create_with_config(&options, ORIGIN, false, &config).unwrap();
            let encoded = binary(&created.response["response"], "attestationObject").unwrap();
            let att = cbor(&mut encoded.as_slice());
            assert_eq!(att["fmt"], "none");
            assert_eq!(att["attStmt"], json!({}));
            assert_eq!(
                &binary(&created.response["response"], "authenticatorData").unwrap()[37..53],
                uuid::Uuid::parse_str(&config.model_aaguid)
                    .unwrap()
                    .as_bytes()
            );
        }
    }

    #[test]
    fn self_attestation_signs_auth_data_and_client_hash_without_a_trust_chain() {
        let mut config = configuration();
        config.attestation_mode = AttestationMode::SelfAttestation;
        config.model_aaguid = crate::authenticator::cdp::OWN_MODEL_AAGUID.into();
        for requested in ["direct", "indirect"] {
            let mut options = creation();
            options["attestation"] = json!(requested);
            let created = create_with_config(&options, ORIGIN, false, &config).unwrap();
            let encoded = binary(&created.response["response"], "attestationObject").unwrap();
            let mut cursor = encoded.as_slice();
            let attestation = cbor(&mut cursor);
            assert!(cursor.is_empty());
            assert_eq!(attestation["fmt"], "packed");
            assert_eq!(
                created.credential["registrationAaguid"],
                crate::authenticator::cdp::OWN_MODEL_AAGUID
            );
            assert_eq!(created.credential["registrationAttestation"], "packed-self");
            assert_eq!(attestation["attStmt"]["alg"], -7);
            assert_eq!(attestation["attStmt"].as_object().unwrap().len(), 2);
            assert!(attestation["attStmt"].get("x5c").is_none());
            let auth = STANDARD
                .decode(attestation["authData"].as_str().unwrap())
                .unwrap();
            assert_eq!(
                &auth[37..53],
                uuid::Uuid::parse_str(crate::authenticator::cdp::OWN_MODEL_AAGUID)
                    .unwrap()
                    .as_bytes()
            );
            assert_eq!(
                auth,
                binary(&created.response["response"], "authenticatorData").unwrap()
            );
            let mut signed = auth;
            signed.extend(hash(
                &binary(&created.response["response"], "clientDataJSON").unwrap(),
            ));
            let public = binary(&created.response["response"], "publicKey").unwrap();
            let verifier =
                UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &public[public.len() - 65..]);
            let signature = STANDARD
                .decode(attestation["attStmt"]["sig"].as_str().unwrap())
                .unwrap();
            verifier.verify(&signed, &signature).unwrap();
            signed[37] ^= 1;
            assert!(verifier.verify(&signed, &signature).is_err());
        }
    }

    #[test]
    fn attestation_matrix_preserves_exact_model_bytes_and_never_leaks_suppressed_proof() {
        // Both transports use the same Level 3 AAGUID rule. None/default and
        // disallowed enterprise suppress proof even for a certificate-capable key.
        for attachment in ["platform", "cross-platform"] {
            for model in [
                "00112233-4455-4677-8899-AABBCCDDEEFF",
                " 00112233445546778899AABBCCDDEEFF ",
                crate::authenticator::cdp::DEFAULT_MODEL_AAGUID,
                "00000000000000000000000000000000",
            ] {
                let canonical = crate::authenticator::cdp::canonical_aaguid(model).unwrap();
                for mode in [
                    AttestationMode::None,
                    AttestationMode::SelfAttestation,
                    AttestationMode::Basic,
                ] {
                    let mut config = configuration();
                    config.attachment = attachment.into();
                    config.model_aaguid = model.into();
                    config.provider_label = "Synthetic private provider label".into();
                    config.attestation_mode = mode;
                    if mode == AttestationMode::Basic {
                        config.attestation_identity = Some(
                            crate::authenticator::attestation::build_identity(
                                crate::authenticator::attestation::AttestationInput::Generate {
                                    country: "US".into(),
                                    organization: "Synthetic test lab".into(),
                                    common_name: "Never exposed in none responses".into(),
                                    valid_days: 30,
                                },
                                model,
                            )
                            .unwrap(),
                        );
                    }
                    let before = serde_json::to_value(&config).unwrap();
                    for requested in [
                        None,
                        Some("none"),
                        Some("direct"),
                        Some("indirect"),
                        Some("enterprise"),
                    ] {
                        let mut options = creation();
                        if let Some(requested) = requested {
                            options["attestation"] = json!(requested);
                        }
                        let created = create_with_config(&options, ORIGIN, false, &config).unwrap();
                        let encoded =
                            binary(&created.response["response"], "attestationObject").unwrap();
                        let mut cursor = encoded.as_slice();
                        let att = cbor(&mut cursor);
                        assert!(cursor.is_empty());
                        let auth =
                            binary(&created.response["response"], "authenticatorData").unwrap();
                        assert_eq!(
                            STANDARD.decode(att["authData"].as_str().unwrap()).unwrap(),
                            auth
                        );
                        // Verify byte ordering directly, not only the string snapshot.
                        let expected =
                            if canonical == crate::authenticator::cdp::DEFAULT_MODEL_AAGUID {
                                [0; 16]
                            } else {
                                [
                                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x46, 0x77, 0x88, 0x99,
                                    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                                ]
                            };
                        assert_eq!(&auth[37..53], &expected);
                        assert_eq!(&auth[..32], &hash(b"example.com"));
                        assert_eq!(auth[32], 0x41);
                        assert_eq!(&auth[33..37], &[0; 4]);
                        let sends_proof = matches!(requested, Some("direct" | "indirect"))
                            && mode != AttestationMode::None;
                        let effective = if !sends_proof {
                            "none"
                        } else if mode == AttestationMode::Basic {
                            "packed-basic"
                        } else {
                            "packed-self"
                        };
                        let expected_fmt = if sends_proof { "packed" } else { "none" };
                        // Exact object shape rules out signatures/certificates outside attStmt.
                        assert_eq!(att.as_object().unwrap().len(), 3);
                        assert_eq!(att["fmt"], expected_fmt);
                        if !sends_proof {
                            assert_eq!(
                                att,
                                json!({
                                    "fmt":"none", "attStmt":{}, "authData":STANDARD.encode(&auth)
                                })
                            );
                        } else {
                            let mut signed = auth.clone();
                            signed.extend(hash(
                                &binary(&created.response["response"], "clientDataJSON").unwrap(),
                            ));
                            let signature = STANDARD
                                .decode(att["attStmt"]["sig"].as_str().unwrap())
                                .unwrap();
                            let public = if mode == AttestationMode::Basic {
                                let chain = config
                                    .attestation_identity
                                    .as_ref()
                                    .unwrap()
                                    .certificate_chain()
                                    .unwrap();
                                assert_eq!(
                                    att["attStmt"]["x5c"],
                                    json!([STANDARD.encode(&chain[0])])
                                );
                                assert_eq!(att["attStmt"].as_object().unwrap().len(), 3);
                                use x509_parser::prelude::FromDer;
                                let (_, cert) =
                                    x509_parser::certificate::X509Certificate::from_der(&chain[0])
                                        .unwrap();
                                cert.public_key().subject_public_key.data.to_vec()
                            } else {
                                assert_eq!(att["attStmt"].as_object().unwrap().len(), 2);
                                assert!(att["attStmt"].get("x5c").is_none());
                                let spki =
                                    binary(&created.response["response"], "publicKey").unwrap();
                                spki[spki.len() - 65..].to_vec()
                            };
                            assert_eq!(att["attStmt"]["alg"], -7);
                            UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public)
                                .verify(&signed, &signature)
                                .unwrap();
                        }
                        assert_eq!(created.credential["registrationAttestation"], effective);
                        assert_eq!(created.credential["registrationAaguid"], canonical);
                        assert_eq!(
                            created.credential["registrationRequestedAttestation"],
                            requested.unwrap_or("none")
                        );
                        assert_eq!(
                            effective_attestation(requested.unwrap_or("none"), &config).unwrap(),
                            (effective, canonical.clone())
                        );
                        assert_eq!(
                            created.credential["registrationIdentity"]["modelAaguid"],
                            canonical
                        );
                        assert!(!created.response.to_string().contains("privateKey"));
                        assert!(!created.response.to_string().contains("provider"));
                        assert!(!encoded
                            .windows(config.provider_label.len())
                            .any(|w| w == config.provider_label.as_bytes()));
                    }
                    assert_eq!(serde_json::to_value(&config).unwrap(), before);
                }
            }
        }
    }

    #[test]
    fn custom_model_uuid_is_signed_and_provider_is_local_metadata_only() {
        let mut config = configuration();
        config.provider_label = "Custom lab 软件".into();
        config.model_aaguid = "00112233-4455-4677-8899-AABBCCDDEEFF".into();
        config.attestation_mode = AttestationMode::SelfAttestation;
        for mode in ["direct", "indirect", "none", "enterprise"] {
            let mut options = creation();
            options["attestation"] = json!(mode);
            let created = create_with_config(&options, ORIGIN, true, &config).unwrap();
            let encoded = binary(&created.response["response"], "attestationObject").unwrap();
            let mut cursor = encoded.as_slice();
            let att = cbor(&mut cursor);
            assert!(cursor.is_empty());
            let auth = STANDARD.decode(att["authData"].as_str().unwrap()).unwrap();
            let sends_proof = matches!(mode, "direct" | "indirect");
            let expected = *uuid::Uuid::parse_str(&config.model_aaguid)
                .unwrap()
                .as_bytes();
            assert_eq!(&auth[37..53], &expected);
            assert_eq!(
                created.credential["registrationAaguid"],
                uuid::Uuid::from_bytes(expected).to_string()
            );
            let identity = &created.credential["registrationIdentity"];
            assert_eq!(identity["providerLabel"], config.provider_label);
            assert_eq!(
                identity["modelAaguid"],
                crate::authenticator::cdp::canonical_aaguid(&config.model_aaguid).unwrap()
            );
            assert_eq!(identity["attachment"], config.attachment);
            assert_eq!(identity["residentKeySupported"], true);
            assert_eq!(identity["attestationMode"], "self");
            assert!(!created.response.to_string().contains("provider"));
            assert!(!encoded
                .windows(config.provider_label.len())
                .any(|w| w == config.provider_label.as_bytes()));
            if sends_proof {
                assert_eq!(att["fmt"], "packed");
                assert_eq!(att["attStmt"]["alg"], -7);
                assert!(att["attStmt"].get("x5c").is_none());
                let mut cose_bytes = &auth[87..];
                let cose = cbor(&mut cose_bytes);
                let mut public = vec![4];
                public.extend(STANDARD.decode(cose["-2"].as_str().unwrap()).unwrap());
                public.extend(STANDARD.decode(cose["-3"].as_str().unwrap()).unwrap());
                let mut signed = auth;
                signed.extend(hash(
                    &binary(&created.response["response"], "clientDataJSON").unwrap(),
                ));
                let signature = STANDARD
                    .decode(att["attStmt"]["sig"].as_str().unwrap())
                    .unwrap();
                UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &public)
                    .verify(&signed, &signature)
                    .unwrap();
                signed[37] ^= 1;
                assert!(UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &public)
                    .verify(&signed, &signature)
                    .is_err());
            } else {
                assert_eq!(att["fmt"], "none");
                assert_eq!(att["attStmt"], json!({}));
            }
        }
    }

    #[test]
    fn every_registration_has_fresh_key_and_assertions_reuse_it_with_snapshot() {
        let mut config = configuration();
        config.provider_label = "Original provider".into();
        let first = create_with_config(&creation(), ORIGIN, false, &config).unwrap();
        config.credentials.push(first.credential.clone());
        let second = create_with_config(&creation(), ORIGIN, false, &config).unwrap();
        let mut another_rp = creation();
        another_rp["rp"]["id"] = json!("other.test");
        another_rp["extensions"]
            .as_object_mut()
            .unwrap()
            .remove("remoteDesktopClientOverride");
        let third = create_with_config(&another_rp, "https://other.test", false, &config).unwrap();
        for other in [&second, &third] {
            assert_ne!(
                first.credential["privateKey"],
                other.credential["privateKey"]
            );
            assert_ne!(
                first.credential["credentialId"],
                other.credential["credentialId"]
            );
            assert_ne!(
                first.response["response"]["publicKey"],
                other.response["response"]["publicKey"]
            );
        }
        config.name = "Renamed nickname".into();
        config.provider_label = "Renamed local provider".into();
        config.presence_timeout_seconds = 15;
        let mut credential = config.credentials[0].clone();
        let public = binary(&first.response["response"], "publicKey").unwrap();
        let verifier =
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &public[public.len() - 65..]);
        for counter in 1..=3 {
            let assertion = get(&request(), ORIGIN, false, &credential).unwrap();
            let response = &assertion.response["response"];
            let mut signed = binary(response, "authenticatorData").unwrap();
            signed.extend(hash(&binary(response, "clientDataJSON").unwrap()));
            verifier
                .verify(&signed, &binary(response, "signature").unwrap())
                .unwrap();
            assert_eq!(assertion.credential["signCount"], counter);
            assert_eq!(
                assertion.credential["privateKey"],
                first.credential["privateKey"]
            );
            assert_eq!(
                assertion.credential["registrationIdentity"],
                first.credential["registrationIdentity"]
            );
            credential = assertion.credential;
        }
    }

    #[test]
    fn resident_support_controls_new_registration_without_erasing_credentials() {
        let mut config = configuration();
        let old = create_with_config(&creation(), ORIGIN, false, &config).unwrap();
        config.credentials.push(old.credential.clone());
        config.resident_key_supported = false;
        assert!(resident_key_required(&creation()));
        assert!(create_with_config(&creation(), ORIGIN, false, &config).is_err());
        assert!(get(&request(), ORIGIN, false, &config.credentials[0]).is_ok());
        assert_eq!(config.credentials[0], old.credential);
        for preference in ["preferred", "discouraged"] {
            let mut options = creation();
            options["authenticatorSelection"]["residentKey"] = json!(preference);
            // Modern residentKey wins over contradictory legacy preference.
            options["authenticatorSelection"]["requireResidentKey"] = json!(true);
            assert!(!resident_key_required(&options));
            let created = create_with_config(&options, ORIGIN, false, &config).unwrap();
            assert_eq!(created.credential["isResidentCredential"], false);
            assert_eq!(
                created.response["clientExtensionResults"]["credProps"]["rk"],
                false
            );
            assert!(!eligible_get(&request(), &created.credential));
            let mut get_options = request();
            get_options["allowCredentials"] =
                json!([{"type":"public-key","id":created.response["id"]}]);
            assert!(get(&get_options, ORIGIN, false, &created.credential).is_ok());
        }
        let mut legacy = creation();
        legacy["authenticatorSelection"] = json!({"requireResidentKey":true});
        assert!(resident_key_required(&legacy));
        assert!(create_with_config(&legacy, ORIGIN, false, &config).is_err());
        config.resident_key_supported = true;
        assert_eq!(
            create_with_config(&legacy, ORIGIN, false, &config)
                .unwrap()
                .credential["isResidentCredential"],
            true
        );
    }
    #[test]
    fn uv_requirement_cannot_be_bypassed() {
        let mut options = creation();
        options["authenticatorSelection"]["userVerification"] = json!("required");
        assert!(create(&options, ORIGIN, false, &[]).is_err());
        let c = create(&options, ORIGIN, true, &[]).unwrap();
        let mut options = request();
        options["userVerification"] = json!("required");
        assert!(get(&options, ORIGIN, false, &c.credential).is_err());
        assert!(get(&options, ORIGIN, true, &c.credential).is_ok());
    }
    #[test]
    fn rp_exclusion_and_allow_list_enforced() {
        let c = create(&creation(), ORIGIN, false, &[]).unwrap();
        let id = c.response["id"].clone();
        let mut options = creation();
        options["excludeCredentials"] = json!([{"type":"public-key","id":id}]);
        assert!(create(&options, ORIGIN, false, std::slice::from_ref(&c.credential)).is_err());
        let mut options = request();
        options["allowCredentials"] = json!([{"type":"public-key","id":"d3Jvbmc"}]);
        assert!(!eligible_get(&options, &c.credential));
        assert!(get(&options, ORIGIN, false, &c.credential).is_err());
        options["allowCredentials"][0]["id"] = id;
        assert!(get(&options, ORIGIN, false, &c.credential).is_ok());
        options["rpId"] = json!("attacker.com");
        assert!(get(&options, "https://attacker.com", false, &c.credential).is_err());
        assert!(get(&request(), "https://evilexample.com", false, &c.credential).is_err());
        assert!(get(&request(), "http://example.com", false, &c.credential).is_err());
    }
    #[test]
    fn nonresident_requires_id_and_counter_never_wraps() {
        let mut options = creation();
        options["authenticatorSelection"] = json!({"residentKey":"discouraged"});
        let mut c = create(&options, ORIGIN, false, &[]).unwrap();
        assert!(!eligible_get(&request(), &c.credential));
        let mut r = request();
        r["allowCredentials"] = json!([{"type":"public-key","id":c.response["id"]}]);
        assert!(eligible_get(&r, &c.credential));
        c.credential["signCount"] = json!(u32::MAX);
        assert!(get(&r, ORIGIN, false, &c.credential).is_err());
    }
    #[test]
    fn malformed_unsupported_and_cross_origin_requests_fail() {
        for invalid in [json!("bogus"), json!(7), json!(null)] {
            let mut options = creation();
            options["attestation"] = invalid;
            assert!(create(&options, ORIGIN, false, &[]).is_err());
        }
        let mut c = creation();
        c["pubKeyCredParams"][0]["alg"] = json!(-257);
        assert!(create(&c, ORIGIN, false, &[]).is_err());
        let mut c = creation();
        c["challenge"] = json!("%%%invalid");
        assert!(create(&c, ORIGIN, false, &[]).is_err());
        let mut c = creation();
        c["user"]["id"] = json!("");
        assert!(create(&c, ORIGIN, false, &[]).is_err());
        let mut c = creation();
        c["extensions"]["remoteDesktopClientOverride"]["sameOriginWithAncestors"] = json!(false);
        assert!(create(&c, ORIGIN, false, &[]).is_err());
        assert!(create(&creation(), "https://example.com", false, &[]).is_err());
        let mut c = creation();
        c["extensions"]["appid"] = json!("https://example.com");
        assert!(create(&c, ORIGIN, false, &[]).is_err());
    }
}
