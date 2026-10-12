//! Optional software attestation identities. A validated chain is not a trust claim.
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use rcgen::{
    CertificateParams, CustomExtension, DistinguishedName, DnType, DnValue, IsCa, KeyUsagePurpose,
};
use ring::{
    digest,
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use x509_parser::prelude::*;

const MAX_CHAIN: usize = 5;
const MAX_CERT: usize = 16 * 1024;
const MAX_PEM: usize = 120 * 1024;
const AAGUID_OID: &str = "1.3.6.1.4.1.45724.1.1.4";
const BASIC_CONSTRAINTS_OID: &str = "2.5.29.19";

fn non_ca_constraints(params: &mut CertificateParams) {
    // rcgen 0.13's ExplicitNoCa encodes the DEFAULT FALSE Boolean explicitly,
    // which strict DER decoders reject as EncodedDefault at BasicConstraints::ca.
    // RFC 5280 Appendix B requires omission: CA:false, no pathLen is 30 00.
    // Add this before signing; never rewrite an already signed certificate.
    params.is_ca = IsCa::NoCa;
    let mut constraints = CustomExtension::from_oid_content(&[2, 5, 29, 19], vec![0x30, 0x00]);
    constraints.set_criticality(true);
    params.custom_extensions.push(constraints);
}

fn validate_basic_constraints_der(cert: &X509Certificate<'_>) -> Result<()> {
    for ext in cert.extensions() {
        if ext.oid.to_id_string() != BASIC_CONSTRAINTS_OID {
            continue;
        }
        let bc = cert
            .basic_constraints()?
            .context("Invalid basicConstraints extension")?;
        let mut contents = Vec::new();
        if bc.value.ca {
            contents.extend_from_slice(&[0x01, 0x01, 0xff]);
        }
        if let Some(limit) = bc.value.path_len_constraint {
            ensure!(bc.value.ca, "Only a CA may have a path length constraint");
            let bytes = limit.to_be_bytes();
            let first = bytes.iter().position(|&b| b != 0).unwrap_or(3);
            let integer = &bytes[first..];
            let sign_pad = usize::from(integer[0] & 0x80 != 0);
            contents.extend_from_slice(&[0x02, (integer.len() + sign_pad) as u8]);
            if sign_pad != 0 {
                contents.push(0);
            }
            contents.extend_from_slice(integer);
        }
        let mut canonical = vec![0x30, contents.len() as u8];
        canonical.extend_from_slice(&contents);
        ensure!(
            ext.value == canonical,
            "Noncanonical basicConstraints DER: DEFAULT FALSE must be omitted and values must use canonical DER; create a new certificate identity for certificate attestation. Existing credentials can still authenticate"
        );
    }
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationIdentity {
    private_key_pkcs8: String,
    certificate_chain_der: Vec<String>,
}
// Secret material must never appear in logs or API summaries.
impl std::fmt::Debug for AttestationIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttestationIdentity")
            .field("certificate_count", &self.certificate_chain_der.len())
            .finish_non_exhaustive()
    }
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AttestationInput {
    Generate {
        country: String,
        organization: String,
        common_name: String,
        valid_days: u32,
    },
    Import {
        certificate_chain_pem: String,
        private_key_pem: String,
    },
}
fn country_valid(s: &str) -> bool {
    // ISO 3166-1 alpha-2 assigned codes. User-assigned/reserved codes are excluded.
    "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW".split_whitespace().any(|c| c == s)
}
fn subject_text(s: &str) -> bool {
    !s.trim().is_empty() && s.chars().count() <= 120 && !s.chars().any(char::is_control)
}
fn strict_pem(input: &str, tag: &str, max: usize) -> Result<Vec<Vec<u8>>> {
    ensure!(input.len() <= max, "PEM input exceeds size limit");
    let begin = format!("-----BEGIN {tag}-----");
    let end = format!("-----END {tag}-----");
    let mut rest = input.trim();
    let mut out = Vec::new();
    while !rest.is_empty() {
        ensure!(rest.starts_with(&begin), "Unexpected PEM content or label");
        let stop = rest.find(&end).context("Incomplete PEM block")? + end.len();
        let block = ::pem::parse(&rest[..stop]).context("Invalid PEM")?;
        ensure!(block.tag() == tag, "Unexpected PEM label");
        out.push(block.into_contents());
        ensure!(out.len() <= MAX_CHAIN, "Too many PEM blocks");
        rest = rest[stop..].trim();
    }
    ensure!(!out.is_empty(), "Empty PEM input");
    Ok(out)
}
pub fn build_identity(input: AttestationInput, model_aaguid: &str) -> Result<AttestationIdentity> {
    let aaguid = crate::authenticator::cdp::parse_aaguid(model_aaguid)?;
    let identity = match input {
        AttestationInput::Generate {
            country,
            organization,
            common_name,
            valid_days,
        } => {
            ensure!(
                country_valid(&country),
                "Country must be two uppercase letters"
            );
            ensure!(
                subject_text(&organization) && subject_text(&common_name),
                "Organization and common name must be 1 to 120 characters without controls"
            );
            ensure!(
                (1..=3650).contains(&valid_days),
                "Certificate validity must be 1 to 3650 days"
            );
            let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
            let mut params = CertificateParams::default();
            let mut dn = DistinguishedName::new();
            dn.push(
                DnType::CountryName,
                DnValue::PrintableString(country.try_into()?),
            );
            dn.push(DnType::OrganizationName, organization);
            dn.push(DnType::OrganizationalUnitName, "Authenticator Attestation");
            dn.push(DnType::CommonName, common_name);
            params.distinguished_name = dn;
            non_ca_constraints(&mut params);
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            let now = ::time::OffsetDateTime::now_utc();
            params.not_before = now - ::time::Duration::minutes(5);
            params.not_after = now + ::time::Duration::days(valid_days as i64);
            let mut encoded_aaguid = vec![0x04, 0x10];
            encoded_aaguid.extend_from_slice(aaguid.as_bytes());
            params
                .custom_extensions
                .push(CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 4, 1, 45724, 1, 1, 4],
                    encoded_aaguid,
                ));
            let cert = params.self_signed(&key)?;
            AttestationIdentity {
                private_key_pkcs8: STANDARD.encode(key.serialize_der()),
                certificate_chain_der: vec![STANDARD.encode(cert.der())],
            }
        }
        AttestationInput::Import {
            certificate_chain_pem,
            private_key_pem,
        } => {
            let certs = strict_pem(&certificate_chain_pem, "CERTIFICATE", MAX_PEM)?;
            let keys = strict_pem(&private_key_pem, "PRIVATE KEY", 8192)?;
            ensure!(
                keys.len() == 1,
                "Exactly one unencrypted PKCS8 private key is required"
            );
            AttestationIdentity {
                private_key_pkcs8: STANDARD.encode(&keys[0]),
                certificate_chain_der: certs.iter().map(|c| STANDARD.encode(c)).collect(),
            }
        }
    };
    identity.validate_current(model_aaguid)?;
    Ok(identity)
}
impl AttestationIdentity {
    pub fn certificate_chain(&self) -> Result<Vec<Vec<u8>>> {
        ensure!(
            !self.certificate_chain_der.is_empty() && self.certificate_chain_der.len() <= MAX_CHAIN,
            "Certificate chain must have 1 to 5 certificates"
        );
        self.certificate_chain_der
            .iter()
            .map(|s| {
                ensure!(s.len() <= MAX_CERT * 2, "Certificate exceeds size limit");
                let der = STANDARD
                    .decode(s)
                    .context("Invalid stored certificate encoding")?;
                ensure!(der.len() <= MAX_CERT, "Certificate exceeds size limit");
                Ok(der)
            })
            .collect()
    }
    fn signing_key(&self) -> Result<EcdsaKeyPair> {
        ensure!(
            self.private_key_pkcs8.len() <= 8192,
            "Private key exceeds size limit"
        );
        let der = STANDARD
            .decode(&self.private_key_pkcs8)
            .context("Invalid stored key encoding")?;
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &der, &SystemRandom::new())
            .map_err(|_| {
                anyhow::anyhow!("Attestation key must be an unencrypted P-256 PKCS8 signing key")
            })
    }
    pub fn validate(&self, model_aaguid: &str) -> Result<()> {
        // Structural persistence/restore validation deliberately accepts the
        // legacy rcgen encoding. Do not make an old certificate prevent loading
        // a store or using its unrelated, previously registered credentials.
        self.validate_inner(model_aaguid, false)
    }
    pub fn validate_current(&self, model_aaguid: &str) -> Result<()> {
        self.validate_inner(model_aaguid, true)
    }
    fn validate_inner(&self, model_aaguid: &str, current: bool) -> Result<()> {
        let aaguid = crate::authenticator::cdp::parse_aaguid(model_aaguid)?;
        let chain = self.certificate_chain()?;
        let certs = chain
            .iter()
            .map(|der| {
                let (rest, cert) = X509Certificate::from_der(der)
                    .map_err(|_| anyhow::anyhow!("Invalid X.509 certificate"))?;
                ensure!(rest.is_empty(), "Trailing certificate DER data");
                Ok(cert)
            })
            .collect::<Result<Vec<_>>>()?;
        let leaf = &certs[0];
        ensure!(
            leaf.version() == X509Version::V3,
            "Attestation certificate must be X.509v3"
        );
        let subject = leaf.subject();
        let values = |oid: &str| -> Result<Vec<String>> {
            subject
                .iter_attributes()
                .filter(|a| a.attr_type().to_id_string() == oid)
                .map(|a| Ok(a.as_str().context("Invalid subject text")?.to_owned()))
                .collect()
        };
        let country = values("2.5.4.6")?;
        ensure!(
            country.len() == 1 && country_valid(&country[0]),
            "Certificate subject must have a two-letter country"
        );
        for oid in ["2.5.4.10", "2.5.4.3"] {
            let v = values(oid)?;
            ensure!(
                v.len() == 1 && subject_text(&v[0]),
                "Certificate requires organization and common name"
            );
        }
        ensure!(
            values("2.5.4.11")? == ["Authenticator Attestation"],
            "Certificate OU must be Authenticator Attestation"
        );
        let bc = leaf
            .basic_constraints()?
            .context("Certificate requires basicConstraints CA:false")?;
        ensure!(
            !bc.value.ca && bc.value.path_len_constraint.is_none(),
            "Attestation leaf must not be a CA"
        );
        let ku = leaf
            .key_usage()?
            .context("Certificate requires digitalSignature key usage")?;
        ensure!(
            ku.value.digital_signature() && !ku.value.key_cert_sign() && !ku.value.crl_sign(),
            "Invalid attestation key usage"
        );
        let key = self.signing_key()?;
        ensure!(
            leaf.public_key().algorithm.algorithm.to_id_string() == "1.2.840.10045.2.1"
                && leaf
                    .public_key()
                    .algorithm
                    .parameters
                    .as_ref()
                    .and_then(|p| p.as_oid().ok())
                    .map(|o| o.to_id_string())
                    .as_deref()
                    == Some("1.2.840.10045.3.1.7"),
            "Certificate key must be P-256"
        );
        ensure!(
            leaf.public_key().subject_public_key.data.as_ref() == key.public_key().as_ref(),
            "Certificate and private key do not match"
        );
        for (i, cert) in certs.iter().enumerate() {
            cert.extensions_map()
                .context("Duplicate certificate extensions")?;
            if current {
                validate_basic_constraints_der(cert)?;
            }
            ensure!(
                cert.validity().not_before < cert.validity().not_after,
                "Invalid certificate validity interval"
            );
            ensure!(
                !current || cert.validity().is_valid(),
                "Attestation certificate is expired or not yet valid"
            );
            for ext in cert.extensions() {
                let oid = ext.oid.to_id_string();
                if oid == AAGUID_OID && i == 0 {
                    ensure!(
                        !ext.critical
                            && ext.value.len() == 18
                            && ext.value[..2] == [4, 16]
                            && ext.value[2..] == aaguid.as_bytes()[..],
                        "AAGUID extension must be noncritical and match model AAGUID"
                    );
                }
                ensure!(
                    !ext.critical || matches!(oid.as_str(), "2.5.29.19" | "2.5.29.15"),
                    "Unsupported critical certificate extension"
                );
            }
            if let Some(issuer) = certs.get(i + 1) {
                ensure!(
                    cert.issuer() == issuer.subject(),
                    "Certificate chain issuer mismatch"
                );
                let bc = issuer
                    .basic_constraints()?
                    .context("Chain issuer must be a CA")?;
                ensure!(bc.value.ca, "Chain issuer must be a CA");
                if let Some(limit) = bc.value.path_len_constraint {
                    ensure!((i as u32) <= limit, "Certificate chain exceeds path length");
                }
                if let Some(usage) = issuer.key_usage()? {
                    ensure!(
                        usage.value.key_cert_sign(),
                        "Chain issuer cannot sign certificates"
                    );
                }
                cert.verify_signature(Some(issuer.public_key()))
                    .context("Certificate chain signature is invalid")?;
            } else if cert.issuer() == cert.subject() {
                cert.verify_signature(None)
                    .context("Self-signed certificate signature is invalid")?;
            }
        }
        Ok(())
    }
    /// Caller validates current certificate validity and model before signing.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.signing_key()?
            .sign(&SystemRandom::new(), message)
            .map(|s| s.as_ref().to_vec())
            .map_err(|_| anyhow::anyhow!("Attestation signing failed"))
    }
    pub fn summary(&self) -> Result<Value> {
        let chain = self.certificate_chain()?;
        let (_, cert) = X509Certificate::from_der(&chain[0])
            .map_err(|_| anyhow::anyhow!("Invalid certificate"))?;
        let fingerprint = digest::digest(&digest::SHA256, &chain[0])
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        let currently_valid = chain
            .iter()
            .all(|der| X509Certificate::from_der(der).is_ok_and(|(_, c)| c.validity().is_valid()));
        let canonical_constraints = chain.iter().all(|der| {
            X509Certificate::from_der(der).is_ok_and(|(rest, c)| {
                rest.is_empty() && validate_basic_constraints_der(&c).is_ok()
            })
        });
        let warning = if !canonical_constraints {
            Some("此证明证书的 basicConstraints 编码不符合 DER，无法用于新的证书证明注册。请新建证书身份；保留旧密钥可继续登录已有凭据。")
        } else if !currently_valid {
            Some("此证明证书已过期或尚未生效，无法用于新的证书证明注册。请检查有效期或新建证书身份；保留旧密钥可继续登录已有凭据。")
        } else {
            None
        };
        Ok(
            json!({"subject":cert.subject().to_string(),"not_before":cert.validity().not_before.to_rfc2822().map_err(|e| anyhow::anyhow!(e))?,"not_after":cert.validity().not_after.to_rfc2822().map_err(|e| anyhow::anyhow!(e))?,"sha256":fingerprint,"chain_length":chain.len(),"currently_valid":currently_valid,"registration_usable":currently_valid && canonical_constraints,"warning":warning,"trust":"Unverified software attestation; RP trust policy decides acceptance"}),
        )
    }
}

#[cfg(test)]
pub(crate) fn legacy_noncanonical_test_identity(model_aaguid: &str) -> AttestationIdentity {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CountryName, "US");
    dn.push(DnType::OrganizationName, "Synthetic legacy lab");
    dn.push(DnType::OrganizationalUnitName, "Authenticator Attestation");
    dn.push(DnType::CommonName, "Synthetic legacy device");
    params.distinguished_name = dn;
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let mut aaguid = vec![0x04, 0x10];
    aaguid.extend_from_slice(uuid::Uuid::parse_str(model_aaguid).unwrap().as_bytes());
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 45724, 1, 1, 4],
            aaguid,
        ));
    let cert = params.self_signed(&key).unwrap();
    AttestationIdentity {
        private_key_pkcs8: STANDARD.encode(key.serialize_der()),
        certificate_chain_der: vec![STANDARD.encode(cert.der())],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const MODEL: &str = "00112233-4455-4677-8899-aabbccddeeff";
    fn generate() -> AttestationIdentity {
        build_identity(
            AttestationInput::Generate {
                country: "US".into(),
                organization: "Synthetic lab".into(),
                common_name: "Synthetic test device".into(),
                valid_days: 365,
            },
            MODEL,
        )
        .unwrap()
    }
    fn import(identity: &AttestationIdentity) -> AttestationInput {
        AttestationInput::Import {
            certificate_chain_pem: identity
                .certificate_chain()
                .unwrap()
                .iter()
                .map(|c| ::pem::encode(&::pem::Pem::new("CERTIFICATE", c.as_slice())))
                .collect::<Vec<_>>()
                .join("\n"),
            private_key_pem: ::pem::encode(&::pem::Pem::new(
                "PRIVATE KEY",
                STANDARD.decode(&identity.private_key_pkcs8).unwrap(),
            )),
        }
    }
    #[test]
    fn generated_identity_roundtrips_import_and_redacts_secrets() {
        let identity = generate();
        identity.validate_current(MODEL).unwrap();
        let chain = identity.certificate_chain().unwrap();
        let (_, cert) = X509Certificate::from_der(&chain[0]).unwrap();
        let constraints = cert
            .extensions()
            .iter()
            .filter(|ext| ext.oid.to_id_string() == BASIC_CONSTRAINTS_OID)
            .collect::<Vec<_>>();
        assert_eq!(constraints.len(), 1);
        assert_eq!(constraints[0].value, &[0x30, 0x00]);
        assert!(constraints[0].critical);
        let country = cert.subject().iter_country().next().unwrap();
        assert_eq!(country.attr_value().tag().0, 19); // PrintableString
        assert_eq!(identity.summary().unwrap()["registration_usable"], true);
        assert!(identity.summary().unwrap()["warning"].is_null());
        let imported = build_identity(import(&identity), MODEL).unwrap();
        assert_eq!(
            imported.certificate_chain().unwrap(),
            identity.certificate_chain().unwrap()
        );
        let saved = serde_json::to_string(&identity).unwrap();
        let restored: AttestationIdentity = serde_json::from_str(&saved).unwrap();
        assert_eq!(restored.summary().unwrap(), identity.summary().unwrap());
        assert!(!format!("{identity:?}").contains(&identity.private_key_pkcs8));
        assert!(!identity
            .summary()
            .unwrap()
            .to_string()
            .contains(&identity.private_key_pkcs8));
        let public = identity.signing_key().unwrap();
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            public.public_key(),
        )
        .verify(b"synthetic", &imported.sign(b"synthetic").unwrap())
        .unwrap();
    }

    #[test]
    fn compact_aaguid_certificate_extension_is_exactly_sixteen_bytes() {
        for model in [
            " D5F8845E756D4F37B02C2BFCB446CF62 ",
            "00000000000000000000000000000000",
        ] {
            let expected = crate::authenticator::cdp::parse_aaguid(model).unwrap();
            let identity = build_identity(
                AttestationInput::Generate {
                    country: "US".into(),
                    organization: "Synthetic lab".into(),
                    common_name: "Synthetic AAGUID test".into(),
                    valid_days: 30,
                },
                model,
            )
            .unwrap();
            let chain = identity.certificate_chain().unwrap();
            let (_, cert) = X509Certificate::from_der(&chain[0]).unwrap();
            let extension = cert
                .extensions()
                .iter()
                .find(|ext| ext.oid.to_id_string() == AAGUID_OID)
                .unwrap();
            assert_eq!(extension.value.len(), 18);
            assert_eq!(&extension.value[..2], &[0x04, 0x10]);
            assert_eq!(&extension.value[2..], expected.as_bytes());
            assert!(!extension.critical);
            for form in [model.to_owned(), expected.hyphenated().to_string()] {
                identity.validate_current(&form).unwrap();
                let imported = build_identity(import(&identity), &form).unwrap();
                assert_eq!(
                    serde_json::to_value(imported).unwrap(),
                    serde_json::to_value(&identity).unwrap()
                );
            }
            assert!(build_identity(import(&identity), &format!("{{{expected}}}")).is_err());
        }
        for length in [0usize, 15, 17, 32] {
            let mut p = params();
            let mut bytes = vec![0x04, length as u8];
            bytes.extend(vec![0; length]);
            p.custom_extensions.push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 45724, 1, 1, 4],
                bytes,
            ));
            assert!(fixture(p)
                .validate_current(crate::authenticator::cdp::DEFAULT_MODEL_AAGUID)
                .is_err());
        }
    }
    #[test]
    fn legacy_encoded_default_preserves_identity_but_blocks_import_and_new_basic_signing() {
        let legacy = legacy_noncanonical_test_identity(MODEL);
        let before = serde_json::to_value(&legacy).unwrap();
        let chain = legacy.certificate_chain().unwrap();
        let (_, cert) = X509Certificate::from_der(&chain[0]).unwrap();
        let ext = cert
            .extensions()
            .iter()
            .find(|ext| ext.oid.to_id_string() == BASIC_CONSTRAINTS_OID)
            .unwrap();
        // This is the exact encoding rejected by cryptography / Yubico as
        // EncodedDefault at BasicConstraints::ca, despite x509-parser accepting it.
        assert_eq!(ext.value, &[0x30, 0x03, 0x01, 0x01, 0x00]);
        legacy.validate(MODEL).unwrap();
        let error = legacy.validate_current(MODEL).unwrap_err().to_string();
        assert!(error.contains("Noncanonical basicConstraints DER"));
        assert!(build_identity(import(&legacy), MODEL).is_err());
        let summary = legacy.summary().unwrap();
        assert_eq!(summary["currently_valid"], true);
        assert_eq!(summary["registration_usable"], false);
        assert!(summary["warning"].as_str().unwrap().contains("DER"));
        assert_eq!(serde_json::to_value(&legacy).unwrap(), before);
        assert!(!summary.to_string().contains(&legacy.private_key_pkcs8));
    }
    #[test]
    fn basic_constraints_der_rejects_trailing_data_and_canonicalizes_no_bytes() {
        for value in [
            vec![0x30, 0x00, 0x00],
            vec![0x30, 0x03, 0x01, 0x01, 0x00],
            vec![0x30, 0x03, 0x01, 0x01, 0xff, 0x00],
        ] {
            let mut p = CertificateParams::default();
            p.custom_extensions
                .push(CustomExtension::from_oid_content(&[2, 5, 29, 19], value));
            let identity = fixture(p);
            let chain = identity.certificate_chain().unwrap();
            let (_, cert) = X509Certificate::from_der(&chain[0]).unwrap();
            assert!(validate_basic_constraints_der(&cert).is_err());
        }
        for limit in [0, 1, 127, 128, 255] {
            let mut p = CertificateParams::default();
            p.is_ca = IsCa::Ca(rcgen::BasicConstraints::Constrained(limit));
            let identity = fixture(p);
            let chain = identity.certificate_chain().unwrap();
            let (_, cert) = X509Certificate::from_der(&chain[0]).unwrap();
            validate_basic_constraints_der(&cert).unwrap();
        }
    }
    #[test]
    fn import_rejects_mismatch_bad_aaguid_junk_and_oversize() {
        let identity = generate();
        let other = generate();
        let mut bad = identity.clone();
        bad.private_key_pkcs8 = other.private_key_pkcs8;
        assert!(bad.validate(MODEL).is_err());
        assert!(identity
            .validate("00000000-0000-0000-0000-000000000000")
            .is_err());
        if let AttestationInput::Import {
            mut certificate_chain_pem,
            private_key_pem,
        } = import(&identity)
        {
            certificate_chain_pem.push_str("junk");
            assert!(build_identity(
                AttestationInput::Import {
                    certificate_chain_pem,
                    private_key_pem
                },
                MODEL
            )
            .is_err());
        }
        bad.certificate_chain_der = vec!["A".repeat(MAX_CERT * 2 + 1)];
        assert!(bad.validate(MODEL).is_err());
        assert!(strict_pem(&" ".repeat(MAX_PEM + 1), "CERTIFICATE", MAX_PEM).is_err());
        assert!(!country_valid("ZZ"));
        assert!(!country_valid("us"));
    }
    fn fixture(params: CertificateParams) -> AttestationIdentity {
        fixture_subject(params, "Authenticator Attestation")
    }
    fn fixture_subject(mut params: CertificateParams, ou: &str) -> AttestationIdentity {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CountryName, "US");
        dn.push(DnType::OrganizationName, "Synthetic lab");
        dn.push(DnType::OrganizationalUnitName, ou);
        dn.push(DnType::CommonName, "Synthetic fixture");
        params.distinguished_name = dn;
        let cert = params.self_signed(&key).unwrap();
        AttestationIdentity {
            private_key_pkcs8: STANDARD.encode(key.serialize_der()),
            certificate_chain_der: vec![STANDARD.encode(cert.der())],
        }
    }
    fn params() -> CertificateParams {
        let mut p = CertificateParams::default();
        non_ca_constraints(&mut p);
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p
    }
    #[test]
    fn expired_identity_is_structurally_restorable_but_not_importable() {
        let mut p = params();
        p.not_before = rcgen::date_time_ymd(2020, 1, 1);
        p.not_after = rcgen::date_time_ymd(2021, 1, 1);
        let expired = fixture(p);
        expired.validate(MODEL).unwrap();
        assert!(expired.validate_current(MODEL).is_err());
        assert!(build_identity(import(&expired), MODEL).is_err());
        assert_eq!(expired.summary().unwrap()["currently_valid"], false);
        assert_eq!(expired.summary().unwrap()["registration_usable"], false);
        assert!(expired.summary().unwrap()["warning"]
            .as_str()
            .unwrap()
            .contains("已过期"));
    }
    #[test]
    fn certificate_constraints_and_self_signature_are_enforced() {
        assert!(fixture_subject(params(), "Incorrect OU")
            .validate(MODEL)
            .is_err());
        let mut unknown = params();
        let mut extension = CustomExtension::from_oid_content(&[1, 2, 3, 4, 5], vec![0x05, 0]);
        extension.set_criticality(true);
        unknown.custom_extensions.push(extension);
        assert!(fixture(unknown).validate(MODEL).is_err());
        let mut malformed = params();
        malformed
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[2, 5, 29, 19],
                vec![0xff],
            ));
        assert!(fixture(malformed).validate(MODEL).is_err());

        let mut p = params();
        p.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        assert!(fixture(p).validate(MODEL).is_err());
        let mut p = params();
        p.key_usages.clear();
        assert!(fixture(p).validate(MODEL).is_err());
        let mut p = params();
        let mut ext =
            CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 45724, 1, 1, 4], vec![4, 16, 0]);
        ext.set_criticality(true);
        p.custom_extensions.push(ext);
        assert!(fixture(p).validate(MODEL).is_err());
        let mut identity = generate();
        let mut der = identity.certificate_chain().unwrap().remove(0);
        let last = der.len() - 1;
        der[last] ^= 1;
        identity.certificate_chain_der[0] = STANDARD.encode(der);
        assert!(identity.validate(MODEL).is_err());
    }
    #[test]
    fn imported_chain_links_ca_and_path_length_are_checked() {
        let root_key = rcgen::KeyPair::generate().unwrap();
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Synthetic root");
        let root = root_params.self_signed(&root_key).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let mut p = params();
        p.distinguished_name = DistinguishedName::new();
        p.distinguished_name.push(DnType::CountryName, "US");
        p.distinguished_name
            .push(DnType::OrganizationName, "Synthetic lab");
        p.distinguished_name
            .push(DnType::OrganizationalUnitName, "Authenticator Attestation");
        p.distinguished_name
            .push(DnType::CommonName, "Synthetic leaf");
        let cert = p.signed_by(&key, &root, &root_key).unwrap();
        let mut identity = AttestationIdentity {
            private_key_pkcs8: STANDARD.encode(key.serialize_der()),
            certificate_chain_der: vec![STANDARD.encode(cert.der()), STANDARD.encode(root.der())],
        };
        identity.validate_current(MODEL).unwrap();
        let imported = build_identity(import(&identity), MODEL).unwrap();
        assert_eq!(
            imported.certificate_chain().unwrap(),
            identity.certificate_chain().unwrap()
        );
        identity.certificate_chain_der.swap(0, 1);
        assert!(identity.validate(MODEL).is_err());
        identity.certificate_chain_der.swap(0, 1);
        let wrong_key = rcgen::KeyPair::generate().unwrap();
        let mut wrong = CertificateParams::default();
        wrong.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        wrong
            .distinguished_name
            .push(DnType::CommonName, "Synthetic root");
        identity.certificate_chain_der[1] =
            STANDARD.encode(wrong.self_signed(&wrong_key).unwrap().der());
        assert!(identity.validate(MODEL).is_err());
    }
}
