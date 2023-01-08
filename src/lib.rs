use num_bigint::*;
use pem::Pem;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use webpki::*;
mod oracles;
mod utils;
type BaseType = Vec<u8>;

pub type SecEnclaveURLS = Vec<ReqResp>;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReqResp {
    pub request: String,
    pub response: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PageSignerAttestation {
    #[serde(with = "base64_vec")]
    pub certificates: Vec<BaseType>,
    #[serde(with = "base64", rename = "notarization time")]
    pub notarization_time: BaseType,
    #[serde(with = "base64", rename = "server RSA sig")]
    pub server_rsa_sig: BaseType,
    #[serde(with = "base64", rename = "server pubkey for ECDHE")]
    pub server_pubkey_for_ecdhe: BaseType,
    #[serde(with = "base64", rename = "notary PMS share")]
    pub notary_pms_share: BaseType,
    #[serde(with = "base64", rename = "client PMS share")]
    pub client_pms_share: BaseType,
    #[serde(with = "base64", rename = "client random")]
    pub client_random: BaseType,
    #[serde(with = "base64", rename = "server random")]
    pub server_random: BaseType,
    #[serde(with = "base64", rename = "notary client_write_key share")]
    pub notary_client_write_key_share: BaseType,
    #[serde(with = "base64", rename = "notary client_write_iv share")]
    pub notary_client_write_iv_share: BaseType,
    #[serde(with = "base64", rename = "notary server_write_key share")]
    pub notary_server_write_key_share: BaseType,
    #[serde(with = "base64", rename = "notary server_write_iv share")]
    pub notary_server_write_iv_share: BaseType,
    #[serde(with = "base64", rename = "client client_write_key share")]
    pub client_client_write_key_share: BaseType,
    #[serde(with = "base64", rename = "client client_write_iv share")]
    pub client_client_write_iv_share: BaseType,
    #[serde(with = "base64", rename = "client server_write_key share")]
    pub client_server_write_key_share: BaseType,
    #[serde(with = "base64", rename = "client server_write_iv share")]
    pub client_server_write_iv_share: BaseType,
    #[serde(with = "base64", rename = "client request ciphertext")]
    pub client_request_ciphertext: BaseType,
    #[serde(with = "base64_vec", rename = "server response records")]
    pub server_response_records: Vec<BaseType>,
    #[serde(with = "base64", rename = "session signature")]
    pub session_signature: BaseType,
    #[serde(with = "base64", rename = "ephemeral pubkey")]
    pub ephemeral_pubkey: BaseType,
    #[serde(with = "base64", rename = "ephemeral valid from")]
    pub ephemeral_valid_from: BaseType,
    #[serde(with = "base64", rename = "ephemeral valid until")]
    pub ephemeral_valid_until: BaseType,
    #[serde(with = "base64", rename = "ephemeral signed by master key")]
    pub ephemeral_signed_by_master_key: BaseType,
    #[serde(with = "base64", rename = "URLFetcher attestation")]
    pub urlfetcher_attestation: BaseType,
    pub title: String,
    pub version: i64,
}

pub struct PageSignerVerificationContext {
    att: PageSignerAttestation,
    sev_ctx: SecEnclaveAttestationCtx,
    cert_root: Vec<Pem>,
}

pub struct SecEnclaveAttestationCtx {
    sev_att: SecEnclaveURLS,
    attestation: Vec<u8>,
}

impl SecEnclaveAttestationCtx {
    pub fn new(sev_att: SecEnclaveURLS, attestation: Vec<u8>) -> Self {
        Self {
            sev_att,
            attestation,
        }
    }
}

impl PageSignerVerificationContext {
    pub fn new(
        att: PageSignerAttestation,
        sev_ctx: SecEnclaveAttestationCtx,
        cert_root: Vec<pem::Pem>,
    ) -> Self {
        Self {
            att,
            sev_ctx,
            cert_root,
        }
    }
}

mod base64 {
    use base64;
    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        let base64 = base64::encode(v);
        String::serialize(&base64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let base64 = String::deserialize(d)?;
        base64::decode_config(base64.as_bytes(), base64::STANDARD_NO_PAD)
            .map_err(|e| serde::de::Error::custom(e))
    }
}

mod base64_vec {
    use base64;
    use serde::de;
    use serde::ser::SerializeSeq;
    use serde::{Deserializer, Serializer};
    use std::marker::PhantomData;

    pub fn serialize<S: Serializer>(v: &Vec<super::BaseType>, s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for u in v {
            let base64 = base64::encode(u);
            seq.serialize_element(&base64)?;
        }
        seq.end()
    }

    /* Simpler but takes more memory */
    /*
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<super::BaseType>, D::Error> {
        let s: Vec<String> = Deserialize::deserialize(d)?;
        let mut v = Vec::new();
        for x in s {
            let m = base64::decode(x.as_bytes())
            .map_err(|e| serde::de::Error::custom(e))?;
            v.push(m);
        }
        Ok(v)
    }*/

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<super::BaseType>, D::Error> {
        struct StringOrVec(PhantomData<Vec<super::BaseType>>);
        impl<'de> de::Visitor<'de> for StringOrVec {
            type Value = Vec<super::BaseType>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("strings or list of strings")
            }

            fn visit_str<E>(self, base64: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let ret =
                    base64::decode(base64.as_bytes()).map_err(|e| serde::de::Error::custom(e))?;
                Ok(vec![ret])
            }
            fn visit_seq<S>(self, mut visitor: S) -> Result<Self::Value, S::Error>
            where
                S: serde::de::SeqAccess<'de>,
            {
                let mut vec = Vec::new();
                while let Some(t) = visitor.next_element::<String>()? {
                    let k = base64::decode(t).map_err(|e| de::Error::custom(e))?;
                    vec.push(k);
                }
                Ok(vec)
            }
        }
        d.deserialize_any(StringOrVec(PhantomData))
    }
}

pub type VerificationResult<'a> = Result<&'a PageSignerVerificationContext, String>;

const PG_SG_TITLE: &str = "PageSigner notarization file";
fn check_version_and_title(ctx: &PageSignerVerificationContext) -> VerificationResult {
    if ctx.att.version != 6 {
        return Err("Version Should be 6".to_string());
    };
    if !ctx.att.title.eq(&PG_SG_TITLE.to_string()) {
        return Err("Certificate Title verification failed".to_string());
    };
    Ok(ctx)
}

static ALL_SIGALGS: &[&webpki::SignatureAlgorithm] = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::ED25519,
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::RSA_PKCS1_3072_8192_SHA384,
];

fn verify_dated_cert(ctx: &PageSignerVerificationContext) -> VerificationResult {
    let date_bytes = ctx
        .att
        .notarization_time
        .as_slice()
        .try_into()
        .map(|x| u64::from_be_bytes(x))
        .map_err(|_| "Failed to retieve certification date")?;
    let cert = webpki::EndEntityCert::try_from(&ctx.att.certificates[0][..]).unwrap();
    let intermidiates = &ctx
        .att
        .certificates
        .iter()
        .skip(1)
        .rev()
        .skip(1)
        .rev()
        .map(|x| &x[..])
        .collect::<Vec<_>>()[..];

    let trust_anchors = ctx
        .cert_root
        .iter()
        .map(|x| webpki::TrustAnchor::try_from_cert_der(&x.contents[..]).unwrap())
        .collect::<Vec<_>>();

    let trust_anchors = webpki::TlsServerTrustAnchors(&trust_anchors);

    match cert.verify_is_valid_tls_server_cert(
        &ALL_SIGALGS,
        &trust_anchors,
        &intermidiates,
        webpki::Time::from_seconds_since_unix_epoch(date_bytes),
    ) {
        Ok(_) => Ok(ctx),
        Err(e) => VerificationResult::Err(e.to_string()),
    }
}

fn verify_rsa(ctx: &PageSignerVerificationContext) -> VerificationResult {
    let mut msg = Vec::new();
    msg.extend_from_slice(&ctx.att.client_random[..]);
    msg.extend_from_slice(&ctx.att.server_random[..]);
    msg.extend_from_slice(&[0x03, 0x00, 0x17, 0x41]);
    msg.extend_from_slice(&ctx.att.server_pubkey_for_ecdhe);
    let cert: EndEntityCert =
        webpki::EndEntityCert::try_from(&ctx.att.certificates[0][..]).unwrap();
    cert.verify_signature(&RSA_PKCS1_2048_8192_SHA256, &msg, &ctx.att.server_rsa_sig)
        .map_err(|e| e.to_string())?;
    Ok(ctx)
}

fn get_expanded_keys(
    pms: &[u8],
    cr: &Vec<u8>,
    sr: &Vec<u8>,
) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, ring::hmac::Key) {
    let secret_cryptokey = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &pms[..]);
    // calculate Master Secret and expanded keys
    let mut seed = "master secret".to_string().into_bytes();
    seed.extend_from_slice(&cr[..]);
    seed.extend_from_slice(&sr[..]);
    let a0 = seed.clone();
    let a1 = ring::hmac::sign(&secret_cryptokey, &a0[..]);
    let a2 = ring::hmac::sign(&secret_cryptokey, a1.as_ref());
    let mut a1_seed = a1.as_ref().to_vec();
    a1_seed.extend_from_slice(&seed[..]);
    let mut a2_seed = a2.as_ref().to_vec();
    a2_seed.extend_from_slice(&seed[..]);
    let p1 = ring::hmac::sign(&secret_cryptokey, &a1_seed);
    let p2 = ring::hmac::sign(&secret_cryptokey, &a2_seed);
    let mut ms = p1.as_ref().to_vec();
    ms.extend_from_slice(p2.as_ref());
    let ms = &ms[0..48];
    let ms_crypto_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &ms);

    // Expand keys
    let mut eseed = "key expansion".to_string().into_bytes();
    eseed.extend_from_slice(&sr[..]);
    eseed.extend_from_slice(&cr[..]);
    let ea0 = eseed.clone();
    let ea1 = ring::hmac::sign(&ms_crypto_key, &ea0);
    let ea2 = ring::hmac::sign(&ms_crypto_key, &ea1.as_ref());
    let mut ea1_seed = ea1.as_ref().to_vec();
    ea1_seed.extend_from_slice(&eseed[..]);
    let mut ea2_seed = ea2.as_ref().to_vec();
    ea2_seed.extend_from_slice(&eseed[..]);
    let ep1 = ring::hmac::sign(&ms_crypto_key, &ea1_seed);
    let ep2 = ring::hmac::sign(&ms_crypto_key, &ea2_seed);

    let mut ep1 = ep1.as_ref().to_vec();
    ep1.extend_from_slice(ep2.as_ref());
    let ek = &ep1[0..40];
    let client_write_key = ek[0..16].to_vec();
    let server_write_key = ek[16..32].to_vec();
    let client_write_iv = ek[32..36].to_vec();
    let servcer_write_iv = ek[36..40].to_vec();
    (
        client_write_key,
        server_write_key,
        client_write_iv,
        servcer_write_iv,
        ms_crypto_key,
    )
}

fn verify_expanded_keys(ctx: &PageSignerVerificationContext) -> VerificationResult {
    // v1 Exor v2 = v3
    let three_xor_arr = |v1: &Vec<u8>, v2: &Vec<u8>, v3: &Vec<u8>| -> VerificationResult {
        let v: Result<Vec<_>, _> = v1
            .iter()
            .zip(v2.iter())
            .zip(v3.iter())
            .map(|((&notary_share, &client_share), &key_share)| {
                if notary_share ^ client_share == key_share {
                    Ok(())
                } else {
                    Err("write key share verification failed")
                }
            })
            .collect();
        match v {
            Ok(_) => Ok(ctx),
            Err(e) => Err(e.to_string()),
        }
    };

    let p256prime = BigUint::new(vec![2]).pow(256) - BigUint::new(vec![2]).pow(224)
        + BigUint::new(vec![2]).pow(192)
        + BigUint::new(vec![2]).pow(96)
        - 1 as u32;
    let pms = (BigUint::from_bytes_be(&ctx.att.notary_pms_share[..])
        + BigUint::from_bytes_be(&ctx.att.client_pms_share[..]))
        % p256prime;

    let (cwk, swk, civ, siv, _key) = get_expanded_keys(
        &pms.to_bytes_be(),
        &ctx.att.client_random,
        &ctx.att.server_random,
    );

    three_xor_arr(
        &ctx.att.notary_client_write_key_share,
        &ctx.att.client_client_write_key_share,
        &cwk,
    )?;
    three_xor_arr(
        &ctx.att.notary_client_write_iv_share,
        &ctx.att.client_client_write_iv_share,
        &civ,
    )?;

    three_xor_arr(
        &ctx.att.notary_server_write_key_share,
        &ctx.att.client_server_write_key_share,
        &swk,
    )?;

    three_xor_arr(
        &ctx.att.notary_server_write_iv_share,
        &ctx.att.client_server_write_iv_share,
        &siv,
    )?;

    Ok(ctx)
}

fn verify_session_signatures(ctx: &PageSignerVerificationContext) -> VerificationResult {
    let mut sha_ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.att
        .server_response_records
        .iter()
        .for_each(|v| sha_ctx.update(&v));
    let commithash = sha_ctx.finish();
    let keysharehash = {
        let mut sha_ctx = ring::digest::Context::new(&ring::digest::SHA256);
        sha_ctx.update(&ctx.att.client_client_write_key_share);
        sha_ctx.update(&ctx.att.client_client_write_iv_share);
        sha_ctx.update(&ctx.att.client_server_write_key_share);
        sha_ctx.update(&ctx.att.client_server_write_iv_share);
        sha_ctx.finish()
    };
    let pmssharehash = ring::digest::digest(&ring::digest::SHA256, &ctx.att.client_pms_share);
    let mut tb1 = Vec::from(commithash.as_ref());
    tb1.extend_from_slice(keysharehash.as_ref());
    tb1.extend_from_slice(pmssharehash.as_ref());
    tb1.extend_from_slice(&ctx.att.client_request_ciphertext);
    tb1.extend_from_slice(&ctx.att.server_pubkey_for_ecdhe);
    tb1.extend_from_slice(&ctx.att.notary_pms_share);
    tb1.extend_from_slice(&ctx.att.notary_client_write_key_share);
    tb1.extend_from_slice(&ctx.att.notary_client_write_iv_share);
    tb1.extend_from_slice(&ctx.att.notary_server_write_key_share);
    tb1.extend_from_slice(&ctx.att.notary_server_write_iv_share);
    tb1.extend_from_slice(&ctx.att.notarization_time);
    let pkey = ring::signature::UnparsedPublicKey::new(
        &ring::signature::ECDSA_P256_SHA256_FIXED,
        &ctx.att.ephemeral_pubkey,
    );
    match pkey.verify(&tb1, &ctx.att.session_signature) {
        Ok(_) => Ok(ctx),
        Err(e) => Err(e.to_string()),
    }
}

#[allow(dead_code)]
fn verify_http_headers(_ctx: &PageSignerVerificationContext) -> VerificationResult {
    todo!();
}

#[allow(dead_code)]
fn verify_server_authtags(_ctx: &PageSignerVerificationContext) -> VerificationResult {
    todo!();
}

fn verify_ephermeral_key(ctx: &PageSignerVerificationContext) -> VerificationResult {
    let mut tb1 = ctx.att.ephemeral_valid_from.clone();
    tb1.extend_from_slice(&ctx.att.ephemeral_valid_until);
    tb1.extend_from_slice(&ctx.att.ephemeral_pubkey);
    Ok(ctx)
}

fn verify_pgsg_v6<'a>(ctx: &'a PageSignerVerificationContext) -> VerificationResult<'a> {
    check_version_and_title(ctx)?;
    let (ctx, oracle_pubkey) = oracles::verify_notary(ctx)?;
    verify_dated_cert(ctx)
        .and_then(verify_rsa)
        .and_then(verify_expanded_keys)
        .and_then(verify_session_signatures)
        .and_then(verify_ephermeral_key)
        .and_then(verify_http_headers)
        .and_then(verify_server_authtags)
}

pub fn simple_test(ctx: PageSignerVerificationContext) {
    verify_dated_cert(&ctx).unwrap();
    verify_rsa(&ctx).unwrap();
    verify_expanded_keys(&ctx).unwrap();
    verify_session_signatures(&ctx).unwrap();
    verify_ephermeral_key(&ctx).unwrap();
    match verify_pgsg_v6(&ctx) {
        Ok(_c) => {
            println!("VERIFIED:");
        }
        Err(e) => {
            println!("FAILED: {}", e);
        }
    }
}
