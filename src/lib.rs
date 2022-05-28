use chrono::prelude::DateTime;
use chrono::Utc;
use num_bigint::*;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use std::time::{Duration, UNIX_EPOCH};

use webpki::*;
type BaseType = Vec<u8>;

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
    attestation: PageSignerAttestation,
    cert_root: Vec<pem::Pem>,
}

impl PageSignerVerificationContext {
    pub fn new(attestation: PageSignerAttestation, cert_root: Vec<pem::Pem>) -> Self {
        Self {
            attestation,
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
        base64::decode(base64.as_bytes()).map_err(|e| serde::de::Error::custom(e))
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

type VerificationResult<'a> = Result<&'a PageSignerVerificationContext, String>;
fn verifyNotary(ctx: &PageSignerVerificationContext) -> VerificationResult {
    todo!();
}

fn verifySessionSignatures(ctx: &PageSignerVerificationContext) -> VerificationResult {
    todo!();
}

fn verifyHTTPHeaders(ctx: &PageSignerVerificationContext) -> VerificationResult {
    todo!();
}

fn verifyServerAuthTags(ctx: &PageSignerVerificationContext) -> VerificationResult {
    todo!();
}

const PG_SG_TITLE: &str = "PageSigner notarization file";
fn checkVersionAndTitle(ctx: &PageSignerVerificationContext) -> VerificationResult {
    if ctx.attestation.version != 6 {
        return Err("Version Should be 6".to_string());
    };
    if !ctx.attestation.title.eq(&PG_SG_TITLE.to_string()) {
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

fn verifyDatedCert(ctx: &PageSignerVerificationContext) -> VerificationResult {
    let date_bytes = ctx
        .attestation
        .notarization_time
        .as_slice()
        .try_into()
        .map(|x| u64::from_be_bytes(x))
        .map_err(|_| "Failed to retieve certification date")?;
    let d = UNIX_EPOCH + Duration::from_secs(date_bytes);
    // Create DateTime from SystemTime
    let datetime = DateTime::<Utc>::from(d);
    // Formats the combined date and time with the specified format string.
    let timestamp_str = datetime.format("%Y-%m-%d %H:%M:%S.%f").to_string();

    let cert = webpki::EndEntityCert::try_from(&ctx.attestation.certificates[0][..]).unwrap();
    let intermidiates = &ctx
        .attestation
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

fn verifyRSA(ctx: &PageSignerVerificationContext) -> VerificationResult {
    let mut msg = Vec::new();
    msg.extend_from_slice(&ctx.attestation.client_random[..]);
    msg.extend_from_slice(&ctx.attestation.server_random[..]);
    msg.extend_from_slice(&[0x03, 0x00, 0x17, 0x41]);
    msg.extend_from_slice(&ctx.attestation.server_pubkey_for_ecdhe);
    let cert: EndEntityCert =
        webpki::EndEntityCert::try_from(&ctx.attestation.certificates[0][..]).unwrap();
    cert.verify_signature(
        &RSA_PKCS1_2048_8192_SHA256,
        &msg,
        &ctx.attestation.server_rsa_sig,
    )
    .map_err(|e| e.to_string())?;
    Ok(ctx)
}

fn getExpandedKeys(
    pms: &[u8],
    cr: &Vec<u8>,
    sr: &Vec<u8>,
) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, ring::hmac::Key) {
    /*
            export async function getExpandedKeys(preMasterSecret, cr, sr){
          const Secret_CryptoKey = await crypto.subtle.importKey(
            'raw',
            preMasterSecret.buffer,
            {name: 'HMAC', hash:'SHA-256'},
            true,
            ['sign']);

          // calculate Master Secret and expanded keys
          const seed = concatTA(str2ba('master secret'), cr, sr);
          const a0 = seed;
          const a1 = new Uint8Array (await crypto.subtle.sign('HMAC', Secret_CryptoKey, a0.buffer));
          const a2 = new Uint8Array (await crypto.subtle.sign('HMAC', Secret_CryptoKey, a1.buffer));
          const p1 = new Uint8Array (await crypto.subtle.sign('HMAC', Secret_CryptoKey, concatTA(a1, seed).buffer));
          const p2 = new Uint8Array (await crypto.subtle.sign('HMAC', Secret_CryptoKey, concatTA(a2, seed).buffer));
          const ms = concatTA(p1, p2).slice(0, 48);
          const MS_CryptoKey = await crypto.subtle.importKey('raw', ms.buffer, {name: 'HMAC', hash:'SHA-256'}, true, ['sign']);

          // Expand keys
          const eseed = concatTA(str2ba('key expansion'), sr, cr);
          const ea0 = eseed;
          const ea1 = new Uint8Array (await crypto.subtle.sign('HMAC', MS_CryptoKey, ea0.buffer));
          const ea2 = new Uint8Array (await crypto.subtle.sign('HMAC', MS_CryptoKey, ea1.buffer));
          const ep1 = new Uint8Array (await crypto.subtle.sign('HMAC', MS_CryptoKey, concatTA(ea1, eseed).buffer));
          const ep2 = new Uint8Array (await crypto.subtle.sign('HMAC', MS_CryptoKey, concatTA(ea2, eseed).buffer));

          const ek = concatTA(ep1, ep2).slice(0, 40);
          // GCM doesnt need MAC keys
          const client_write_key = ek.slice(0, 16);
          const server_write_key = ek.slice(16, 32);
          const client_write_IV = ek.slice(32, 36);
          const server_write_IV = ek.slice(36, 40);
          return [client_write_key, server_write_key, client_write_IV, server_write_IV, MS_CryptoKey];
    }*/
    let secret_cryptokey = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, pms);
    // calculate Master Secret and expanded keys
    let mut seed = "master_secret".to_string().into_bytes();
    seed.extend_from_slice(&cr[..]);
    seed.extend_from_slice(&sr[..]);
    let a0 = seed.clone();
    let a1 = ring::hmac::sign(&secret_cryptokey, &a0);
    let a2 = ring::hmac::sign(&secret_cryptokey, a1.as_ref());
    let mut a1_seed = a1.as_ref().to_vec();
    a1_seed.extend_from_slice(&seed[..]);
    let mut a2_seed = a2.as_ref().to_vec();
    a2_seed.extend_from_slice(&seed[..]);
    let p1 = ring::hmac::sign(&secret_cryptokey, &a1_seed);
    let p2 = ring::hmac::sign(&secret_cryptokey, &a2_seed);
    let mut ms = p1.as_ref().to_vec();
    ms.extend_from_slice(p2.as_ref());
    let ms_cryptoKey = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &ms);

    // Expand keys
    let mut eseed = "key expansion".to_string().into_bytes();
    eseed.extend_from_slice(&cr[..]);
    eseed.extend_from_slice(&sr[..]);
    let ea0 = eseed;
    let ea1 = ring::hmac::sign(&ms_cryptoKey, &ea0);
    let ea2 = ring::hmac::sign(&ms_cryptoKey, &ea1.as_ref());
    let mut ea1_seed = ea1.as_ref().to_vec();
    ea1_seed.extend_from_slice(&seed[..]);
    let mut ea2_seed = ea2.as_ref().to_vec();
    ea2_seed.extend_from_slice(&seed[..]);
    let ep1 = ring::hmac::sign(&ms_cryptoKey, &ea1_seed);
    let ep2 = ring::hmac::sign(&ms_cryptoKey, &ea2_seed);

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
        ms_cryptoKey,
    )
}

fn verifyExpandedKeys(ctx: &PageSignerVerificationContext) -> VerificationResult {
    // // Step 4. Combine PMS shares and derive expanded keys.
    // const P256prime = 2n**256n - 2n**224n + 2n**192n + 2n**96n - 1n;
    // // we may need to reduce mod prime if the sum overflows the prime
    // const pms = int2ba((ba2int(obj['notary PMS share']) + ba2int(obj['client PMS share'])) % P256prime, 32);
    // const [cwk, swk, civ, siv] = await getExpandedKeys(pms, cr, sr);

    // // Step 5. Check that expanded keys match key shares
    // const clientCwkShare = obj['client client_write_key share'];
    // const clientCivShare = obj['client client_write_iv share'];
    // const clientSwkShare = obj['client server_write_key share'];
    // const clientSivShare = obj['client server_write_iv share'];
    // const notaryCwkShare = obj['notary client_write_key share'];
    // const notaryCivShare = obj['notary client_write_iv share'];
    // const notarySwkShare = obj['notary server_write_key share'];
    // const notarySivShare = obj['notary server_write_iv share'];
    // assert(eq( xor(notaryCwkShare, clientCwkShare), cwk));
    // assert(eq( xor(notaryCivShare, clientCivShare), civ));
    // assert(eq( xor(notarySwkShare, clientSwkShare), swk));
    // assert(eq( xor(notarySivShare, clientSivShare), siv));
    let p256prime = BigUint::new(vec![2]).pow(256) - BigUint::new(vec![2]).pow(224)
        + BigUint::new(vec![2]).pow(192)
        + BigUint::new(vec![2]).pow(96)
        - 1 as u32;
    let pms = (BigUint::from_bytes_be(&ctx.attestation.notary_pms_share[..])
        + BigUint::from_bytes_be(&ctx.attestation.client_pms_share[..]))
        % p256prime;

    let (cwk, swk, civ, siv, key) = getExpandedKeys(
        &pms.to_bytes_be(),
        &ctx.attestation.client_random,
        &ctx.attestation.server_random,
    );

    let v: Vec<_> = ctx
        .attestation
        .notary_client_write_key_share
        .iter()
        .zip(ctx.attestation.client_client_write_key_share.iter())
        .zip(cwk.iter())
        .map(|((&notary_share, &client_share), &key_share)| if notary_share ^ client_share == key_share {
	    Ok(ctx)} else {
	    println!("Exor failed");
	    Err("write key share verification failed")
	})
        .collect();
    Ok(ctx)
}

fn verify_pgsg_v6<'a>(ctx: &'a PageSignerVerificationContext) -> VerificationResult<'a> {
    checkVersionAndTitle(ctx)
        .and_then(verifyNotary)
        .and_then(verifyDatedCert)
        .and_then(verifyRSA)
        .and_then(verifyExpandedKeys)
        .and_then(verifySessionSignatures)
        .and_then(verifyHTTPHeaders)
        .and_then(verifyServerAuthTags)
}

pub fn simple_test(ctx: PageSignerVerificationContext) {
    verifyDatedCert(&ctx).unwrap();
    verifyRSA(&ctx).unwrap();
    verifyExpandedKeys(&ctx).unwrap();
    match verify_pgsg_v6(&ctx) {
        Ok(c) => {
            println!("Cert verified");
        }
        Err(e) => {
            println!("Cert failed {}", e);
        }
    }
}
