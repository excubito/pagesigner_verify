use serde_derive::Deserialize;
use serde_derive::Serialize;
use chrono::prelude::DateTime;
use chrono::Utc;
use std::time::{UNIX_EPOCH, Duration};

type BaseType = Vec<u8>;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PageSignerCertificate {
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



type VerificationResult<'a> = Result<&'a PageSignerCertificate, &'static str>;
#[macro_export]
macro_rules! cert_checkcond {
    (&$c:ident, $e: expr ,$error_msg:tt) => {
        if ($e) {
            Ok(($c))
        } else {
            Err($error_msg)
        }
    };
}

fn verifyNotary(cert: &PageSignerCertificate) -> VerificationResult {
    todo!();
}

fn verifyRSA(cert: &PageSignerCertificate) -> VerificationResult {
    todo!();
}

fn verifyExpandedKeys(cert: &PageSignerCertificate) -> VerificationResult {
    todo!();
}

fn verifySessionSignatures(cert: &PageSignerCertificate) -> VerificationResult {
    todo!();
}

fn verifyHTTPHeaders(cert: &PageSignerCertificate) -> VerificationResult {
    todo!();
}

fn verifyServerAuthTags(cert: &PageSignerCertificate) -> VerificationResult {
    todo!();
}

/*
fn veriyfyNotary(cert: &PageSignerCertificate) -> VerificationResult {
    todo!();
}*/

const PG_SG_TITLE: &str = "PageSigner notarization file";
fn checkVersionAndTitle(cert: &PageSignerCertificate) -> VerificationResult {
    if (cert.version != 6) {
        return Err("Version Should be 6");
    };
    if (!cert.title.eq(&PG_SG_TITLE.to_string())) {
        return Err("Certificate Title verification failed");
    };
    Ok(cert)
}

fn verifyDatedCert(cert: &PageSignerCertificate) -> VerificationResult {
    let date_bytes = 
        cert.notarization_time.as_slice()
            .try_into()
            .map(|x| u64::from_be_bytes(x))
            .map_err(|_| "Failed to retieve certification date")?;
    let d = UNIX_EPOCH + Duration::from_secs(date_bytes);
    // Create DateTime from SystemTime
    let datetime = DateTime::<Utc>::from(d);
    // Formats the combined date and time with the specified format string.
    let timestamp_str = datetime.format("%Y-%m-%d %H:%M:%S.%f").to_string();
    println!{"{}",timestamp_str};
    Ok(cert)
}

fn verify_pgsg_v6<'a>(cert: &'a PageSignerCertificate) -> VerificationResult<'a> {
    checkVersionAndTitle(cert)
        .and_then(verifyNotary)
        .and_then(verifyDatedCert)
        .and_then(verifyRSA)
        .and_then(verifyExpandedKeys)
        .and_then(verifySessionSignatures)
        .and_then(verifyHTTPHeaders)
        .and_then(verifyServerAuthTags)
}

pub fn simple_test(cert: &PageSignerCertificate) {
    verifyDatedCert(&cert);
    match verify_pgsg_v6(cert) {
        Ok(c) => {
            println!("Cert verified");
        }
        Err(e) => {
            println!("Cert failed {}", e);
        }
    }
}
