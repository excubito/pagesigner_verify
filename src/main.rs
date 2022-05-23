use std::fs;
use serde_derive::Deserialize;
use serde_derive::Serialize;
type BaseType = Vec<u8>;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Root {
    #[serde(with="base64_vec")]
    pub certificates: Vec<BaseType>,
    #[serde(with="base64", rename = "notarization time")]
    pub notarization_time: BaseType,
    #[serde(with="base64", rename = "server RSA sig")]
    pub server_rsa_sig: BaseType,
    #[serde(with="base64", rename = "server pubkey for ECDHE")]
    pub server_pubkey_for_ecdhe: BaseType,
    #[serde(with="base64", rename = "notary PMS share")]
    pub notary_pms_share: BaseType,
    #[serde(with="base64", rename = "client PMS share")]
    pub client_pms_share: BaseType,
    #[serde(with="base64", rename = "client random")]
    pub client_random: BaseType,
    #[serde(with="base64", rename = "server random")]
    pub server_random: BaseType,
    #[serde(with="base64", rename = "notary client_write_key share")]
    pub notary_client_write_key_share: BaseType,
    #[serde(with="base64", rename = "notary client_write_iv share")]
    pub notary_client_write_iv_share: BaseType,
    #[serde(with="base64", rename = "notary server_write_key share")]
    pub notary_server_write_key_share: BaseType,
    #[serde(with="base64", rename = "notary server_write_iv share")]
    pub notary_server_write_iv_share: BaseType,
    #[serde(with="base64", rename = "client client_write_key share")]
    pub client_client_write_key_share: BaseType,
    #[serde(with="base64", rename = "client client_write_iv share")]
    pub client_client_write_iv_share: BaseType,
    #[serde(with="base64", rename = "client server_write_key share")]
    pub client_server_write_key_share: BaseType,
    #[serde(with="base64", rename = "client server_write_iv share")]
    pub client_server_write_iv_share: BaseType,
    #[serde(with="base64", rename = "client request ciphertext")]
    pub client_request_ciphertext: BaseType,
    #[serde(with="base64_vec", rename = "server response records")]
    pub server_response_records: Vec<BaseType>,
    #[serde(with="base64", rename = "session signature")]
    pub session_signature: BaseType,
    #[serde(with="base64", rename = "ephemeral pubkey")]
    pub ephemeral_pubkey: BaseType,
    #[serde(with="base64", rename = "ephemeral valid from")]
    pub ephemeral_valid_from: BaseType,
    #[serde(with="base64", rename = "ephemeral valid until")]
    pub ephemeral_valid_until: BaseType,
    #[serde(with="base64", rename = "ephemeral signed by master key")]
    pub ephemeral_signed_by_master_key: BaseType,
    #[serde(with="base64", rename = "URLFetcher attestation")]
    pub urlfetcher_attestation: BaseType,
    pub title: String,
    pub version: i64,
}


mod base64 {
    use serde::{Serialize, Deserialize};
    use serde::{Deserializer, Serializer};
    use base64;

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        let base64 = base64::encode(v);
        String::serialize(&base64, s)
    }
    
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let base64 = String::deserialize(d)?;
        base64::decode(base64.as_bytes())
            .map_err(|e| serde::de::Error::custom(e))
    }
}

mod base64_vec {
    use std::marker::PhantomData;
    use serde::ser::SerializeSeq;
    use serde::{Serialize, Deserialize};
    use serde::{Deserializer, Serializer};
    use serde::de;
    use base64;

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
            where E: de::Error
            {

                let ret = base64::decode(base64.as_bytes())
                    .map_err(|e| serde::de::Error::custom(e))?;
                Ok(vec![ret])
            }
            fn visit_seq<S>(self, mut visitor: S) -> Result<Self::Value, S::Error>
                where S: serde::de::SeqAccess<'de>
            {
                
                let mut vec = Vec::new();
                while let Some(t) = visitor.next_element::<String>()? {
                    let k = base64::decode(t)
                        .map_err(|e| de::Error::custom(e))?;
                    vec.push(k);
                }
                Ok(vec)       
            }
        }
        d.deserialize_any(StringOrVec(PhantomData))
    }
}


fn read_pgsg(filepath: &str) -> Vec<u8> {
    fs::read(filepath).expect("file should open read only")
}

fn get_attestation(cert: &[u8]) -> Root {
   serde_json::from_slice(cert).expect("malformed json")
}

fn get_untyped_attestation(cert: &[u8]) -> serde_json::Value {
    serde_json::from_slice(cert).expect("malformed json")
}

fn main() {
    let b = read_pgsg("/home/faraz/pagesigner_verify/cert.pgsg");
    //println!("{:?}", get_untyped_attestation(b.as_slice()));
    //println!("{:#?}", get_attestation(b.as_slice()));
    //let value  =  get_cert(b.as_slice());
    //println!("{:?}", value);
}
