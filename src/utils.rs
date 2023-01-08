use crate::SecEnclaveAttestationCtx;
use cose::algs;
use cose::keys;
use cose::sign;
use pem::Pem;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use std::collections::BTreeMap;

/*
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AttestationDocument {
    pub pcrs: Pcrs,
    pub nonce: serde_cbor::value::Value, // This field cbor was NULL, so it could be typed
    pub digest: String,
    //#[serde(with = "serde_bytes")]     // ca bundle was vec<vec<u8>> which trips serde_bytes
    pub cabundle: serde_cbor::value::Value,
    #[serde(rename = "module_id")]
    pub module_id: String,
    pub timestamp: i64,
    #[serde(with = "serde_bytes")]
    #[serde(rename = "user_data")]
    pub user_data: Vec<u8>,
    #[serde(rename = "public_key")] // This field cbor was NULL, so it could be typed
    pub public_key: serde_cbor::value::Value,
    #[serde(with = "serde_bytes")]
    pub certificate: Vec<u8>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Pcrs {
    #[serde(with = "serde_bytes")]
    #[serde(rename = "0")]
    pub n0: Vec<u8>,
    #[serde(with = "serde_bytes")]
    #[serde(rename = "1")]
    pub n1: Vec<u8>,
    #[serde(with = "serde_bytes")]
    #[serde(rename = "2")]
    pub n2: Vec<u8>,
    #[serde(with = "serde_bytes")]
    #[serde(rename = "3")]
    pub n3: Vec<u8>,
    #[serde(with = "serde_bytes")]
    #[serde(rename = "4")]
    pub n4: Vec<u8>,
    #[serde(rename = "5")]
    #[serde(with = "serde_bytes")]
    pub n5: Vec<u8>,
    #[serde(with = "serde_bytes")]
    #[serde(rename = "6")]
    pub n6: Vec<u8>,
    #[serde(with = "serde_bytes")]
    #[serde(rename = "7")]
    pub n7: Vec<u8>,
    #[serde(with = "serde_bytes")]
    #[serde(rename = "8")]
    pub n8: Vec<u8>,
    #[serde(with = "serde_bytes")]
    #[serde(rename = "9")]
    pub n9: Vec<u8>,
    #[serde(with = "serde_bytes")]
    #[serde(rename = "10")]
    pub n10: Vec<u8>,
    #[serde(with = "serde_bytes")]
    #[serde(rename = "11")]
    pub n11: Vec<u8>,
    #[serde(with = "serde_bytes")]
    #[serde(rename = "12")]
    pub n12: Vec<u8>,
    #[serde(with = "serde_bytes")]
    #[serde(rename = "13")]
    pub n13: Vec<u8>,
    #[serde(with = "serde_bytes")]
    #[serde(rename = "14")]
    pub n14: Vec<u8>,
    #[serde(with = "serde_bytes")]
    #[serde(rename = "15")]
    pub n15: Vec<u8>,
}
 */

pub struct AttestationDocument {
    pub module_id: String,
    pub timestamp: u64,
    pub digest: String,
    pub pcrs: Vec<Vec<u8>>,
    pub certificate: Vec<u8>,
    pub cabundle: Vec<Vec<u8>>,
    pub public_key: Option<Vec<u8>>,
    pub user_data: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
}

/*
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

*/

impl AttestationDocument {
    pub fn authenticate(document: &[u8], cert_root: &Vec<Pem>) -> Result<Self, String> {
        // Following the steps here: https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
        // Step 1. Decode the CBOR object and map it to a COSE_Sign1 structure
        let (_protected, payload, _signature) = AttestationDocument::parse(document)
            .map_err(|err| format!("AttestationDocument::authenticate parse failed:{:?}", err))?;
        // Step 2. Exract the attestation document from the COSE_Sign1 structure
        let document = AttestationDocument::parse_payload(&payload)
            .map_err(|err| format!("AttestationDocument::authenticate failed:{:?}", err))?;
        ///////
        // Step 1. Verify the certificate's chain
        let mut errors = 0;
        let trust_anchors = cert_root
            .iter()
            .map(|x| webpki::TrustAnchor::try_from_cert_der(&x.contents[..]))
            .filter_map(|res| res.map_err(|e| errors += 1).ok())
            .collect::<Vec<_>>();

        let trust_anchors = webpki::TlsServerTrustAnchors(&trust_anchors);

        let intermidiates = document
            .cabundle
            .iter()
            .map(|x| pem::parse(&x))
            .filter_map(|r| r.map_err(|e| errors += 1).ok())
            .collect::<Vec<_>>();
        if errors > 0 {
            Err("CA bundle parsing error")
        } else {
            Ok(())
        }?;

        /////
        /*
            // Step 1. Verify the certificate's chain
            let mut certs: Vec<rustls::Certificate> = Vec::new();
            for this_cert in document.cabundle.clone().iter().rev() {
                let cert = rustls::Certificate(this_cert.to_vec());
                certs.push(cert);
            }
            let cert = rustls::Certificate(document.certificate.clone());
            certs.push(cert);

            let mut root_store = rustls::RootCertStore::empty();
            root_store
                .add(&rustls::Certificate(trusted_root_cert.to_vec()))
                .map_err(|err| {
                    format!(
                        "AttestationDocument::authenticate failed to add trusted root cert:{:?}",
                        err
                    )
                })?;

            let verifier = rustls::server::AllowAnyAuthenticatedClient::new(root_store);
            let _verified = verifier
                .verify_client_cert(
                    &rustls::Certificate(document.certificate.clone()),
                    &certs,
                    std::time::SystemTime::now(),
                )
                .map_err(|err| {
                    format!(
                        "AttestationDocument::authenticate verify_client_cert failed:{:?}",
                        err
                    )
                })?;
            // if verify_client_cert didn't generate an error, authentication passed

            // Step 2. Ensure the attestation document is properly signed
            let authenticated = {
                let sig_structure = aws_nitro_enclaves_cose::sign::COSESign1::from_bytes(document_data)
                        .map_err(|err| {
                            format!("AttestationDocument::authenticate failed to load document_data as COSESign1 structure:{:?}", err)
                        })?;
                let cert = openssl::x509::X509::from_der(&document.certificate)
                        .map_err(|err| {
                            format!("AttestationDocument::authenticate failed to parse document.certificate as X509 certificate:{:?}", err)
                        })?;
                let public_key = cert.public_key()
                        .map_err(|err| {
                            format!("AttestationDocument::authenticate failed to extract public key from certificate:{:?}", err)
                        })?;
                let pub_ec_key = public_key.ec_key().map_err(|err| {
                    format!(
                        "AttestationDocument::authenticate failed to get ec_key from public_key:{:?}",
                        err
                    )
                })?;
                let result = sig_structure.verify_signature(&pub_ec_key)
                        .map_err(|err| {
                            format!("AttestationDocument::authenticate failed to verify signature on sig_structure:{:?}", err)
                        })?;
                result
            };
            if !authenticated {
                return Err(format!(
                    "AttestationDocument::authenticate invalid COSE certificate for provided key"
                ));
            } else {
                return Ok(document);
        }*/

        Ok(document)
    }

    fn parse(document_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
        let elts: serde_cbor::Value =
            serde_cbor::from_slice(document_data).map_err(|e| e.to_string())?;
        let elts = match elts {
            serde_cbor::Value::Array(elts) => Ok(elts),
            _ => Err("AttestationDocument parse error"),
        }?;
        // Parse byte arrays out [ Protected, Skip Unprotected, Payload, Signature ]
        let elts: Vec<_> = elts
            .into_iter()
            .enumerate()
            .filter_map(|(i, e)| if i != 1 { Some(e) } else { None })
            .filter_map(|e| match e {
                serde_cbor::Value::Bytes(bytes) => Some(bytes),
                _ => None,
            })
            .collect();
        Ok((elts[0].to_vec(), elts[1].to_vec(), elts[2].to_vec()))
    }

    fn parse_payload(payload: &Vec<u8>) -> Result<AttestationDocument, String> {
        let document_data: serde_cbor::Value = serde_cbor::from_slice(payload.as_slice())
            .map_err(|err| format!("document parse failed:{:?}", err))?;

        let document_map: BTreeMap<serde_cbor::Value, serde_cbor::Value> = match document_data {
            serde_cbor::Value::Map(map) => Ok(map),
            _ => Err("AttestationDocument::parse_payload"),
        }?;

        let module_id: String =
            match document_map.get(&serde_cbor::Value::Text("module_id".to_string())) {
                Some(serde_cbor::Value::Text(val)) => Ok(val.to_string()),
                _ => Err("AttestationDocument::parse_payload module_id"),
            }?;

        let timestamp: i128 =
            match document_map.get(&serde_cbor::Value::Text("timestamp".to_string())) {
                Some(serde_cbor::Value::Integer(val)) => Ok(*val),
                _ => Err("AttestationDocument::parse_payload time stamp"),
            }?;

        let timestamp: u64 = timestamp.try_into().map_err(|err| {
            format!(
                "AttestationDocument::parse_payload failed to convert timestamp to u64:{:?}",
                err
            )
        })?;

        let public_key: Option<Vec<u8>> =
            match document_map.get(&serde_cbor::Value::Text("public_key".to_string())) {
                Some(serde_cbor::Value::Bytes(val)) => Some(val.to_vec()),
                Some(_) => None,
                None => None,
            };

        let certificate: Vec<u8> =
            match document_map.get(&serde_cbor::Value::Text("certificate".to_string())) {
                Some(serde_cbor::Value::Bytes(val)) => Ok(val.to_vec()),
                _ => Err("AttestationDocument::parse_payload certificate"),
            }?;

        // get pcrs
        let pcrs_map = match document_map.get(&serde_cbor::Value::Text("pcrs".to_string())) {
            Some(serde_cbor::Value::Map(map)) => Ok(map),
            _ => Err("AttestationDocument::parse_payload pcrs"),
        }?;
        let num_entries = pcrs_map.len();
        let mut errors: u32 = 0;
        let pcrs: Vec<_> = { 0..num_entries }
            .into_iter()
            .map(|i| pcrs_map.get(&serde_cbor::Value::Integer(i as i128)))
            .filter_map(|pcrs| match pcrs {
                Some(serde_cbor::Value::Bytes(inner_vec)) => Some(inner_vec.to_vec()),
                _ => {
                    errors += 1;
                    None
                }
            })
            .collect();
        if errors != 0 {
            Err("AttestationDocument::parse_payload PCRS")
        } else {
            Ok(())
        }?;

        let nonce: Option<Vec<u8>> =
            match document_map.get(&serde_cbor::Value::Text("nonce".to_string())) {
                Some(serde_cbor::Value::Bytes(val)) => Some(val.to_vec()),
                _ => None,
            };

        let user_data: Option<Vec<u8>> =
            match document_map.get(&serde_cbor::Value::Text("user_data".to_string())) {
                Some(serde_cbor::Value::Bytes(val)) => Some(val.to_vec()),
                _ => None,
            };

        let digest: String = match document_map.get(&serde_cbor::Value::Text("digest".to_string()))
        {
            Some(serde_cbor::Value::Text(val)) => Ok(val.to_string()),
            _ => Err("AttestationDocument::parse_payload digest"),
        }?;

        // get cabundle
        let cabundle_array =
            match document_map.get(&serde_cbor::Value::Text("cabundle".to_string())) {
                Some(serde_cbor::Value::Array(outer_vec)) => Ok(outer_vec),
                _ => Err("AttestationDocument::parse_payload cabundle 2"),
            }?;
        let mut errors: u32 = 0;
        let cabundle: Vec<_> = cabundle_array
            .iter()
            .filter_map(|cabundle| match cabundle {
                serde_cbor::Value::Bytes(inner_vec) => Some(inner_vec.to_vec()),
                _ => {
                    errors += 1;
                    None
                }
            })
            .collect();
        if errors != 0 {
            Err("AttestationDocument::parse_payload CABUNDLE")
        } else {
            Ok(())
        }?;
        Ok(AttestationDocument {
            module_id,
            timestamp,
            digest,
            pcrs,
            certificate,
            cabundle,
            public_key,
            user_data,
            nonce,
        })
    }
}

pub fn verify_nitro_attestation_doc(
    att_ctx: &SecEnclaveAttestationCtx,
    cert_root: &Vec<Pem>,
) -> Result<(), String> {
    let attestation_doc = AttestationDocument::authenticate(&att_ctx.attestation, cert_root)?;
    /*

        //    println!("{:?}", &att_ctx.attestation);
        let docRoot: AttestationDocRoot =
            serde_cbor::from_slice(&att_ctx.attestation).map_err(|e| e.to_string())?;
        if docRoot.len() >= 4 {
            Ok(())
        } else {
            Err("Failed to decode attestation doc")
        }?;
        let payload = match &docRoot[2] {
            serde_cbor::Value::Bytes(t) => Ok((t)),
            _ => Err("Failed to decode attestation doc2"),
        }?;

        let payload: AttestationPayloadRoot =
            serde_cbor::from_slice(payload).map_err(|e| e.to_string())?;
        let cert = x509_certificate::X509Certificate::from_ber(payload.certificate)
            .map_err(|e| e.to_string())?;
        let public_key = cert.public_key_data();
        let mut key = keys::CoseKey::new();
        key.k
        println!("{:?}", cert);
    */
    Ok(())
}
