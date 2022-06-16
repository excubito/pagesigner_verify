use pagesigner_verify::{
    PageSignerAttestation, PageSignerVerificationContext, SecEnclaveAttestationCtx, SecEnclaveURLS,
};
use pem::parse_many;
use pem::Pem;
use std::fs;

fn read_pgsg(filepath: &str) -> Vec<u8> {
    fs::read(filepath).expect("file should open read only")
}

fn get_attestation(cert_bytes: &[u8]) -> PageSignerAttestation {
    serde_json::from_slice(cert_bytes).expect("malformed json")
}

fn get_sev_attestation(att: &PageSignerAttestation) -> SecEnclaveAttestationCtx {
    let mut transcript_len: [u8; 4] = [0; 4];
    transcript_len.copy_from_slice(&att.urlfetcher_attestation[0..4]);
    let transcript_len = u32::from_be_bytes(transcript_len);
    let transcript = &att.urlfetcher_attestation[4..(4 + transcript_len) as usize];
    let attestation = &att.urlfetcher_attestation[(4 + transcript_len) as usize..];
    //println!("{}", String::from_utf8_lossy(&transcript));
    let sev_att_urls = serde_json::from_slice::<SecEnclaveURLS>(transcript)
        .expect("SEV attestation parsing failed");
    SecEnclaveAttestationCtx::new(sev_att_urls, attestation.into())
}

#[allow(dead_code)]
fn get_untyped_cert(cert: &[u8]) -> serde_json::Value {
    serde_json::from_slice(cert).expect("malformed json")
}

fn read_certroot(filepath: &str) -> Result<Vec<Pem>, String> {
    let certs = std::fs::read_to_string(filepath).expect("Cannot open cert root");
    let certs = parse_many(certs).map_err(|e| e.to_string());
    /*
    let pcerts = certs.clone().unwrap();
    println!("{:?}", pcerts.len());
    for pcert in pcerts {
        println!("{:?}", pcert.tag);
    } */
    certs
}

fn main() {
    let cert_root = read_certroot("/home/faraz/pagesigner_verify/certs.txt").unwrap();
    let cert_bytes = read_pgsg("/home/faraz/pagesigner_verify/cert.pgsg");
    let att = get_attestation(&cert_bytes);
    let sev_att = get_sev_attestation(&att);
    pagesigner_verify::simple_test(PageSignerVerificationContext::new(att, sev_att, cert_root));
}
