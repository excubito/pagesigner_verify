use pagesigner_verify::PageSignerCertificate;
use std::fs;
use std::io::Read;

fn read_pgsg(filepath: &str) -> Vec<u8> {
    fs::read(filepath).expect("file should open read only")
}

fn get_cert(cert_bytes: &[u8]) -> PageSignerCertificate {
    serde_json::from_slice(cert_bytes).expect("malformed json")
}

#[allow(dead_code)]
fn get_untyped_cert(cert: &[u8]) -> serde_json::Value {
    serde_json::from_slice(cert).expect("malformed json")
}

fn main() {
    let cert_bytes = read_pgsg("/home/faraz/pagesigner_verify/cert.pgsg");
    let cert = get_cert(&cert_bytes);
    pagesigner_verify::simple_test(&cert);
}