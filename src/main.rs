use pagesigner_verify::PageSignerAttestation;
use pagesigner_verify::PageSignerVerificationContext;
use pem::parse_many;
use pem::Pem;
use std::fs;

fn read_pgsg(filepath: &str) -> Vec<u8> {
    fs::read(filepath).expect("file should open read only")
}

fn get_attestation(cert_bytes: &[u8]) -> PageSignerAttestation {
    serde_json::from_slice(cert_bytes).expect("malformed json")
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
    let attestation = get_attestation(&cert_bytes);

    //print the client certificates from the attestation
    /*
        for x in attestation.clone().certificates {
            let p = pem::Pem {
                tag: "CERTIFICATE".to_string(),
                contents: x,
            };
            println!("{}", pem::encode(&p));
    }*/
    pagesigner_verify::simple_test(PageSignerVerificationContext::new(attestation, cert_root));
}
