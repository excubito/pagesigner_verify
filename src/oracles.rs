use super::PageSignerVerificationContext;
use super::VerificationResult;
use crate::ReqResp;
use regex::Regex;
use std::collections::BTreeMap;
use sxd_xpath::function::Function;
use sxd_xpath::{evaluate_xpath, Value};

const ALLOWED_ACCESS_KEYS: &str = "AKIAI2NJVYXCCAQDCC5Q";
const AWS_ZONE_PREFIX: &str = "https://ec2.us-east-1.amazonaws.com/";
const AWS_IAM_ZONE_PREFIX: &str = "https://iam.amazonaws.com/";

macro_rules! xpathnonspath {
    ($pathfrg: expr) => {
        concat!("/*[name()='", $pathfrg, "']")
    };
    ($firstpathfrag: expr,  $($tail:tt)* ) => {
        concat!(xpathnonspath!($firstpathfrag), xpathnonspath!($($tail)*))
    }
}

macro_rules! ErrIfFail {
    ($expr:expr) => {{
        if $expr {
            Ok(())
        } else {
            Err(concat!("failed ", stringify!(errstr)))
        }
    }};
}

fn check_marked_id<'a>(
    req: &'a str,
    regex: &str,
    marker_anchor: &str,
    marker_len: usize,
) -> Result<&'a str, String> {
    let marker_re = Regex::new(regex).map_err(|e| e.to_string())?;
    let m = marker_re.find(req).ok_or("marker failed")?;
    let m = m.as_str();
    let m_len = m.len();
    let ma_len = marker_anchor.len();
    if m_len < ma_len + marker_len {
        Err("marker too short")
    } else {
        Ok(())
    }?;

    if marker_anchor == &m[m_len - (marker_len + ma_len)..m_len - marker_len] {
        Ok(&m[m_len - marker_len..])
    } else {
        Err(format!(
            "marker id should be of len {} {}",
            marker_len,
            &m[m_len - (marker_len + ma_len)..m_len]
        ))
    }
}

fn re_match(re: &String, txt: &String) -> Result<(), String> {
    // check urls for all requests
    let re = Regex::new(&re).map_err(|e| e.to_string())?;
    match re.is_match(&txt) {
        true => Ok(()),
        false => {
            println!("{}", re);
            println!("{}", txt);
            Err("Re mismatch".to_string())
        }
    }
}

fn xpath_get_child_len(
    document: &sxd_document::dom::Document,
    xpath: &str,
) -> Result<usize, String> {
    let value = evaluate_xpath(&document, xpath).map_err(|e| e.to_string())?;
    match &value {
        Value::Nodeset(n) => Ok(n.size()),
        _ => Err(format!("Malformed XPATH {}", xpath)),
    }
}

fn xpath_has_one_child(document: &sxd_document::dom::Document, xpath: &str) -> Result<(), String> {
    match { xpath_get_child_len(&document, xpath)? } {
        1 => Ok(()),
        n => Err(format!("{} Has {} child", xpath, n).to_string()),
    }
}

#[rustfmt::skip]
fn check_describe_instances(
    xml_doc: &str,
    instance_id: &str,
    image_id: &str,
    vol_id: &str,
) -> Result<(), String> {
    let package = sxd_document::parser::parse(xml_doc).map_err(|e| e.to_string())?;
    let doc = package.as_document();
    xpath_has_one_child(&doc, xpathnonspath!("DescribeInstancesResponse"))?;
    xpath_has_one_child(&doc,xpathnonspath!("DescribeInstancesResponse", "reservationSet"))?;

    let owner_id = evaluate_xpath(
	&doc,
	xpathnonspath!("DescribeInstancesResponse","reservationSet","item","ownerId"))
    .map_err(|e| e.to_string())?;

    xpath_has_one_child(
        &doc,
        xpathnonspath!("DescribeInstancesResponse", "reservationSet", "item")
    )?;

    xpath_has_one_child(
        &doc,
        xpathnonspath!(
            "DescribeInstancesResponse","reservationSet","item","instancesSet")
    )?;

    xpath_has_one_child(
        &doc,
        xpathnonspath!("DescribeInstancesResponse","reservationSet","item","instancesSet","item")
    )?;

    let state = evaluate_xpath(
        &doc,
        xpathnonspath!("DescribeInstancesResponse","reservationSet","item","instancesSet","item","instanceState","name")
    )
    .map_err(|e| e.to_string())?;

    ErrIfFail!((state.into_string()).eq("running"))?;


    Ok(())
}

use sxd_xpath::{context, function};
use sxd_xpath::{Context, Factory};

pub fn verify_notary(ctx: &PageSignerVerificationContext) -> VerificationResult {
    // find which URL corresponds to which API call
    let search_req_resp = |omarker: &str| -> Result<&ReqResp, &str> {
        let pos = ctx
            .sev_att
            .iter()
            .position(|x| x.request.contains(omarker) == true)
            .ok_or("SEV attestation marker absent")?;
        Ok(&ctx.sev_att[pos])
    };
    let mut markers: BTreeMap<&str, (&str, Option<&ReqResp>)> = [
        ("DI", ("DescribeInstances", None)),
        ("DV", ("DescribeVolumes", None)),
        ("GCO", ("GetConsoleOutput", None)),
        ("GU", ("GetUser", None)),
        ("DIAud", ("userData", None)),
        ("DIAk", ("kernel", None)),
        ("DIAr", ("ramdisk", None)),
        ("DImg", ("DescribeImage", None)),
    ]
    .into();

    for (_m, (s, anchor)) in markers.iter_mut() {
        let resp = search_req_resp(*s)?;
        anchor.replace(resp);
    }

    let access_key_re: &str = &format!("{}\\?AWSAccessKeyId=[A-Z0-9]{{20}}", AWS_ZONE_PREFIX);
    let access_key = check_marked_id(
        &markers["DI"].1.unwrap().request,
        access_key_re,
        "AWSAccessKeyId=",
        20,
    )?;

    // We only allow notarization from machine hosted by known AWS accounts
    if let ALLOWED_ACCESS_KEYS = access_key {
        Ok(())
    } else {
        Err("ACCESS_KEY mismatch")
    }?;

    // Check instance id
    let instance_re =
	&format!("^{}\\?AWSAccessKeyId={}&Action=DescribeInstances&Expires=2030-01-01&InstanceId=i-[a-f0-9]{{17}}", AWS_ZONE_PREFIX, ALLOWED_ACCESS_KEYS);
    let instance_id = check_marked_id(
        &markers["DI"].1.unwrap().request,
        &instance_re,
        "InstanceId=",
        19,
    )?;

    // Check volume id
    let vol_re=
	&format!("^{}\\?AWSAccessKeyId={}&Action=DescribeVolumes&Expires=2030-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&VolumeId=vol-[a-f0-9]{{17}}", AWS_ZONE_PREFIX, ALLOWED_ACCESS_KEYS);
    let vol_id = check_marked_id(&markers["DV"].1.unwrap().request, vol_re, "VolumeId=", 21)?;

    // Check amid id
    let ami_re=
	&format!("^{}\\?AWSAccessKeyId={}&Action=DescribeImages&Expires=2030-01-01&ImageId.1=ami-[a-f0-9]{{17}}", AWS_ZONE_PREFIX, ALLOWED_ACCESS_KEYS);
    let image_id = check_marked_id(
        &markers["DImg"].1.unwrap().request,
        ami_re,
        "ImageId.1=",
        21,
    )?;

    // check urls for all requests
    let re_str = format!("^{}\\?AWSAccessKeyId={}&Action=DescribeInstances&Expires=2030-01-01&InstanceId={}&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=[a-zA-Z0-9%]{{46,56}}$", AWS_ZONE_PREFIX, access_key, instance_id);
    re_match(&re_str, &markers["DI"].1.unwrap().request)?;

    let re_str = format!("^{}\\?AWSAccessKeyId={}&Action=DescribeVolumes&Expires=2030-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&VolumeId={}&Signature=[a-zA-Z0-9%]{{46,56}}$", AWS_ZONE_PREFIX, access_key, vol_id);
    re_match(&re_str, &markers["DV"].1.unwrap().request)?;

    let re_str = format!("^{}\\?AWSAccessKeyId={}&Action=GetConsoleOutput&Expires=2030-01-01&InstanceId={}&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=[a-zA-Z0-9%]{{46,56}}$", AWS_ZONE_PREFIX, access_key, instance_id);
    re_match(&re_str, &markers["GCO"].1.unwrap().request)?;

    let re_str = format!("^{}\\?AWSAccessKeyId={}&Action=GetUser&Expires=2030-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2010-05-08&Signature=[a-zA-Z0-9%]{{46,56}}$", AWS_IAM_ZONE_PREFIX, access_key);
    re_match(&re_str, &markers["GU"].1.unwrap().request)?;

    let re_str = format!("^{}\\?AWSAccessKeyId={}&Action=DescribeInstanceAttribute&Attribute=userData&Expires=2030-01-01&InstanceId={}&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=[a-zA-Z0-9%]{{46,56}}$", AWS_ZONE_PREFIX, access_key, instance_id);
    re_match(&re_str, &markers["DIAud"].1.unwrap().request)?;

    let re_str = format!("^{}\\?AWSAccessKeyId={}&Action=DescribeInstanceAttribute&Attribute=kernel&Expires=2030-01-01&InstanceId={}&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=[a-zA-Z0-9%]{{46,56}}$", AWS_ZONE_PREFIX, access_key, instance_id);
    re_match(&re_str, &markers["DIAk"].1.unwrap().request)?;

    let re_str = format!("^{}\\?AWSAccessKeyId={}&Action=DescribeInstanceAttribute&Attribute=ramdisk&Expires=2030-01-01&InstanceId={}&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=[a-zA-Z0-9%]{{46,56}}$", AWS_ZONE_PREFIX, access_key, instance_id);
    re_match(&re_str, &markers["DIAr"].1.unwrap().request)?;

    let re_str = format!("^{}\\?AWSAccessKeyId={}&Action=DescribeImages&Expires=2030-01-01&ImageId.1={}&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=[a-zA-Z0-9%]{{46,56}}$", AWS_ZONE_PREFIX, access_key, image_id);
    re_match(&re_str, &markers["DImg"].1.unwrap().request)?;

    check_describe_instances(
        &markers["DI"].1.unwrap().response,
        instance_id,
        image_id,
        vol_id,
    )?;

    Ok(ctx)
}
