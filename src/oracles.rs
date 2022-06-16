use super::PageSignerVerificationContext;
use crate::ReqResp;
use chrono::DateTime;
use chrono::FixedOffset;
use regex::Regex;
use std::collections::BTreeMap;
use sxd_document::dom::Document;
use sxd_xpath::{evaluate_xpath, Value};

const ALLOWED_ACCESS_KEYS: &str = "AKIAI2NJVYXCCAQDCC5Q";
const AWS_ZONE_PREFIX: &str = "https://ec2.us-east-1.amazonaws.com/";
const AWS_IAM_ZONE_PREFIX: &str = "https://iam.amazonaws.com/";

// rootsOfTrust contains an array of trusted EBS snapshots
// essentially the whole oracle verification procedure boils down to proving that an EC2 instance was
// launched from an AMI which was created from one of the "rootsOfTrust" snapshot ids.
type RootOfTrust = [&'static str; 6];
const ROOT_OF_TRUST: RootOfTrust = [
    "snap-0ccb00d0e0fb4d4da",
    "snap-07eda3ed4836f82fb",
    "snap-023d50ee97873a1f0",
    "snap-0e50af508006037dc",
    "snap-023dda76582a6b29f",
    "snap-027ade4f1002864da",
];

macro_rules! xpathnonspath {
    () => {};
    ($pathfrg: expr) => {
        concat!("/*[name()='", $pathfrg, "']")
    };
    ($firstpathfrag: expr,  $($tail:tt)* ) => {
        concat!(xpathnonspath!($firstpathfrag), xpathnonspath!($($tail)*))
    }
}

macro_rules! _xpathnonspath_prefix {
    ($prefix: expr,  $($tail:tt)* ) => {
        concat!(prefix, xpathnonspath!($($tail)*))
    }
}

macro_rules! checkexpr {
    ($expr:expr) => {{
        if $expr {
            Ok(())
        } else {
            Err(concat!("failed ", stringify!(errstr)))
        }
    }};
}

/*
macro_rules! warn_todo {
    () => {{
        println!(concat!(function_name!(), " Not implemented"));
        Err("Not Implemented".to_string())
    }};
}
*/

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
        false => Err("Re mismatch".to_string()),
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

fn xpath_equals(doc: &Document, xpath: &str, compare_to: &str) -> Result<(), String> {
    let xpath_val = evaluate_xpath(&doc, xpath)
        .map_err(|e| e.to_string())?
        .into_string();
    if xpath_val.as_str().eq(compare_to) {
        Ok(())
    } else {
        Err(format!("XPATH {} mismatch {} != {}", xpath, xpath_val, compare_to).to_string())
    }
}

fn check_describe_instances(
    xml_doc: &str,
    instance_id: &str,
    image_id: &str,
    vol_id: &str,
) -> Result<(String, DateTime<FixedOffset>, DateTime<FixedOffset>), String> {
    let package = sxd_document::parser::parse(xml_doc).map_err(|e| e.to_string())?;
    let doc = package.as_document();
    xpath_has_one_child(&doc, xpathnonspath!("DescribeInstancesResponse"))?;
    xpath_has_one_child(
        &doc,
        xpathnonspath!("DescribeInstancesResponse", "reservationSet"),
    )?;

    let owner_id = evaluate_xpath(
        &doc,
        xpathnonspath!(
            "DescribeInstancesResponse",
            "reservationSet",
            "item",
            "ownerId"
        ),
    )
    .map_err(|e| e.to_string())?;

    xpath_has_one_child(
        &doc,
        xpathnonspath!("DescribeInstancesResponse", "reservationSet", "item"),
    )?;

    xpath_has_one_child(
        &doc,
        xpathnonspath!(
            "DescribeInstancesResponse",
            "reservationSet",
            "item",
            "instancesSet"
        ),
    )?;

    // TODO: Fix inefficiencies due to repeated parsing of the xml tree upto instanceSet node
    macro_rules! xpathinstance_prefix {
	() => { xpathnonspath!("DescribeInstancesResponse","reservationSet","item","instancesSet","item") };
	($($tail:tt)* ) => {
            concat!(xpathinstance_prefix!(), xpathnonspath!($($tail)*))
	}
    }

    xpath_has_one_child(&doc, xpathinstance_prefix!())?;

    let attestation_instance_id =
        evaluate_xpath(&doc, xpathinstance_prefix!("instanceId")).map_err(|e| e.to_string())?;
    checkexpr!((attestation_instance_id.into_string()).eq(instance_id))?;

    let attestation_image_id =
        evaluate_xpath(&doc, xpathinstance_prefix!("imageId")).map_err(|e| e.to_string())?;
    checkexpr!((attestation_image_id.into_string()).eq(image_id))?;

    xpath_equals(
        &doc,
        xpathinstance_prefix!("instanceState", "name"),
        "running",
    )?;

    let instance_type =
        evaluate_xpath(&doc, xpathinstance_prefix!("instanceType")).map_err(|e| e.to_string())?;
    checkexpr!(instance_type.into_string().starts_with("t3"))?;

    let launch_time =
        evaluate_xpath(&doc, xpathinstance_prefix!("launchTime")).map_err(|e| e.to_string())?;

    xpath_equals(&doc, xpathinstance_prefix!("rootDeviceType"), "ebs")?;
    xpath_equals(&doc, xpathinstance_prefix!("rootDeviceName"), "/dev/sda1")?;

    xpath_has_one_child(&doc, xpathinstance_prefix!("blockDeviceMapping"))?;
    xpath_equals(
        &doc,
        xpathinstance_prefix!("blockDeviceMapping", "item", "deviceName"),
        "/dev/sda1",
    )?;

    xpath_has_one_child(&doc, xpathinstance_prefix!("blockDeviceMapping"))?;
    xpath_equals(
        &doc,
        xpathinstance_prefix!("blockDeviceMapping", "item", "ebs", "status"),
        "attached",
    )?;

    let attach_time = evaluate_xpath(
        &doc,
        xpathinstance_prefix!("blockDeviceMapping", "item", "ebs", "attachTime"),
    )
    .map_err(|e| e.to_string())?;

    xpath_equals(
        &doc,
        xpathinstance_prefix!("blockDeviceMapping", "item", "ebs", "volumeId"),
        vol_id,
    )?;

    xpath_equals(&doc, xpathinstance_prefix!("virtualizationType"), "hvm")?;
    xpath_equals(&doc, xpathinstance_prefix!("hypervisor"), "xen")?;

    let attach_time = chrono::DateTime::parse_from_rfc3339(&attach_time.into_string())
        .map_err(|_| "Cannot parse attach time".to_string())?;
    let launch_time = chrono::DateTime::parse_from_rfc3339(&launch_time.into_string())
        .map_err(|_| "Cannot parse launch_time".to_string())?;

    Ok((owner_id.into_string(), attach_time, launch_time))
}

fn check_get_user(xml_doc: &str, owner_id: &str) -> Result<(), String> {
    let package = sxd_document::parser::parse(xml_doc).map_err(|e| e.to_string())?;
    let doc = package.as_document();
    xpath_has_one_child(&doc, xpathnonspath!("GetUserResponse"))?;

    xpath_equals(
        &doc,
        xpathnonspath!("GetUserResponse", "GetUserResult", "User", "UserId"),
        owner_id,
    )?;

    let arn = evaluate_xpath(
        &doc,
        xpathnonspath!("GetUserResponse", "GetUserResult", "User", "Arn"),
    )
    .map_err(|e| e.to_string())?
    .into_string();

    let owner_id_string = owner_id.to_string() + ":root";
    if arn.as_str().ends_with(&owner_id_string) {
        Ok(())
    } else {
        Err("ARN owner id mismatch")
    }?;

    Ok(())
}

fn check_describe_volumes(
    xml_doc: &str,
    instance_id: &str,
    vol_id: &str,
    attach_time: &DateTime<FixedOffset>,
    roots_of_trust: RootOfTrust,
) -> Result<(), String> {
    let package = sxd_document::parser::parse(xml_doc).map_err(|e| e.to_string())?;
    let doc = package.as_document();
    xpath_has_one_child(&doc, xpathnonspath!("DescribeVolumesResponse"))?;
    xpath_has_one_child(&doc, xpathnonspath!("DescribeVolumesResponse", "volumeSet"))?;

    // TODO: Fix inefficiencies due to repeated parsing of the xml tree upto instanceSet node
    macro_rules! xpathvolume_prefix {
	() => { xpathnonspath!("DescribeVolumesResponse", "volumeSet", "item") };
	($($tail:tt)* ) => {
            concat!(xpathvolume_prefix!(), xpathnonspath!($($tail)*))
	}
    }

    macro_rules! xpathattachment_prefix {
	() => { xpathnonspath!("DescribeVolumesResponse", "volumeSet", "item", "attachmentSet", "item") };
	($($tail:tt)* ) => {
            concat!(xpathattachment_prefix!(), xpathnonspath!($($tail)*))
	}
    }

    xpath_equals(&doc, xpathvolume_prefix!("volumeId"), vol_id)?;

    let snapshot_id = evaluate_xpath(&doc, xpathvolume_prefix!("snapshotId"))
        .map_err(|e| e.to_string())?
        .into_string();
    roots_of_trust
        .iter()
        .find(|&&x| x == snapshot_id)
        .ok_or("verifier booted from invalid snapshot")?;

    xpath_equals(&doc, xpathvolume_prefix!("status"), "in-use")?;

    let create_time = evaluate_xpath(&doc, xpathvolume_prefix!("createTime"))
        .map_err(|e| e.to_string())?
        .into_string();

    //Verify attachment;
    xpath_has_one_child(&doc, xpathvolume_prefix!("attachmentSet"))?;
    xpath_equals(&doc, xpathattachment_prefix!("volumeId"), vol_id)?;
    xpath_equals(&doc, xpathattachment_prefix!("instanceId"), instance_id)?;
    xpath_equals(&doc, xpathattachment_prefix!("device"), "/dev/sda1")?;
    xpath_equals(&doc, xpathattachment_prefix!("status"), "attached")?;

    let doc_attach_time = evaluate_xpath(&doc, xpathattachment_prefix!("attachTime"))
        .map_err(|e| e.to_string())?
        .into_string();
    if attach_time
        == &chrono::DateTime::parse_from_rfc3339(&doc_attach_time).map_err(|e| e.to_string())?
    {
        Ok(())
    } else {
        Err("Attachment time mismatch".to_string())
    }?;

    // Crucial: volume was created from snapshot and attached at the same instant
    // this guarantees that there was no time window to modify it
    match doc_attach_time[0..19].cmp(create_time[0..19].into()) {
        std::cmp::Ordering::Equal => Ok(()),
        _ => Err("Attachment time != create time".to_string()),
    }?;

    Ok(())
}

fn check_get_console_output(xml_doc: &str, instance_id: &str) -> Result<String, String> {
    let package = sxd_document::parser::parse(xml_doc).map_err(|e| e.to_string())?;
    let doc = package.as_document();
    xpath_has_one_child(&doc, xpathnonspath!("GetConsoleOutputResponse"))?;
    let attestation_instance_id = evaluate_xpath(
        &doc,
        xpathnonspath!("GetConsoleOutputResponse", "instanceId"),
    )
    .map_err(|e| e.to_string())?;
    checkexpr!((attestation_instance_id.into_string()).eq(instance_id))?;

    let output = evaluate_xpath(&doc, xpathnonspath!("GetConsoleOutputResponse", "output"))
        .map_err(|e| e.to_string())?;
    let output = base64::decode_config(&output.into_string().as_bytes(), base64::STANDARD_NO_PAD)
        .map_err(|e| e.to_string())?;
    let output = String::from_utf8(output).map_err(|e| e.to_string())?;
    let re = Regex::new("nvme[0-9|a-z]{0,7}").map_err(|_| "Cannot create Regex".to_string())?;
    for cap in re.captures_iter(&output) {
        if cap.len() != 1 {
            Err("Invalid NVMe found")
        } else {
            Ok(())
        }?;
        let cap = cap.get(0).ok_or("Invalid NVMe".to_string())?;
        match cap.as_str() {
            "nvme" | "nvme0" | "nvme0n1" | "nvme0n1p1" => Ok(()),
            _ => Err("Invalid NVMe found"),
        }?;
    }

    let begin_pattern = "-----BEGIN PUBLIC KEY-----".to_string();
    let mut pub_key = begin_pattern.clone();
    for x in output
        .lines()
        .skip_while(|e| !e.contains(&begin_pattern))
        .skip(1)
        .take(2)
    {
        let key_line = x
            .split(" ")
            .take(6)
            .last()
            .ok_or("No server key".to_string())?;
        pub_key.push_str("\n");
        pub_key.push_str(key_line);
    }
    pub_key.push_str("\n");
    pub_key.push_str("-----END PUBLIC KEY-----");
    Ok(pub_key)
}

fn check_describe_instance_attribute_helper(
    doc: &Document,
    instance_id: &str,
) -> Result<(), String> {
    xpath_has_one_child(doc, xpathnonspath!("DescribeInstanceAttributeResponse"))?;
    xpath_equals(
        doc,
        xpathnonspath!("DescribeInstanceAttributeResponse", "instanceId"),
        instance_id,
    )?;
    Ok(())
}

fn check_describe_instance_attribute_user_data(
    xml_doc: &str,
    instance_id: &str,
) -> Result<(), String> {
    let package = sxd_document::parser::parse(xml_doc).map_err(|e| e.to_string())?;
    let doc = package.as_document();
    check_describe_instance_attribute_helper(&doc, instance_id)?;
    xpath_equals(
        &doc,
        xpathnonspath!("DescribeInstanceAttributeResponse", "userData"),
        "",
    )?;
    Ok(())
}

fn check_describe_instance_attribute_kernel(
    xml_doc: &str,
    instance_id: &str,
) -> Result<(), String> {
    let package = sxd_document::parser::parse(xml_doc).map_err(|e| e.to_string())?;
    let doc = package.as_document();
    check_describe_instance_attribute_helper(&doc, instance_id)?;
    xpath_equals(
        &doc,
        xpathnonspath!("DescribeInstanceAttributeResponse", "kernel"),
        "",
    )?;
    Ok(())
}

fn check_describe_instance_attribute_ramdisk(
    xml_doc: &str,
    instance_id: &str,
) -> Result<(), String> {
    let package = sxd_document::parser::parse(xml_doc).map_err(|e| e.to_string())?;
    let doc = package.as_document();
    check_describe_instance_attribute_helper(&doc, instance_id)?;
    xpath_equals(
        &doc,
        xpathnonspath!("DescribeInstanceAttributeResponse", "ramdisk"),
        "",
    )?;
    Ok(())
}

fn check_describe_images(
    xml_doc: &str,
    ami_id: &str,
    roots_of_trust: RootOfTrust,
) -> Result<(), String> {
    let package = sxd_document::parser::parse(xml_doc).map_err(|e| e.to_string())?;
    let doc = package.as_document();
    xpath_has_one_child(&doc, xpathnonspath!("DescribeImagesResponse"))?;
    xpath_has_one_child(&doc, xpathnonspath!("DescribeImagesResponse", "imagesSet"))?;

    macro_rules! xpathimg_prefix {
	() => {
	    xpathnonspath!("DescribeImagesResponse", "imagesSet", "item")
	};
	($($tail:tt)* ) => {
            concat!(xpathimg_prefix!(), xpathnonspath!($($tail)*))
	}
    }

    macro_rules! xpathbdmap_prefix {
	() => {
	    xpathnonspath!("DescribeImagesResponse", "imagesSet", "item", "blockDeviceMapping", "item")
	};
	($($tail:tt)* ) => {
            concat!(xpathbdmap_prefix!(), xpathnonspath!($($tail)*))
	}
    }

    xpath_equals(&doc, xpathimg_prefix!("imageId"), ami_id)?;
    xpath_equals(&doc, xpathimg_prefix!("imageState"), "available")?;
    xpath_equals(&doc, xpathimg_prefix!("rootDeviceName"), "/dev/sda1")?;
    xpath_has_one_child(&doc, xpathimg_prefix!("blockDeviceMapping"))?;
    xpath_equals(&doc, xpathbdmap_prefix!("deviceName"), "/dev/sda1")?;
    let ebs_snapshot_id = evaluate_xpath(&doc, xpathbdmap_prefix!("ebs", "snapshotId"))
        .map_err(|e| e.to_string())?
        .into_string();
    roots_of_trust
        .iter()
        .find(|&&x| x == ebs_snapshot_id)
        .ok_or("verifier booted from invalid snapshot")?;
    xpath_equals(&doc, xpathimg_prefix!("virtualizationType"), "hvm")?;
    xpath_equals(&doc, xpathimg_prefix!("hypervisor"), "xen")?;
    Ok(())
}

pub fn verify_notary(
    ctx: &PageSignerVerificationContext,
) -> Result<(&PageSignerVerificationContext, String), String> {
    // find which URL corresponds to which API call
    let search_req_resp = |omarker: &str| -> Result<&ReqResp, &str> {
        let pos = ctx
            .sev_ctx
            .sev_att
            .iter()
            .position(|x| x.request.contains(omarker) == true)
            .ok_or("SEV attestation marker absent")?;
        Ok(&ctx.sev_ctx.sev_att[pos])
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
    let ami_id = check_marked_id(
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

    let re_str = format!("^{}\\?AWSAccessKeyId={}&Action=DescribeImages&Expires=2030-01-01&ImageId.1={}&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=[a-zA-Z0-9%]{{46,56}}$", AWS_ZONE_PREFIX, access_key, ami_id);
    re_match(&re_str, &markers["DImg"].1.unwrap().request)?;

    let (owner_id, attach_time, _launch_time) = check_describe_instances(
        &markers["DI"].1.unwrap().response,
        instance_id,
        ami_id,
        vol_id,
    )?;

    check_describe_volumes(
        &markers["DV"].1.unwrap().response,
        instance_id,
        vol_id,
        &attach_time,
        ROOT_OF_TRUST,
    )?;

    check_get_user(&markers["GU"].1.unwrap().response, &owner_id)?;
    let pubkey = check_get_console_output(&markers["GCO"].1.unwrap().response, &instance_id)?;

    check_describe_instance_attribute_user_data(
        &markers["DIAud"].1.unwrap().response,
        &instance_id,
    )?;

    check_describe_instance_attribute_kernel(&markers["DIAk"].1.unwrap().response, &instance_id)?;
    check_describe_instance_attribute_ramdisk(&markers["DIAr"].1.unwrap().response, &instance_id)?;
    check_describe_images(&markers["DImg"].1.unwrap().response, &ami_id, ROOT_OF_TRUST)?;

    Ok((ctx, pubkey))
}
