use crate::test_util::{assert, setup};
use common_s3_headers::{self, S3HeadersBuilder};
use serde::Deserialize;
use std::str::FromStr;
use url::Url;

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename = "ListBucketResult")]
struct AwsListBucketResult {
  #[serde(rename = "Contents", default)]
  contents: Vec<AwsContents>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct AwsContents {
  #[serde(rename = "Key")]
  key: String,
  #[serde(rename = "LastModified")]
  last_modified: String,
  #[serde(rename = "Size")]
  size: u64,
  #[serde(rename = "Owner")]
  owner: Option<AwsOwner>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct AwsOwner {
  #[serde(rename = "ID")]
  id: String,
  #[serde(rename = "DisplayName")]
  display_name: String,
}

#[test]
#[ignore]
fn test_aws_structures() {
  let body = r#"<?xml version="1.0" encoding="UTF-8"?>
  <ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
      <Contents>
          <Key>test/</Key>
          <LastModified>2023-08-06T04:39:19.000Z</LastModified>
          <Size>6360</Size>
      </Contents>
  </ListBucketResult>"#;

  let result: AwsListBucketResult = serde_xml_rs::from_str(body).unwrap();

  println!("{:#?}", result);
}

#[test]
#[ignore]
fn test_list_objects() {
  let (access_key, secret_key, region) = setup::get_config_from_env("TEST_S3");
  let url = Url::from_str("https://jsonlog.s3.amazonaws.com/").unwrap();
  let headers = S3HeadersBuilder::new(&url)
    .set_access_key(&access_key)
    .set_secret_key(&secret_key)
    .set_region(&region)
    .set_method("GET")
    .set_service("s3")
    .build();

  let (status_code, response_headers, body) = assert::request_get(url, headers);

  assert::equal(status_code, 200);
  assert::content_type(response_headers, "application/xml");
  assert!(!body.is_empty());

  // println!("{:#?}", body);
  let result: Result<AwsListBucketResult, _> = serde_xml_rs::from_str(&body);
  assert::ok(&result);
  //println!("{:#?}", result);
}

#[test]
#[ignore]
fn test_list_objects_v2() {
  let (access_key, secret_key, region) = setup::get_config_from_env("TEST_S3");
  let url = Url::from_str("https://jsonlog.s3.amazonaws.com/?list_type=2").unwrap();
  let headers = S3HeadersBuilder::new(&url)
    .set_access_key(&access_key)
    .set_secret_key(&secret_key)
    .set_region(&region)
    .set_method("GET")
    .set_service("s3")
    .build();

  let (status_code, response_headers, body) = assert::request_get(url, headers);

  assert::equal(status_code, 200);
  assert::content_type(response_headers, "application/xml");
  assert!(!body.is_empty());

  // println!("{:#?}", body);
  let result: Result<AwsListBucketResult, _> = serde_xml_rs::from_str(&body);
  assert::ok(&result);
  // println!("{:#?}", result);
}
