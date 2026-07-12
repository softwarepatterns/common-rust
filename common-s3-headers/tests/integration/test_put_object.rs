use crate::test_util::{assert, setup};
use common_s3_headers::{self, S3HeadersBuilder};
use std::str::FromStr;
use url::Url;

#[test]
#[ignore]
fn test_put_object() {
  let (access_key, secret_key, region) = setup::get_config_from_env("TEST_S3");

  let url = Url::from_str("https://jsonlog.s3.amazonaws.com/test/test2.json").unwrap();
  let content = "{\"c\":\"d\"}\n".as_bytes().to_vec();
  let sha = common_s3_headers::aws_math::get_sha256(&content);
  let headers = S3HeadersBuilder::new(&url)
    .set_access_key(&access_key)
    .set_secret_key(&secret_key)
    .set_region(&region)
    .set_method("PUT")
    .set_service("s3")
    // Only borrowed should work.
    .set_payload_hash(&sha)
    .build();

  let (status_code, _, body) = assert::request_put(url, headers, content);
  assert::equal(status_code, 200);
  assert::equal(body, "");
}

// Should be able to set this as const.
const PUT_METHOD: &str = "PUT";

#[test]
#[ignore]
fn test_put_object_with_sha_shortcut() {
  let (access_key, secret_key, region) = setup::get_config_from_env("TEST_S3");

  let url = Url::from_str("https://jsonlog.s3.amazonaws.com/test/test2.json").unwrap();
  let content = "{\"c\":\"d\"}\n".as_bytes().to_vec();
  let headers = S3HeadersBuilder::new(&url)
    .set_access_key(&access_key)
    .set_secret_key(&secret_key)
    .set_region(&region)
    // This const should be okay.
    .set_method(PUT_METHOD)
    .set_service("s3")
    // This creates a new payload value that is owned until dropped.
    .set_payload_hash_with_content(&content)
    .build();

  let (status_code, _, body) = assert::request_put(url, headers, content);
  assert::equal(status_code, 200);
  assert::equal(body, "");
}

#[test]
#[ignore]
fn test_put_object_full() {
  // Build the S3 headers
  let (access_key, secret_key, region) = setup::get_config_from_env("TEST_S3");
  let url = Url::from_str("https://jsonlog.s3.amazonaws.com/test/test2.json").unwrap();
  let content = "{\"c\":\"d\"}\n".as_bytes().to_vec();
  let headers = S3HeadersBuilder::new(&url)
    .set_access_key(&access_key)
    .set_secret_key(&secret_key)
    .set_region(&region)
    // This const should be okay.
    .set_method(PUT_METHOD)
    .set_service("s3")
    // This creates a new payload value that is owned until dropped.
    .set_payload_hash_with_content(&content)
    .build();

  // Use Reqwest
  let response = reqwest::blocking::Client::new()
    .put(url)
    .headers(reqwest::header::HeaderMap::from_iter(headers.into_iter().map(
      |(k, v)| {
        (
          reqwest::header::HeaderName::from_str(k).unwrap(),
          reqwest::header::HeaderValue::from_str(&v).unwrap(),
        )
      },
    )))
    .send()
    .unwrap();

  // Print results
  let status_code = response.status();
  let response_headers = response.headers().clone();
  let body = response.text().unwrap();
  println!("{}\n{:#?}\n{}", status_code, response_headers, body);
}
