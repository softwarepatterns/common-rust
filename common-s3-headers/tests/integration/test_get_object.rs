use crate::test_util::{assert, setup};
use common_s3_headers::{self, S3HeadersBuilder};
use std::str::FromStr;
use url::Url;

#[test]
#[ignore]
fn test_get_object() {
  let (access_key, secret_key, region) = setup::get_config_from_env("TEST_S3");
  let url = Url::from_str("https://jsonlog.s3.amazonaws.com/test/test.json").unwrap();
  let headers = S3HeadersBuilder::new(&url)
    .set_access_key(&access_key)
    .set_secret_key(&secret_key)
    .set_region(&region)
    .set_method("GET")
    .set_service("s3")
    .build();

  let (status_code, response_headers, body) = assert::request_get(url, headers);

  assert::equal(status_code, 200);
  assert::content_type(response_headers, "application/json");
  assert::equal(body, "{\"a\":\"b\"}\n");
}

#[test]
#[ignore]
fn test_get_object_range_with_start() {
  let (access_key, secret_key, region) = setup::get_config_from_env("TEST_S3");
  let url = Url::from_str("https://jsonlog.s3.amazonaws.com/test/test.json").unwrap();
  let range_headers = common_s3_headers::get_range_headers(1, None);
  let headers = S3HeadersBuilder::new(&url)
    .set_access_key(&access_key)
    .set_secret_key(&secret_key)
    .set_region(&region)
    .set_method("GET")
    .set_service("s3")
    .set_headers(&range_headers)
    .build();

  let (status_code, response_headers, body) = assert::request_get(url, headers);
  assert::equal(status_code, 206);
  assert::content_type(response_headers, "application/json");
  assert::equal(body, "\"a\":\"b\"}\n");
}

#[test]
#[ignore]
fn test_get_object_range_with_end() {
  let (access_key, secret_key, region) = setup::get_config_from_env("TEST_S3");
  let url = Url::from_str("https://jsonlog.s3.amazonaws.com/test/test.json").unwrap();
  let range_headers = common_s3_headers::get_range_headers(1, Some(2));
  let headers = S3HeadersBuilder::new(&url)
    .set_access_key(&access_key)
    .set_secret_key(&secret_key)
    .set_region(&region)
    .set_method("GET")
    .set_service("s3")
    .set_headers(&range_headers)
    .build();

  let (status_code, response_headers, body) = assert::request_get(url, headers);
  assert::equal(status_code, 206);
  assert::content_type(response_headers, "application/json");
  assert::equal(body, "\"a");
}
