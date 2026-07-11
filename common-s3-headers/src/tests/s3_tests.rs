use crate::{
  aws_math::get_sha256,
  s3::{self, S3DateTime, S3HeadersBuilder},
};
use common_testing::assert;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::str::FromStr;
use time::Date;
use url::Url;

#[test]
fn test_get_object() {
  let url = Url::from_str("https://jsonlog.s3.amazonaws.com/test.json").unwrap();
  let options = S3HeadersBuilder::new(&url)
    .set_access_key("some_access_key")
    .set_secret_key("some_secret_key")
    .set_region("some_place")
    .set_datetime(S3DateTime::UnixTimestamp(0))
    .set_method("GET")
    .set_service("s3");
  let result = s3::get_headers(options);

  assert::equal(result, vec![
    ("Host", "jsonlog.s3.amazonaws.com".to_owned()),
    ("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned()),
    ("x-amz-date", "19700101T000000Z".to_owned()),
    (
      "Authorization",
      "AWS4-HMAC-SHA256 Credential=some_access_key/19700101/some_place/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=521595a9eeee7092d3b2cc49d4db7cb828a5db5c7ad5136c149db0b0e7277f83".to_owned()
    )
  ])
}

#[test]
fn test_put_object() {
  let url = Url::from_str("https://examplebucket.s3.amazonaws.com/test$file.text").unwrap();
  let headers = &[("x-amz-storage-class", "REDUCED_REDUNDANCY".to_owned())];
  let content = b"".as_slice();
  let sha = get_sha256(content);
  let options = S3HeadersBuilder::new(&url)
    .set_access_key("some_access_key")
    .set_secret_key("some_secret_key")
    .set_region("some_place")
    .set_datetime(S3DateTime::UnixTimestamp(1369324800)) // 20130524T000000Z
    .set_headers(headers)
    .set_method("PUT")
    .set_service("s3")
    .set_payload_hash(&sha);
  let result = s3::get_headers(options);

  assert::equal(result, vec![
    ("x-amz-storage-class", "REDUCED_REDUNDANCY".to_owned()),
    ("Host", "examplebucket.s3.amazonaws.com".to_owned()),
    ("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned()),
    ("x-amz-date", "20130523T160000Z".to_owned()),
    (
      "Authorization",
      "AWS4-HMAC-SHA256 Credential=some_access_key/20130523/some_place/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-storage-class,Signature=7e2911c8225f7591609bcbdc2faf8c443a898d8c83fc35b6a23f0b0e8084da60".to_owned()
    )
  ])
}

// --- presign_get: round-trip against the KAT-verified low-level primitives ---

fn fixture_datetime() -> time::OffsetDateTime {
  Date::from_calendar_date(2013, 5.try_into().unwrap(), 24)
    .unwrap()
    .with_hms(0, 0, 0)
    .unwrap()
    .assume_utc()
}

/// Hand-built canonical query string for the fixture's presign params, kept as a
/// literal so the test is an independent oracle for what `presign_get` must build
/// via `authorization_query_params_no_sig`.
const FIXTURE_CANONICAL_QUERY: &str = "X-Amz-Algorithm=AWS4-HMAC-SHA256\
  &X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request\
  &X-Amz-Date=20130524T000000Z\
  &X-Amz-Expires=86400\
  &X-Amz-SignedHeaders=host";

#[test]
fn test_presign_get_signature_matches_kat_primitives() {
  let datetime = fixture_datetime();
  // Independently build the canonical request for a host-only UNSIGNED-PAYLOAD
  // presigned GET, and sign it with the same KAT-verified primitives
  // `presign_get` uses internally.
  let expected_canonical_request = format!(
    "GET\n/test.txt\n{}\nhost:examplebucket.s3.amazonaws.com\n\nhost\nUNSIGNED-PAYLOAD",
    FIXTURE_CANONICAL_QUERY
  );
  let string_to_sign =
    crate::aws_format::string_to_sign(&datetime, "us-east-1", "s3", &expected_canonical_request);
  let signing_key = crate::aws_math::get_signature_key(
    &datetime,
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "us-east-1",
    "s3",
  );
  let mut hmac = Hmac::<Sha256>::new_from_slice(&signing_key).unwrap();
  hmac.update(string_to_sign.as_bytes());
  let expected_signature = hex::encode(hmac.finalize().into_bytes());

  let url = Url::from_str("https://examplebucket.s3.amazonaws.com/test.txt").unwrap();
  let presigned = s3::presign_get(
    &url,
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "us-east-1",
    "s3",
    S3DateTime::UnixTimestamp(datetime.unix_timestamp()),
    86400,
  );

  // The URL must carry exactly the signature derived over the independent
  // canonical request. A construction bug in `presign_get` would diverge here.
  assert_eq!(
    tail_signature(&presigned),
    expected_signature,
    "presigned url: {presigned}"
  );
}

#[test]
fn test_presign_get_url_shape() {
  let datetime = fixture_datetime();
  let url = Url::from_str("https://examplebucket.s3.amazonaws.com/test.txt").unwrap();
  let presigned = s3::presign_get(
    &url,
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "us-east-1",
    "s3",
    S3DateTime::UnixTimestamp(datetime.unix_timestamp()),
    86400,
  );

  assert!(
    presigned.starts_with("https://examplebucket.s3.amazonaws.com/test.txt?"),
    "presigned url: {presigned}"
  );
  assert!(presigned.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
  assert!(presigned.contains("X-Amz-Date=20130524T000000Z"));
  assert!(presigned.contains("X-Amz-Expires=86400"));
  assert!(presigned.contains("X-Amz-SignedHeaders=host"));
  // The signature is a 64-character lowercase hex SHA-256 HMAC.
  let sig = tail_signature(&presigned);
  assert_eq!(sig.len(), 64);
  assert!(sig.bytes().all(|b| b.is_ascii_hexdigit()));
}

#[test]
fn test_presign_get_is_deterministic() {
  let datetime = fixture_datetime();
  let url = Url::from_str("https://examplebucket.s3.amazonaws.com/test.txt").unwrap();
  let a = s3::presign_get(
    &url,
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "us-east-1",
    "s3",
    S3DateTime::UnixTimestamp(datetime.unix_timestamp()),
    3600,
  );
  let b = s3::presign_get(
    &url,
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "us-east-1",
    "s3",
    S3DateTime::UnixTimestamp(datetime.unix_timestamp()),
    3600,
  );
  assert::equal(a, b);
}

#[test]
fn test_presign_get_expiry_changes_signature() {
  let datetime = fixture_datetime();
  let url = Url::from_str("https://examplebucket.s3.amazonaws.com/test.txt").unwrap();
  let ts = S3DateTime::UnixTimestamp(datetime.unix_timestamp());
  let short = s3::presign_get(
    &url,
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "us-east-1",
    "s3",
    ts,
    3600,
  );
  let long = s3::presign_get(
    &url,
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "us-east-1",
    "s3",
    ts,
    7200,
  );
  assert_ne!(tail_signature(&short), tail_signature(&long));
}

/// Extract the value of `X-Amz-Signature=...` from the tail of a presigned URL.
fn tail_signature(presigned_url: &str) -> String {
  let marker = "&X-Amz-Signature=";
  let idx = presigned_url
    .find(marker)
    .expect("presigned url must carry X-Amz-Signature");
  presigned_url[idx + marker.len()..].to_owned()
}
