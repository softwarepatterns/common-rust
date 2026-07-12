//! AWS-specific math.
//!
//! Crypto goes here.
//!
use crate::aws_format::{query_params_string, security_token_string, to_short_datetime};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use time::OffsetDateTime;

// Create alias for HMAC-SHA256
// @see https://docs.rs/hmac/latest/hmac/
pub type HmacSha256 = Hmac<Sha256>;
#[allow(dead_code)]
type HeaderMap<'a> = Vec<(Cow<'a, str>, Cow<'a, str>)>;

/// Gets the SHA256 hash of the value. Returns a hex string. Never panics.
///
/// # Examples
///
/// ```
/// use common_s3_headers::aws_math::get_sha256;
///
/// let result = get_sha256(b"");
/// assert_eq!(result, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
/// ```
///
/// ```
/// use common_s3_headers::aws_math::get_sha256;
///
/// let result = get_sha256(b"hello world");
/// assert_eq!(result, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
/// ```
///
pub fn get_sha256(value: &[u8]) -> String {
  // There is a Rust analyzer bug that forces us to use `as Digest` here.
  let mut hasher = <Sha256 as Digest>::new();
  hasher.update(value);
  hex::encode(hasher.finalize().as_slice())
}

/// Signs data with the key using Hmac<Sha256>. Never panics.
pub fn sign(key: &[u8], data: &[u8]) -> HmacSha256 {
  // Never panics; the algorithm we're using can accept any length of bytes.
  let mut hmac: HmacSha256 = Hmac::new_from_slice(key).expect("HMAC can take key of any size");
  hmac.update(data);
  hmac
}

/// AWS uses the previous HMAC to calculate each new item.
///
/// @see https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
/// @private
fn fold_hmacs(items: &[&[u8]]) -> Vec<u8> {
  assert!(items.len() > 1);

  let mut hmac: HmacSha256 = sign(items[0], items[1]);
  for data in items[2..].iter() {
    hmac = sign(&hmac.finalize().into_bytes(), data);
  }
  hmac.finalize().into_bytes().to_vec()
}

/// Generate the AWS signing key, derived from the secret key, date, region,
/// and service name.
///
/// # Examples
///
/// ```
/// use common_s3_headers::aws_math::get_signature_key;
/// use time::Date;
///
/// // The AWS reference vector for 2015-08-30 / us-east-1 / iam.
/// let datetime = Date::from_calendar_date(2015, time::Month::August, 30)
///     .unwrap()
///     .with_hms(0, 0, 0)
///     .unwrap()
///     .assume_utc();
/// let result = get_signature_key(&datetime, "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "us-east-1", "iam");
/// assert_eq!(result, vec![
///  196, 175, 177, 204, 87, 113, 216, 113, 118, 58, 57, 62, 68, 183, 3, 87, 27, 85, 204, 40, 66, 77, 26, 94, 134, 218, 110, 211, 193, 84, 164, 185
/// ]);
/// ```
///
/// @see https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
/// @see https://docs.aws.amazon.com/translate/latest/dg/examples-sigv4.html
pub fn get_signature_key(datetime: &OffsetDateTime, secret_key: &str, region: &str, service: &str) -> Vec<u8> {
  let secret = format!("AWS4{}", secret_key);
  let formatted_datetime = to_short_datetime(datetime);

  fold_hmacs(&[
    secret.as_bytes(),
    formatted_datetime.as_bytes(),
    region.as_bytes(),
    service.as_bytes(),
    b"aws4_request",
  ])
}

/// Gets the authorization header for AWS.
///
/// # Examples
///
/// ```
/// use common_s3_headers::aws_math::authorization_query_params_no_sig;
/// use common_s3_headers::aws_format::to_short_datetime;
/// use time::OffsetDateTime;
///
/// // Preset datetime for testing.
/// let datetime = OffsetDateTime::from_unix_timestamp(0).unwrap();
/// let result = authorization_query_params_no_sig(
/// "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
/// &datetime,
/// "us-east-1",
/// "iam",
/// 86400,
/// None,
/// None,
/// );
/// assert_eq!(result, "?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=wJalrXUtnFEMI%2FK7MDENG%2FbPxRfiCYEXAMPLEKEY%2F19700101%2Fus-east-1%2Fiam%2Faws4_request&X-Amz-Date=19700101T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host");
/// ```
///
pub fn authorization_query_params_no_sig(
  access_key: &str,
  datetime: &OffsetDateTime,
  region: &str,
  service: &str,
  expires: u32,
  custom_headers: Option<&HeaderMap>,
  token: Option<&String>,
) -> String {
  let signed_headers = if let Some(custom_headers) = &custom_headers {
    let mut list = Vec::with_capacity(custom_headers.len() + 1);
    list.push("host");
    custom_headers.iter().for_each(|(k, _)| list.push(k));
    list.sort();
    list
  } else {
    vec!["host"]
  };

  let mut query_params = query_params_string(&signed_headers, access_key, datetime, region, service, expires);

  if let Some(token) = token {
    query_params += &security_token_string(token);
  }

  query_params
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{aws_canonical::to_canonical_headers, aws_format};
  use common_testing::assert;
  use hmac::{Hmac, Mac};
  use sha2::Sha256;
  use time::Date;
  use url::Url;

  #[test]
  fn test_signing_key() {
    let datetime = &Date::from_calendar_date(2015, 8.try_into().unwrap(), 30)
      .unwrap()
      .with_hms(0, 0, 0)
      .unwrap()
      .assume_utc();
    let secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    let region = "us-east-1";
    let service = "iam";

    let result = get_signature_key(datetime, secret_key, region, service);

    assert::equal_hex_bytes(
      &result,
      "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9",
    );
  }

  const EXPECTED_SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

  const EXPECTED_CANONICAL_REQUEST: &str = "GET\n\
    /test.txt\n\
    \n\
    host:examplebucket.s3.amazonaws.com\n\
    range:bytes=0-9\n\
    x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\
    x-amz-date:20130524T000000Z\n\
    \n\
    host;range;x-amz-content-sha256;x-amz-date\n\
    e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

  const EXPECTED_STRING_TO_SIGN: &str = "AWS4-HMAC-SHA256\n\
    20130524T000000Z\n\
    20130524/us-east-1/s3/aws4_request\n\
    7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972";

  #[test]
  fn test_signing() {
    let url = Url::parse("https://examplebucket.s3.amazonaws.com/test.txt").unwrap();
    let headers = vec![
      ("x-amz-date", "20130524T000000Z"),
      ("Range", "bytes=0-9"),
      ("Host", "examplebucket.s3.amazonaws.com"),
      ("x-amz-content-sha256", EXPECTED_SHA),
    ];
    let service = "s3";
    let canonical_headers = to_canonical_headers(&headers);
    let canonical_string = aws_format::canonical_request_string("GET", &url, &canonical_headers, EXPECTED_SHA);
    assert_eq!(EXPECTED_CANONICAL_REQUEST, canonical_string);

    let datetime = Date::from_calendar_date(2013, 5.try_into().unwrap(), 24)
      .unwrap()
      .with_hms(0, 0, 0)
      .unwrap()
      .assume_utc();
    let string_to_sign = aws_format::string_to_sign(&datetime, "us-east-1", service, &canonical_string);
    assert_eq!(EXPECTED_STRING_TO_SIGN, string_to_sign);

    let expected = "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41";
    let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    let signing_key = get_signature_key(&datetime, secret, "us-east-1", "s3");
    let mut hmac = Hmac::<Sha256>::new_from_slice(&signing_key).unwrap();
    hmac.update(string_to_sign.as_bytes());
    assert_eq!(expected, hex::encode(hmac.finalize().into_bytes()));
  }
}
