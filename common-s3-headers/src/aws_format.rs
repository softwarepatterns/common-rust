//! AWS-specific formatting.
//!
//! Any creation of strings goes here.
//!
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, CONTROLS};
use time::{macros::format_description, OffsetDateTime};
use url::Url;

use crate::aws_math::get_sha256;

const SHORT_DATE: &[time::format_description::FormatItem<'static>] = format_description!("[year][month][day]");

/// Convert a `time::OffsetDateTime` to a short date string. This is used in
/// the AWS credential scope. It is always UTC, YYYYMMDD, sortable and
/// lexicographically comparable.
///
/// # Examples
///
/// ```
/// use time::OffsetDateTime;
/// use common_s3_headers::aws_format::to_short_datetime;
///
/// let datetime = OffsetDateTime::from_unix_timestamp(0).unwrap();
/// let result = to_short_datetime(&datetime);
/// assert_eq!(result, "19700101");
///
/// let datetime = OffsetDateTime::from_unix_timestamp(1_000_000_000).unwrap();
/// let result = to_short_datetime(&datetime);
/// assert_eq!(result, "20010909");
/// ```
///
pub fn to_short_datetime(datetime: &OffsetDateTime) -> String {
  datetime
    .format(SHORT_DATE)
    .expect("All dates can be represented as short.")
}

const LONG_DATETIME: &[time::format_description::FormatItem<'static>] =
  time::macros::format_description!("[year][month][day]T[hour][minute][second]Z");

/// Convert a `time::OffsetDateTime` to a long date string. This is used in
/// the AWS credential scope. It is always UTC, YYYYMMDD'T'HHMMSS'Z', sortable
/// and lexicographically comparable.
///
/// # Examples
///
/// ```
/// use time::OffsetDateTime;
/// use common_s3_headers::aws_format::to_long_datetime;
///
/// let datetime = OffsetDateTime::from_unix_timestamp(0).unwrap();
/// let result = to_long_datetime(&datetime);
/// assert_eq!(result, "19700101T000000Z");
///
/// let datetime = OffsetDateTime::from_unix_timestamp(1_000_000_000).unwrap();
/// let result = to_long_datetime(&datetime);
/// assert_eq!(result, "20010909T014640Z");
/// ```
///
pub fn to_long_datetime(datetime: &OffsetDateTime) -> String {
  datetime
    .format(LONG_DATETIME)
    .expect("All dates can be represented as long.")
}

///
///
/// See https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html
/// See https://perishablepress.com/stop-using-unsafe-characters-in-urls/
const FRAGMENT: &AsciiSet = &CONTROLS
  // URL_RESERVED
  .add(b':')
  .add(b'?')
  .add(b'#')
  .add(b'[')
  .add(b']')
  .add(b'@')
  .add(b'!')
  .add(b'$')
  .add(b'&')
  .add(b'\'')
  .add(b'(')
  .add(b')')
  .add(b'*')
  .add(b'+')
  .add(b',')
  .add(b';')
  .add(b'=')
  // URL_UNSAFE
  .add(b'"')
  .add(b' ')
  .add(b'<')
  .add(b'>')
  .add(b'%')
  .add(b'{')
  .add(b'}')
  .add(b'|')
  .add(b'\\')
  .add(b'^')
  .add(b'`');

const FRAGMENT_SLASH: &AsciiSet = &FRAGMENT.add(b'/');

/// Encode a URI following the specific requirements of the AWS service.
pub fn uri_encode(string: &str, encode_slash: bool) -> String {
  if encode_slash {
    utf8_percent_encode(string, FRAGMENT_SLASH).to_string()
  } else {
    utf8_percent_encode(string, FRAGMENT).to_string()
  }
}

/// Generate an AWS scope string. This is used in the AWS authorization header. It is
/// always YYYYMMDD'T'HHMMSS'Z'/region/service/aws4_request.
///
/// # Examples
///
/// ```
/// use time::OffsetDateTime;
/// use common_s3_headers::aws_format::credential_scope_string;
///
/// let datetime = OffsetDateTime::from_unix_timestamp(0).unwrap();
/// let result = credential_scope_string(&datetime, "us-east-1", "s3");
/// assert_eq!(result, "19700101/us-east-1/s3/aws4_request");
/// ```
///
pub fn credential_scope_string(datetime: &OffsetDateTime, region: &str, service: &str) -> String {
  format!("{}/{}/{}/aws4_request", to_short_datetime(datetime), region, service)
}

/// Generate the AWS authorization header.
pub fn authorization_header_string(
  access_key: &str,
  datetime: &OffsetDateTime,
  region: &str,
  service: &str,
  signed_headers: &str,
  signature: &str,
) -> String {
  format!(
    "AWS4-HMAC-SHA256 Credential={access_key}/{scope},\
          SignedHeaders={signed_headers},Signature={signature}",
    access_key = access_key,
    scope = credential_scope_string(datetime, region, service),
    signed_headers = signed_headers,
    signature = signature
  )
}

/// Generate the AWS string to sign. This is used in the AWS authorization header.
///
/// # Examples
///
/// ```
/// use time::OffsetDateTime;
/// use common_s3_headers::aws_format::string_to_sign;
///
/// let datetime = OffsetDateTime::from_unix_timestamp(0).unwrap();
/// let result = string_to_sign(&datetime, "us-east-1", "s3", "canonical_request");
/// assert_eq!(
///   result,
///   "AWS4-HMAC-SHA256\n19700101T000000Z\n19700101/us-east-1/s3/aws4_request\n572b1e335109068b81e4def81524c5fe5d0e385143b5656cbf2f7c88e5c1a51e"
/// );
/// ```
///
/// # See
///
/// * https://docs.aws.amazon.com/AmazonS3/latest/userguide/RESTAuthentication.html#ConstructingTheAuthenticationHeader
/// * https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
/// * https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
///
pub fn string_to_sign(datetime: &OffsetDateTime, region: &str, service: &str, canonical_request: &str) -> String {
  let hashed_canonical_request = get_sha256(canonical_request.as_bytes());

  format!(
    "AWS4-HMAC-SHA256\n{}\n{}\n{}",
    to_long_datetime(datetime),
    credential_scope_string(datetime, region, service),
    hashed_canonical_request
  )
}

/// Generate a canonical URI string from the given URL. This is used in the AWS
/// canonical request. It is always the path of the URL with percent encoding
/// applied.
///
/// # Examples
///
/// ```
/// use url::Url;
/// use common_s3_headers::aws_format::canonical_uri_string;
///
/// let url = Url::parse("http://localhost/some-url/?okay").unwrap();
/// let result = canonical_uri_string(&url);
/// assert_eq!(result, "/some-url/");
/// ```
pub fn canonical_uri_string(uri: &Url) -> String {
  // decode `Url`'s percent-encoding and then reencode it
  // according to AWS's rules
  let decoded = percent_decode_str(uri.path()).decode_utf8_lossy();
  uri_encode(&decoded, false)
}

/// Generate a canonical query string from the query pairs in the given URL.
pub fn canonical_query_string(uri: &Url) -> String {
  let mut keyvalues: Vec<(String, String)> = uri
    .query_pairs()
    .map(|(key, value)| (key.to_string(), value.to_string()))
    .collect();
  // Note that the sorting happens BEFORE encoding.
  keyvalues.sort();

  let keyvalues: Vec<String> = keyvalues
    .iter()
    .map(|(k, v)| {
      format!(
        "{}={}",
        utf8_percent_encode(k, FRAGMENT_SLASH),
        utf8_percent_encode(v, FRAGMENT_SLASH)
      )
    })
    .collect();
  keyvalues.join("&")
}

/// Convert a list of key-value pairs into a list of key-value strings with the given separator.
/// Allocates.
fn to_key_value_strings<S: AsRef<str>, T: AsRef<str>>(headers: &[(S, T)], sep: &str) -> Vec<String> {
  headers
    .iter()
    .map(|(k, v)| [k.as_ref(), v.as_ref()].join(sep))
    .collect::<Vec<String>>()
}

/// Get the keys from a list of key-value pairs. Allocates.
pub fn get_keys<S: AsRef<str>, T>(headers: &[(S, T)]) -> Vec<&str> {
  headers.iter().map(|(key, _)| key.as_ref()).collect::<Vec<&str>>()
}

/// Generate a canonical request. Assumes headers are already sorted and aws canonical.
///
/// NOTE: payload_hash might be "UNSIGNED-PAYLOAD" or sha256() of content, which can be different per request type.
///
/// canonical_request = method + '\n' +
///   canonical_uri + '\n' +
///   canonical_querystring + '\n' +
///   canonical_headers + '\n' +
///   signed_headers + '\n' +
///   payload_hash
///
/// # Examples
///
/// ```
/// use url::Url;
/// use common_s3_headers::aws_canonical::to_canonical_headers;
/// use common_s3_headers::aws_format::canonical_request_string;
///
/// let url = Url::parse("https://examplebucket.s3.amazonaws.com/test.txt").unwrap();
/// let headers = vec![
///  ("x-amz-date", "20130524T000000Z"),
///  ("Range", "bytes=0-9"),
///  ("Host", "examplebucket.s3.amazonaws.com"),
///  ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
/// ];
/// let canonical_headers = to_canonical_headers(&headers);
/// let result = canonical_request_string("GET", &url, &canonical_headers, "UNSIGNED-PAYLOAD");
/// assert_eq!(
///  result,
///  "GET\n\
///  /test.txt\n\
///  \n\
///  host:examplebucket.s3.amazonaws.com\n\
///  range:bytes=0-9\n\
///  x-amz-content-sha256:UNSIGNED-PAYLOAD\n\
///  x-amz-date:20130524T000000Z\n\
///  \n\
///  host;range;x-amz-content-sha256;x-amz-date\n\
///  UNSIGNED-PAYLOAD"
/// );
/// ```
///
/// # See
///
/// * https://docs.aws.amazon.com/AmazonS3/latest/userguide/RESTAuthentication.html#ConstructingTheAuthenticationHeader
/// * https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
/// * https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
/// * https://docs.aws.amazon.com/general/latest/gr/sigv4-add-signature-to-request.html
///
pub fn canonical_request_string<S: AsRef<str>>(
  method: &str,
  url: &Url,
  canonical_headers: &[(S, &str)],
  payload_hash: &str,
) -> String {
  let headers = to_key_value_strings(canonical_headers, ":").join("\n");
  format!(
    "{}\n{}\n{}\n{headers}\n\n{}\n{}",
    method,
    canonical_uri_string(url),
    canonical_query_string(url),
    get_keys(canonical_headers).join(";"),
    payload_hash
  )
}

/// Get the security token string. It is always &X-Amz-Security-Token=token with percent encoding.
///
/// # Examples
///
/// ```
/// use common_s3_headers::aws_format::security_token_string;
///
/// let result = security_token_string("token");
/// assert_eq!(result, "&X-Amz-Security-Token=token");
///
/// let result = security_token_string("token with spaces");
/// assert_eq!(result, "&X-Amz-Security-Token=token%20with%20spaces");
///
/// let result = security_token_string("token/with/slashes");
/// assert_eq!(result, "&X-Amz-Security-Token=token%2Fwith%2Fslashes")
/// ```
pub fn security_token_string(token: &str) -> String {
  format!("&X-Amz-Security-Token={}", utf8_percent_encode(token, FRAGMENT_SLASH))
}

/// Get the query params string. It is always ?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=credential&X-Amz-Date=long_date&X-Amz-Expires=expires&X-Amz-SignedHeaders=signed_headers.
/// The credential is always access_key/credential_scope_string(datetime, region, service) with percent encoding.
/// The datetime is always to_long_datetime(datetime).
///
/// # Examples
///
/// ```
/// use time::OffsetDateTime;
/// use common_s3_headers::aws_format::query_params_string;
///
/// let datetime = OffsetDateTime::from_unix_timestamp(0).unwrap();
/// let result = query_params_string(&["host", "x-amz-content-sha256", "x-amz-date"], "access_key", &datetime, "region", "service", 123);
/// assert_eq!(
///  result,
///  "?X-Amz-Algorithm=AWS4-HMAC-SHA256\
///  &X-Amz-Credential=access_key%2F19700101%2Fregion%2Fservice%2Faws4_request\
///  &X-Amz-Date=19700101T000000Z\
///  &X-Amz-Expires=123\
///  &X-Amz-SignedHeaders=host%3Bx-amz-content-sha256%3Bx-amz-date"
/// );
/// ```
pub fn query_params_string(
  signed_headers: &[&str],
  access_key: &str,
  datetime: &OffsetDateTime,
  region: &str,
  service: &str,
  expires: u32,
) -> String {
  let signed_headers = signed_headers.join(";");
  let signed_headers = utf8_percent_encode(&signed_headers, FRAGMENT_SLASH);

  let credentials = format!("{}/{}", access_key, credential_scope_string(datetime, region, service));
  let credentials = utf8_percent_encode(&credentials, FRAGMENT_SLASH);

  format!(
    "?X-Amz-Algorithm=AWS4-HMAC-SHA256\
          &X-Amz-Credential={credentials}\
          &X-Amz-Date={long_date}\
          &X-Amz-Expires={expires}\
          &X-Amz-SignedHeaders={signed_headers}",
    credentials = credentials,
    long_date = to_long_datetime(datetime),
    expires = expires,
    signed_headers = signed_headers,
  )
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::aws_canonical::to_canonical_headers;
  use common_testing::assert;
  use std::str::FromStr;

  #[test]
  fn to_short_datetime_works() {
    let datetime = OffsetDateTime::from_unix_timestamp(0).unwrap();
    let result = to_short_datetime(&datetime);
    assert_eq!(result, "19700101");

    let datetime = OffsetDateTime::from_unix_timestamp(1_000_000_000).unwrap();
    let result = to_short_datetime(&datetime);
    assert_eq!(result, "20010909");
  }

  #[test]
  fn to_long_datetime_works() {
    let datetime = OffsetDateTime::from_unix_timestamp(0).unwrap();
    let result = to_long_datetime(&datetime);
    assert_eq!(result, "19700101T000000Z");

    let datetime = OffsetDateTime::from_unix_timestamp(1_000_000_000).unwrap();
    let result = to_long_datetime(&datetime);
    assert_eq!(result, "20010909T014640Z");
  }

  #[test]
  fn uri_encode_works() {
    let result = uri_encode("foo", false);
    assert_eq!(result, "foo");

    let result = uri_encode("foo", true);
    assert_eq!(result, "foo");

    let result = uri_encode("foo bar", false);
    assert_eq!(result, "foo%20bar");

    let result = uri_encode("foo bar", true);
    assert_eq!(result, "foo%20bar");

    let result = uri_encode("foo/bar", false);
    assert_eq!(result, "foo/bar");

    let result = uri_encode("foo/bar", true);
    assert_eq!(result, "foo%2Fbar");

    let result = uri_encode("foo/bar/baz", false);
    assert_eq!(result, "foo/bar/baz");

    let result = uri_encode("foo/bar/baz", true);
    assert_eq!(result, "foo%2Fbar%2Fbaz");

    let result = uri_encode("foo/bar/baz/", false);
    assert_eq!(result, "foo/bar/baz/");

    let result = uri_encode("foo/bar/baz/", true);
    assert_eq!(result, "foo%2Fbar%2Fbaz%2F");
  }

  #[test]
  fn canonical_uri_string_when_empty() {
    let url = Url::from_str("http://localhost").unwrap();
    let result = canonical_uri_string(&url);
    assert::equal(result, "/");
  }

  #[test]
  fn canonical_uri_string_slash_percent_multiple() {
    let url = Url::parse("http://s3.amazonaws.com/bucket/Folder (xx)%=/Filename (xx)%=").unwrap();
    let canonical = canonical_uri_string(&url);
    assert_eq!("/bucket/Folder%20%28xx%29%25%3D/Filename%20%28xx%29%25%3D", canonical);
  }

  #[test]
  fn canonical_uri_string_when_plain_text() {
    let url = Url::from_str("http://localhost/some-url/?okay").unwrap();
    let result = canonical_uri_string(&url);
    assert::equal(result, "/some-url/");
  }

  #[test]
  fn canonical_uri_string_encode() {
    // Make sure parsing doesn't remove extra slashes, as normalization
    // will mess up the path lookup.
    let url = Url::parse("http://s3.amazonaws.com/examplebucket///foo//bar//baz").unwrap();
    let canonical = canonical_uri_string(&url);
    assert_eq!("/examplebucket///foo//bar//baz", canonical);
  }

  #[test]
  fn credential_scope_string_works() {
    let datetime = OffsetDateTime::from_unix_timestamp(0).unwrap();
    let result = credential_scope_string(&datetime, "us-east-1", "s3");
    assert_eq!(result, "19700101/us-east-1/s3/aws4_request");
  }

  #[test]
  fn canonical_request_string_works() {
    let url = Url::parse("https://examplebucket.s3.amazonaws.com/test.txt").unwrap();
    let headers = vec![
      ("x-amz-date", "20130524T000000Z"),
      ("Range", "bytes=0-9"),
      ("Host", "examplebucket.s3.amazonaws.com"),
      ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
    ];
    let canonical_headers = to_canonical_headers(&headers);
    let result = canonical_request_string("GET", &url, &canonical_headers, "UNSIGNED-PAYLOAD");
    assert_eq!(
      result,
      "GET\n\
      /test.txt\n\
      \n\
      host:examplebucket.s3.amazonaws.com\n\
      range:bytes=0-9\n\
      x-amz-content-sha256:UNSIGNED-PAYLOAD\n\
      x-amz-date:20130524T000000Z\n\
      \n\
      host;range;x-amz-content-sha256;x-amz-date\n\
      UNSIGNED-PAYLOAD"
    );
  }

  #[test]
  fn test_query_string_encode() {
    let url =
      Url::parse("http://s3.amazonaws.com/examplebucket?prefix=somePrefix&marker=someMarker&max-keys=20").unwrap();
    let canonical = canonical_query_string(&url);
    assert_eq!("marker=someMarker&max-keys=20&prefix=somePrefix", canonical);

    let url = Url::parse("http://s3.amazonaws.com/examplebucket?acl").unwrap();
    let canonical = canonical_query_string(&url);
    assert_eq!("acl=", canonical);

    let url = Url::parse("http://s3.amazonaws.com/examplebucket?key=with%20space&also+space=with+plus").unwrap();
    let canonical = canonical_query_string(&url);
    assert_eq!("also%20space=with%20plus&key=with%20space", canonical);

    let url = Url::parse("http://s3.amazonaws.com/examplebucket?key-with-postfix=something&key=").unwrap();
    let canonical = canonical_query_string(&url);
    assert_eq!("key=&key-with-postfix=something", canonical);

    let url = Url::parse("http://s3.amazonaws.com/examplebucket?key=c&key=a&key=b").unwrap();
    let canonical = canonical_query_string(&url);
    assert_eq!("key=a&key=b&key=c", canonical);
  }

  #[test]
  fn test_uri_encode() {
    assert_eq!(uri_encode(r#"~!@#$%^&*()-_=+[]\{}|;:'",.<>? привет 你好"#, true), "~%21%40%23%24%25%5E%26%2A%28%29-_%3D%2B%5B%5D%5C%7B%7D%7C%3B%3A%27%22%2C.%3C%3E%3F%20%D0%BF%D1%80%D0%B8%D0%B2%D0%B5%D1%82%20%E4%BD%A0%E5%A5%BD");
  }

  #[test]
  fn query_params_string_renders_expiry_and_signed_headers() {
    let datetime = OffsetDateTime::from_unix_timestamp(0).unwrap();
    let result = query_params_string(
      &["host", "x-amz-content-sha256", "x-amz-date"],
      "AKIAEXAMPLE",
      &datetime,
      "us-west-2",
      "s3",
      900,
    );
    // Algorithm + credential (region + expiry rendered) + signed-headers list.
    assert!(result.starts_with("?X-Amz-Algorithm=AWS4-HMAC-SHA256&"));
    assert!(result.contains("X-Amz-Credential=AKIAEXAMPLE%2F19700101%2Fus-west-2%2Fs3%2Faws4_request"));
    assert!(result.contains("X-Amz-Date=19700101T000000Z"));
    assert!(result.contains("X-Amz-Expires=900"));
    assert!(result.contains("X-Amz-SignedHeaders=host%3Bx-amz-content-sha256%3Bx-amz-date"));
  }

  #[test]
  fn security_token_string_percent_encodes_token() {
    // Special characters and spaces are percent-encoded with FRAGMENT_SLASH.
    assert_eq!(
      security_token_string("a/b c"),
      "&X-Amz-Security-Token=a%2Fb%20c"
    );
    assert_eq!(security_token_string("plain"), "&X-Amz-Security-Token=plain");
  }

  #[test]
  fn canonical_request_orders_headers_alphabetically() {
    // Headers supplied out of order must be sorted in the canonical request.
    let url = Url::parse("https://examplebucket.s3.amazonaws.com/k").unwrap();
    let headers = vec![
      ("X-Amz-Date", "20240101T000000Z".to_owned()),
      ("Host", "examplebucket.s3.amazonaws.com".to_owned()),
      (
        "x-amz-content-sha256",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned(),
      ),
    ];
    let canonical = to_canonical_headers(&headers);
    let keys: Vec<&str> = canonical.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
      keys,
      vec!["host", "x-amz-content-sha256", "x-amz-date"],
      "canonical headers must be lowercase and sorted"
    );
  }
}
