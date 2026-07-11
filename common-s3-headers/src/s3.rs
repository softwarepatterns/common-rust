use crate::{aws_canonical, aws_format, aws_math};
use hmac::Mac;
use std::borrow::Cow;
use url::Url;

pub const EMPTY_PAYLOAD_SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// The payload-hash value used for presigned URLs. A presigned GET does not hash
/// the request body; S3 accepts `UNSIGNED-PAYLOAD`.
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

#[derive(Debug, Default, Clone, Copy)]
pub enum S3DateTime {
  #[default]
  Now,
  UnixTimestamp(i64),
}

impl S3DateTime {
  pub fn get_offset_datetime(&self) -> time::OffsetDateTime {
    match self {
      S3DateTime::Now => time::OffsetDateTime::now_utc(),
      S3DateTime::UnixTimestamp(timestamp) => {
        time::OffsetDateTime::from_unix_timestamp(*timestamp).expect("Always valid")
      }
    }
  }
}

#[derive(Debug, Clone)]
pub struct S3HeadersBuilder<'a> {
  pub datetime: S3DateTime,
  pub access_key: &'a str,
  pub secret_key: &'a str,
  pub region: &'a str,
  pub service: &'a str,
  pub url: &'a Url,
  pub method: &'a str,
  pub headers: &'a [(&'static str, std::string::String)],
  pub payload_hash: Cow<'a, str>,
}

impl<'a> S3HeadersBuilder<'a> {
  pub fn new(url: &'a Url) -> Self {
    Self {
      datetime: Default::default(),
      access_key: Default::default(),
      secret_key: Default::default(),
      region: Default::default(),
      service: Default::default(),
      url,
      method: Default::default(),
      headers: Default::default(),
      payload_hash: Cow::Borrowed(EMPTY_PAYLOAD_SHA),
    }
  }

  pub fn set_access_key(mut self, value: &'a str) -> Self {
    self.access_key = value;
    self
  }

  pub fn set_secret_key(mut self, value: &'a str) -> Self {
    self.secret_key = value;
    self
  }

  pub fn set_region(mut self, value: &'a str) -> Self {
    self.region = value;
    self
  }
  pub fn set_datetime(mut self, value: S3DateTime) -> Self {
    self.datetime = value;
    self
  }

  pub fn set_payload_hash(mut self, value: &'a str) -> Self {
    self.payload_hash = Cow::Borrowed(value);
    self
  }

  pub fn set_payload_hash_with_content(mut self, content: &[u8]) -> Self {
    let sha = aws_math::get_sha256(content);
    self.payload_hash = Cow::Owned(sha);
    self
  }

  pub fn set_method(mut self, value: &'a str) -> Self {
    self.method = value;
    self
  }

  pub fn set_service(mut self, value: &'a str) -> Self {
    self.service = value;
    self
  }

  pub fn set_url(mut self, url: &'a Url) -> Self {
    self.url = url;
    self
  }

  pub fn set_headers(mut self, headers: &'a [(&'static str, std::string::String)]) -> Self {
    self.headers = headers;
    self
  }

  pub fn build(self) -> Vec<(&'static str, String)> {
    get_headers(self)
  }
}

/// Gets all the headers necessary to make a request to a AWS compatible service.
pub fn get_headers(options: S3HeadersBuilder) -> Vec<(&'static str, String)> {
  let url = options.url;
  let payload_hash = &options.payload_hash;
  let datetime = options.datetime.get_offset_datetime();
  let amz_date = aws_format::to_long_datetime(&datetime);

  let mut headers: Vec<(&'static str, String)> = [
    options.headers,
    &[
      ("Host", url.host_str().unwrap().to_owned()),
      ("x-amz-content-sha256", payload_hash.to_string()),
      ("x-amz-date", amz_date),
    ],
  ]
  .concat();

  let auth_header = get_authorization_header(options.set_headers(&headers));

  headers.push(("Authorization", auth_header));
  headers
}

/// Gets the headers necessary to ask for a byte range.
pub fn get_range_headers(start: u64, end: Option<u64>) -> Vec<(&'static str, String)> {
  let mut range = format!("bytes={}-", start);

  if let Some(end) = end {
    range.push_str(&end.to_string());
  }

  let headers: Vec<(&'static str, String)> = vec![("Accept", "application/octet-stream".to_string()), ("Range", range)];
  headers
}

/// Only gets the authorirzation header.
pub fn get_authorization_header(options: S3HeadersBuilder) -> String {
  let datetime = options.datetime.get_offset_datetime();
  let region = options.region;
  let access_key = options.access_key;
  let secret_key = options.secret_key;
  let service = options.service;
  let url = options.url;
  let method = options.method;
  let payload_hash = options.payload_hash;
  let canonical_headers = aws_canonical::to_canonical_headers(options.headers);
  let canonical_request = aws_format::canonical_request_string(method, url, &canonical_headers, &payload_hash);

  let string_to_sign = aws_format::string_to_sign(&datetime, region, service, &canonical_request);
  let signing_key = aws_math::get_signature_key(&datetime, secret_key, region, service);

  let hmac: aws_math::HmacSha256 = aws_math::sign(&signing_key, string_to_sign.as_bytes());
  let signature = hex::encode(hmac.finalize().into_bytes());
  let signed_headers = aws_format::get_keys(&canonical_headers).join(";");

  aws_format::authorization_header_string(access_key, &datetime, region, service, &signed_headers, &signature)
}

/// Build a presigned GET URL for downloading `url` directly from an
/// S3-compatible service.
///
/// The returned URL carries AWS SigV4 query-parameter authentication. The holder
/// may GET the object until the signature expires, with no further credentials.
/// Only the `host` header is signed, and the request body is not hashed
/// (`UNSIGNED-PAYLOAD`) — the correct choices for a download URL.
///
/// `expires` is the URL lifetime in seconds; S3 rejects values outside
/// `1..=604800` (7 days).
pub fn presign_get(
  url: &Url,
  access_key: &str,
  secret_key: &str,
  region: &str,
  service: &str,
  datetime: S3DateTime,
  expires: u32,
) -> String {
  let datetime = datetime.get_offset_datetime();
  let host = host_with_port(url);
  let canonical_uri = aws_format::canonical_uri_string(url);

  // The presign query params (X-Amz-Algorithm … X-Amz-SignedHeaders), already
  // alphabetical and percent-encoded. They are returned with a leading '?';
  // strip it to form the canonical query string used for signing.
  let presign_query = aws_math::authorization_query_params_no_sig(
    access_key,
    &datetime,
    region,
    service,
    expires,
    None,
    None,
  );
  let canonical_query = presign_query.strip_prefix('?').unwrap_or(&presign_query);

  // The canonical request for a presigned URL: GET, the canonical URI, the
  // presign query params as the canonical query, the host header only, and
  // UNSIGNED-PAYLOAD. X-Amz-Signature is appended after signing and is not part
  // of the canonical request.
  let canonical_request = format!(
    "GET\n{canonical_uri}\n{canonical_query}\nhost:{host}\n\nhost\n{UNSIGNED_PAYLOAD}",
  );

  let string_to_sign = aws_format::string_to_sign(&datetime, region, service, &canonical_request);
  let signing_key = aws_math::get_signature_key(&datetime, secret_key, region, service);
  let hmac = aws_math::sign(&signing_key, string_to_sign.as_bytes());
  let signature = hex::encode(hmac.finalize().into_bytes());

  format!(
    "{}://{host}{canonical_uri}?{canonical_query}&X-Amz-Signature={signature}",
    url.scheme(),
  )
}

/// Render the URL's host with its port when one is present, so the signed `host`
/// header matches what the client actually sends. Required for non-default ports
/// such as local S3-compatible services.
fn host_with_port(url: &Url) -> String {
  let host = url.host_str().expect("url must have a host");
  match url.port() {
    Some(port) => format!("{host}:{port}"),
    None => host.to_string(),
  }
}
