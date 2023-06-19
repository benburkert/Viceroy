use hyper::{header, HeaderMap};

pub fn filter_outgoing_headers(headers: &mut HeaderMap) {
    // Remove framing-related headers; we rely on Hyper to insert the appropriate
    // framing headers automatically, and do not allow guests to include them.
    headers.remove(header::CONTENT_LENGTH);
    headers.remove(header::TRANSFER_ENCODING);

    // Re-join Cookie headers split by http/2: https://github.com/hyperium/hyper/issues/2528
    let cookies = headers
        .get_all(header::COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect::<Vec<&str>>();

    if cookies.len() > 1 {
        let cookie = header::HeaderValue::from_str(cookies.join("; ").as_str()).unwrap();
        headers.insert(header::COOKIE, cookie);
    }
}
