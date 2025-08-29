use std::collections::HashMap;

#[derive(Debug)]
pub enum HttpRequest {
    Request {
        method: String,
        url: String,
        headers: HashMap<String, String>,
        body: Option<String>,
    },
    Response {
        status: String,
        headers: HashMap<String, String>,
        body: Option<String>,
    },
}

pub fn parse_http_data(data: &str, is_outgoing: bool) -> Option<HttpRequest> {
    let lines: Vec<&str> = data.lines().collect();
    if lines.is_empty() {
        return None;
    }
    
    if is_outgoing {
        parse_http_request(data)
    } else {
        parse_http_response(data)
    }
}

fn parse_http_request(data: &str) -> Option<HttpRequest> {
    let mut headers = httparse::Request::new(&mut []);
    let mut header_buf = [httparse::Header { name: "", value: &[] }; 64];
    headers.headers = &mut header_buf;
    
    match headers.parse(data.as_bytes()) {
        Ok(httparse::Status::Complete(_)) => {
            let method = headers.method?.to_string();
            let path = headers.path?.to_string();
            
            let mut header_map = HashMap::new();
            for header in headers.headers.iter() {
                if !header.name.is_empty() {
                    let value = String::from_utf8_lossy(header.value);
                    header_map.insert(header.name.to_string(), value.to_string());
                }
            }
            
            // Try to construct full URL
            let host = header_map.get("Host")
                .or_else(|| header_map.get("host"))
                .map(|h| h.as_str())
                .unwrap_or("unknown");
                
            let url = if path.starts_with("http") {
                path
            } else {
                format!("http://{}{}", host, path)
            };
            
            Some(HttpRequest::Request {
                method,
                url,
                headers: header_map,
                body: None, // TODO: Parse body if needed
            })
        }
        _ => None,
    }
}

fn parse_http_response(data: &str) -> Option<HttpRequest> {
    let mut response = httparse::Response::new(&mut []);
    let mut header_buf = [httparse::Header { name: "", value: &[] }; 64];
    response.headers = &mut header_buf;
    
    match response.parse(data.as_bytes()) {
        Ok(httparse::Status::Complete(_)) => {
            let status = format!("{} {}", 
                response.code?, 
                response.reason.unwrap_or("Unknown")
            );
            
            let mut header_map = HashMap::new();
            for header in response.headers.iter() {
                if !header.name.is_empty() {
                    let value = String::from_utf8_lossy(header.value);
                    header_map.insert(header.name.to_string(), value.to_string());
                }
            }
            
            Some(HttpRequest::Response {
                status,
                headers: header_map,
                body: None, // TODO: Parse body if needed
            })
        }
        _ => None,
    }
}
