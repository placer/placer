//! placer-source-http: fetch placer packs over HTTP(S)

#![crate_name = "placer_source_http"]
#![deny(missing_docs, unsafe_code, unused_import_braces, unused_qualifications)]

use bytes::Bytes;
use failure::{bail, Error};
use rand::Rng;
use reqwest::header::{HeaderMap, ETAG};
use reqwest::Client as HttpClient;
use reqwest::{Response, StatusCode};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::time::Duration;
use std::{io, process, thread};

#[tokio::main]
async fn main() {
    let version = env!("CARGO_PKG_VERSION");

    // Send source worker greeting
    println!("OK placer-source-http {} started", version);

    let urls = read_urls_from_stdin();

    let mut resources: Vec<Resource> = urls.iter().map(|url| Resource::new(url)).collect();

    while let Some(resource) = resources.pop() {
        worker_loop(resource).await;
    }
}

fn read_urls_from_stdin() -> Vec<String> {
    let mut urls = vec![];

    loop {
        let mut line = String::new();

        io::stdin().read_line(&mut line).unwrap_or_else(|e| {
            eprintln!("error reading URLs to fetch from STDIN: {}", e);
            process::exit(1);
        });

        // Remove trailing newline
        let len = line.trim_end().len();
        line.truncate(len);

        if line.is_empty() {
            return urls;
        } else {
            urls.push(line);
        }
    }
}

async fn worker_loop(mut resource: Resource) {
    loop {
        match resource.fetch().await {
            Ok(Some(body)) => {
                let stdout = io::stdout();
                let mut handle = stdout.lock();
                handle
                    .write_all(format!("{} {}\n", body.len(), resource.url).as_bytes())
                    .unwrap();
                handle.write_all(&body).unwrap();
                handle.write_all(b"\n").unwrap();
                handle.flush().unwrap();
            }
            Ok(None) => (),
            Err(e) => eprintln!("error fetching URL: {} {}", resource.url, e),
        }

        let jitter = rand::thread_rng().gen_range(1, 15);
        thread::sleep(Duration::from_millis(jitter * 1000));
    }
}

#[derive(Debug, PartialEq)]
struct ResourceHash([u8; 32]);

impl ResourceHash {
    pub fn digest(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::default();
        hasher.input(bytes);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(hasher.result().as_slice());
        ResourceHash(hash)
    }
}

struct Resource {
    pub etag: Option<String>,
    pub url: String,
    pub sha256: Option<ResourceHash>,
}

impl Resource {
    fn new(url: &str) -> Self {
        Self {
            etag: None,
            url: url.to_owned(),
            sha256: None,
        }
    }

    async fn fetch(&mut self) -> Result<Option<Bytes>, Error> {
        let mut headers = HeaderMap::new();
        if let Some(ref etag) = self.etag {
            headers.insert("Cache-Control", "max-age=0".parse()?);
            headers.insert("If-None-Match", etag.parse()?);
        }

        let response = HttpClient::new()
            .get(&self.url)
            .headers(headers)
            .send()
            .await?;

        match response.status() {
            StatusCode::NOT_MODIFIED => Ok(None),
            StatusCode::OK => {
                self.handle_etag(&response);
                let body = response.bytes().await?;
                let hash = ResourceHash::digest(&body);
                if let Some(ref h) = self.sha256 {
                    if h == &hash {
                        return Ok(None);
                    }
                }
                self.sha256 = Some(hash);
                Ok(Some(body))
            }
            e => bail!("Unexpected status code: {}", e),
        }
    }

    fn handle_etag(&mut self, response: &Response) {
        if let Some(etag) = response.headers().get(ETAG) {
            self.etag = Some(etag.to_str().unwrap().to_owned());
        }
    }
}
