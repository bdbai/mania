use std::env;

use crate::core::http;
use crate::core::sign::{SignProvider, SignResult};
use crate::utility::extensions::HexString;
use bytes::Bytes;
use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(not(unix))]
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::{UnixSocket, UnixStream};
use tokio::sync::Mutex;

#[cfg(unix)]
type SockStream = UnixStream;
#[cfg(not(unix))]
type SockStream = TcpStream;

#[derive(Serialize)]
struct SignServerReq {
    cmd: String,
    seq: u32,
    src: String,
}

#[derive(Deserialize)]
struct SignServerResp {
    value: SignResult,
    platform: String,
    version: String,
}

pub struct LinuxSignProvider {
    pub url: Option<String>,
    pub sock: Mutex<Option<SockStream>>,
}

impl SignProvider for LinuxSignProvider {
    fn sign_impl(&self, cmd: &str, seq: u32, body: &[u8]) -> Option<SignResult> {
        if let Some("sock") = env::var("MANIA_LINUX_SIGN_MODE").ok().as_deref() {
            self.sign_impl_sock(cmd, seq, body)
        } else {
            self.sign_impl_http(cmd, seq, body)
        }
    }
}

impl LinuxSignProvider {
    #[cfg(unix)]
    async fn connect_sock() -> UnixStream {
        let socket = UnixSocket::new_stream().unwrap();
        let sock_file = env::var("MANIA_LINUX_SIGN_SOCK").unwrap();
        let stream = socket.connect(sock_file).await.unwrap();
        stream
    }
    #[cfg(not(unix))]
    async fn connect_sock() -> TcpStream {
        use tokio::net::TcpSocket;

        let socket = TcpSocket::new_v4().unwrap();
        let addr = env::var("MANIA_LINUX_SIGN_SOCK").unwrap().parse().unwrap();
        socket.connect(addr).await.unwrap()
    }
    fn sign_impl_sock(&self, cmd: &str, seq: u32, body: &[u8]) -> Option<SignResult> {
        tracing::debug!(
            "sign request: cmd={}, seq={}, body={}",
            cmd,
            seq,
            body.hex()
        );
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let mut socket_guard = self.sock.lock().await;
                let mut socket = if let Some(socket) = &mut *socket_guard {
                    socket
                } else {
                    let new_socket = Self::connect_sock().await;
                    socket_guard.insert(new_socket)
                };
                // 0x1 + length of body in 4 bytes (network order) + 4 bytes seq + null terminated cmd + body
                let mut req = Vec::with_capacity(1 + 4 + 4 + cmd.len() + 1 + body.len());
                req.push(0x1);
                let body_len = (4 + cmd.len() + 1 + body.len()) as u32;
                req.extend_from_slice(&body_len.to_be_bytes());
                req.extend_from_slice(&seq.to_be_bytes());
                req.extend_from_slice(cmd.as_bytes());
                req.push(0);
                req.extend_from_slice(body);
                if let Err(e) = socket.write_all(&req).await {
                    tracing::error!("failed to write to sign socket, reconnecting: {}", e);
                    socket = socket_guard.insert(Self::connect_sock().await);
                    socket.write_all(&req).await.unwrap();
                }
                let str1_len = socket.read_u32().await.unwrap();
                let str2_len = socket.read_u32().await.unwrap();
                let str3_len = socket.read_u32().await.unwrap();
                let mut resp = vec![0; (str1_len + str2_len + str3_len) as usize];
                socket.read_exact(&mut resp).await.unwrap();
                let res = SignResult {
                    token: String::from_utf8_lossy(&resp[0..str1_len as usize]).into(),
                    extra: Bytes::copy_from_slice(
                        &resp[str1_len as usize..(str1_len + str2_len) as usize],
                    ),
                    sign: Bytes::copy_from_slice(&resp[(str1_len + str2_len) as usize..]),
                };
                tracing::debug!(
                    "sign response for seq {}: token={}, extra={}, sign={}",
                    seq,
                    res.token,
                    res.extra.hex(),
                    res.sign.hex()
                );
                Some(res)
            })
        })
    }
    fn sign_impl_http(&self, cmd: &str, seq: u32, body: &[u8]) -> Option<SignResult> {
        let dummy_sign = || -> SignResult {
            SignResult {
                sign: Bytes::from(&[0u8; 20][..]),
                extra: Bytes::new(),
                token: String::new(),
            }
        };
        match self.url.as_ref() {
            Some(url) => {
                let request_body = SignServerReq {
                    cmd: cmd.to_string(),
                    seq,
                    src: body.hex(),
                };
                let payload = match serde_json::to_vec(&request_body) {
                    Ok(payload) => payload,
                    Err(e) => {
                        tracing::error!("failed to serialize SignServerReq: {}", e);
                        return Some(dummy_sign());
                    }
                };
                let response = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        let mut headers = HeaderMap::new();
                        headers.insert("Content-Type", "application/json".parse().unwrap());
                        http::client()
                            .post_binary_async(url.as_str(), &payload, Some(headers))
                            .await
                    })
                });
                let resp: Option<SignServerResp> = match response {
                    Ok(resp) => match serde_json::from_slice(&resp) {
                        Ok(resp) => Some(resp),
                        Err(e) => {
                            tracing::error!("failed to deserialize SignServerResp: {}", e);
                            None
                        }
                    },
                    Err(e) => {
                        tracing::error!("failed to send request to sign server: {}", e);
                        None
                    }
                };
                resp.map(|r| r.value).or_else(|| Some(dummy_sign()))
            }
            None => {
                tracing::warn!("sign server url is not set, using dummy sign");
                Some(dummy_sign())
            }
        }
    }
}
