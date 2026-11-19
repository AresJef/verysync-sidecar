//! Test-only authenticated SOCKS5 peer with exactly one owned loopback upstream.
use super::managed_fixture::TestResult;
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::{JoinHandle, JoinSet},
};

#[derive(Default)]
struct Counts {
    refused: AtomicUsize,
    authenticated: AtomicUsize,
    forwarded: AtomicUsize,
}
pub struct Socks5Peer {
    address: SocketAddr,
    counts: Arc<Counts>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<std::io::Result<()>>>,
}
impl Socks5Peer {
    pub async fn start(upstream: SocketAddr) -> TestResult<Self> {
        if upstream.ip() != Ipv4Addr::LOCALHOST || matches!(upstream.port(), 0 | 18886) {
            return Err("only the exact task-owned loopback core can be forwarded".into());
        }
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        if address.port() == 18886 {
            return Err("reserved live-instance port refused".into());
        }
        let counts = Arc::new(Counts::default());
        let shared = counts.clone();
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _=&mut stopped=>break,
                    incoming=listener.accept()=>{
                        let (socket,_)=incoming?;
                        if connections.len()>=32 { return Err(std::io::Error::other("owned SOCKS5 connection bound exceeded")); }
                        let counts=shared.clone();
                        connections.spawn(async move {
                            let _=serve(socket,upstream,counts).await;
                        });
                    },
                    result=connections.join_next(),if !connections.is_empty()=>{
                        if result.is_some_and(|v|v.is_err()) { return Err(std::io::Error::other("owned SOCKS5 task panicked")); }
                    }
                }
            }
            connections.abort_all();
            while connections.join_next().await.is_some() {}
            Ok(())
        });
        Ok(Self {
            address,
            counts,
            stop: Some(stop),
            task: Some(task),
        })
    }
    pub fn authority(&self, password: &str) -> String {
        format!("proxy-user:{password}@{}", self.address)
    }
    pub fn counts(&self) -> (usize, usize, usize) {
        (
            self.counts.refused.load(Ordering::SeqCst),
            self.counts.authenticated.load(Ordering::SeqCst),
            self.counts.forwarded.load(Ordering::SeqCst),
        )
    }
    pub async fn close(mut self) -> TestResult {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.await??;
        }
        Ok(())
    }
}
impl Drop for Socks5Peer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
async fn serve(
    mut client: TcpStream,
    upstream: SocketAddr,
    counts: Arc<Counts>,
) -> std::io::Result<()> {
    let handshake = async {
        let mut header = [0; 2];
        client.read_exact(&mut header).await?;
        if header[0] != 5 || header[1] == 0 || header[1] > 16 {
            return Err(std::io::Error::other("invalid SOCKS5 greeting"));
        }
        let mut methods = vec![0; usize::from(header[1])];
        client.read_exact(&mut methods).await?;
        if !methods.contains(&2) {
            client.write_all(&[5, 255]).await?;
            return Ok(false);
        }
        client.write_all(&[5, 2]).await?;
        client.read_exact(&mut header).await?;
        if header[0] != 1 || header[1] == 0 {
            return Err(std::io::Error::other(
                "invalid SOCKS5 auth version or user length",
            ));
        }
        let mut user = vec![0; usize::from(header[1])];
        client.read_exact(&mut user).await?;
        let len = client.read_u8().await?;
        let mut password = vec![0; usize::from(len)];
        client.read_exact(&mut password).await?;
        if user != b"proxy-user" || password != b"private@token" {
            counts.refused.fetch_add(1, Ordering::SeqCst);
            client.write_all(&[1, 1]).await?;
            return Ok(false);
        }
        counts.authenticated.fetch_add(1, Ordering::SeqCst);
        client.write_all(&[1, 0]).await?;
        let mut request = [0; 4];
        client.read_exact(&mut request).await?;
        if request[..3] != [5, 1, 0] {
            return Err(std::io::Error::other("only SOCKS5 CONNECT is supported"));
        }
        let target_matches = match request[3] {
            1 => {
                let mut ip = [0; 4];
                client.read_exact(&mut ip).await?;
                ip == [198, 51, 100, 17]
            }
            3 => {
                let n = client.read_u8().await?;
                let mut name = vec![0; usize::from(n)];
                client.read_exact(&mut name).await?;
                name == b"198.51.100.17"
            }
            _ => false,
        };
        if !target_matches || client.read_u16().await? != 22000 {
            return Err(std::io::Error::other(
                "only the fixed synthetic destination is allowed",
            ));
        }
        Ok(true)
    };
    if !tokio::time::timeout(Duration::from_secs(5), handshake).await?? {
        return Ok(());
    }
    // No DNS, external connection, caller-provided target or general proxying.
    let mut server = TcpStream::connect(upstream).await?;
    client.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1]).await?;
    counts.forwarded.fetch_add(1, Ordering::SeqCst);
    let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
    Ok(())
}
