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
    accepted: AtomicUsize,
    refused: AtomicUsize,
    authenticated: AtomicUsize,
    forwarded: AtomicUsize,
}
pub struct Socks5Peer {
    address: SocketAddr,
    upstream: SocketAddr,
    counts: Arc<Counts>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<std::io::Result<TcpListener>>>,
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
        Ok(Self::serve_listener(listener, address, upstream))
    }

    fn serve_listener(listener: TcpListener, address: SocketAddr, upstream: SocketAddr) -> Self {
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
                        shared.accepted.fetch_add(1, Ordering::SeqCst);
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
            Ok(listener)
        });
        Self {
            address,
            upstream,
            counts,
            stop: Some(stop),
            task: Some(task),
        }
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

    pub fn accepted(&self) -> usize {
        self.counts.accepted.load(Ordering::SeqCst)
    }

    /// Keep watching the original proxy port after its only sender has exited.
    pub async fn reset_after_sender_exit(mut self) -> TestResult<Self> {
        let listener = self.stop_listener().await?.into_std()?;
        // All old connection tasks are gone. Drain any sockets the old sender
        // placed in the kernel queue before we count the new generation.
        for _ in 0..=32 {
            match listener.accept() {
                Ok((socket, _)) => drop(socket),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    let listener = TcpListener::from_std(listener)?;
                    return Ok(Self::serve_listener(listener, self.address, self.upstream));
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err("old SOCKS5 connection queue exceeded its bounds".into())
    }

    pub async fn close(mut self) -> TestResult {
        self.stop_listener().await?;
        Ok(())
    }

    async fn stop_listener(&mut self) -> TestResult<TcpListener> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        Ok(self
            .task
            .take()
            .ok_or("owned SOCKS5 listener task missing")?
            .await??)
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
