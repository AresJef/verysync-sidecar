//! Test-only TCP forwarding between explicit private loopback peers.
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::{JoinHandle, JoinSet},
};

#[derive(Default)]
struct Counts {
    accepted: AtomicUsize,
    completed: AtomicUsize,
    connected: AtomicUsize,
}
pub struct PeerProxy {
    address: SocketAddr,
    counts: Arc<Counts>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<std::io::Result<()>>>,
}
impl PeerProxy {
    pub async fn start(upstream: &str) -> std::io::Result<Self> {
        let target: SocketAddr = upstream
            .strip_prefix("tcp://")
            .ok_or_else(|| std::io::Error::other("explicit private TCP peer required"))?
            .parse()
            .map_err(|_| std::io::Error::other("private peer address invalid"))?;
        if target.ip() != std::net::IpAddr::V4(Ipv4Addr::LOCALHOST)
            || target.port() == 0
            || target.port() == 18886
        {
            return Err(std::io::Error::other(
                "only exact private loopback peer is allowed",
            ));
        }
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let counts = Arc::new(Counts::default());
        let shared = counts.clone();
        let (stop, mut stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    _=&mut stopped=>break,
                    incoming=listener.accept()=>{
                        let (mut client,_)=incoming?;
                        if connections.len()>=64 {return Err(std::io::Error::other("private peer connection bound exceeded"));}
                        shared.accepted.fetch_add(1,Ordering::SeqCst);
                        let counts=shared.clone();
                        connections.spawn(async move {
                            if let Ok(mut server)=TcpStream::connect(target).await {
                                counts.connected.fetch_add(1,Ordering::SeqCst);
                                // Only forward to the known task-owned loopback core.
                                let _=tokio::io::copy_bidirectional(&mut client,&mut server).await;
                            }
                            counts.completed.fetch_add(1,Ordering::SeqCst);
                        });
                    },
                    result=connections.join_next(),if !connections.is_empty()=>{
                        if result.is_some_and(|v|v.is_err()) {return Err(std::io::Error::other("private peer forwarding task failed"));}
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
    pub fn address(&self) -> String {
        format!("tcp://{}", self.address)
    }
    pub fn attempts(&self) -> (usize, usize) {
        (
            self.counts.accepted.load(Ordering::SeqCst),
            self.counts.completed.load(Ordering::SeqCst),
        )
    }
    pub fn upstream_connections(&self) -> usize {
        self.counts.connected.load(Ordering::SeqCst)
    }
    pub async fn close(mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.await??;
        }
        Ok(())
    }
}
impl Drop for PeerProxy {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
