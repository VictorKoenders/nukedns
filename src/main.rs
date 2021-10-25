use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

mod dns;
mod resolve;

#[tokio::main]
async fn main() {
    let _ = dotenv::dotenv();
    pretty_env_logger::init();

    resolve::init().await;
    dns::spawn(&[get_desired_bind_addr()]);
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

fn get_desired_bind_addr() -> SocketAddr {
    let addr = if let Some(addr) = std::env::var("HOST")
        .ok()
        .and_then(|host| host.parse().ok())
    {
        addr
    } else if let Ok(addr) = local_ip_address::local_ip() {
        addr
    } else {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    };

    let port = if let Some(port) = std::env::var("PORT").ok().and_then(|p| p.parse().ok()) {
        port
    } else {
        53u16
    };

    (addr, port).into()
}
