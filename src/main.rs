use log::LevelFilter;
use log4rs::{
    config::{Appender, Config, Root},
    encode::pattern::PatternEncoder,
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

#[cfg(debug_assertions)]
use log4rs::append::console::ConsoleAppender;
#[cfg(not(debug_assertions))]
use log4rs::append::file::FileAppender;

mod dns;
mod resolve;

#[tokio::main]
async fn main() {
    let _ = dotenv::dotenv();

    const FORMAT: &str = "[{d(%H:%M:%S)}] {l}: {t} - {m}\n";

    #[cfg(not(debug_assertions))]
    let log_target = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(FORMAT)))
        .build("/var/log/nukedns.log")
        .unwrap();

    println!("Logging to /var/log/nukedns.log");
    #[cfg(debug_assertions)]
    let log_target = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(FORMAT)))
        .build();

    let config = Config::builder()
        .appender(Appender::builder().build("log_target", Box::new(log_target)))
        .build(
            Root::builder()
                .appender("log_target")
                .build(LevelFilter::Info),
        )
        .unwrap();

    log4rs::init_config(config).unwrap();

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
