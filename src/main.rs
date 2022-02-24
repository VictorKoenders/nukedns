use log::LevelFilter;
use log4rs::{
    config::{Appender, Root},
    encode::pattern::PatternEncoder,
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

    let config = log4rs::Config::builder()
        .appender(Appender::builder().build("log_target", Box::new(log_target)))
        .build(
            Root::builder()
                .appender("log_target")
                .build(LevelFilter::Info),
        )
        .unwrap();

    log4rs::init_config(config).unwrap();

    let config = Config::load();

    resolve::init().await;
    let handles = dns::spawn(config);
    let _ = futures::future::select_all(handles).await;
}

#[derive(serde::Deserialize)]
pub struct Config {
    pub host: Vec<ConfigHost>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            host: vec![ConfigHost {
                address: "0.0.0.0".to_string(),
                port: 25,
            }],
        }
    }
}

impl Config {
    pub fn load() -> Config {
        #[cfg(debug_assertions)]
        let path = "./nukedns.toml";
        #[cfg(not(debug_assertions))]
        let path = "/etc/nukedns.toml";

        fn load(path: &str) -> Option<Config> {
            let contents = std::fs::read_to_string(path).ok()?;
            toml::from_str(&contents).ok()
        }
        load(path).unwrap_or_default()
    }
}

#[derive(serde::Deserialize)]
pub struct ConfigHost {
    pub address: String,
    pub port: u16,
}
