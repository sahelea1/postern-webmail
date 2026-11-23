//! Postern: a small webmail gateway. See README.md.
#![forbid(unsafe_code)]

mod admin;
mod api;
mod assets;
mod backend;
mod config;
mod error;
mod message;
mod seal;
mod smime;
mod state;

use axum::{Router, middleware, routing::get};
use config::{Config, Servers};
use state::AppState;
use std::{net::SocketAddr, process::ExitCode, time::Duration};

const USAGE: &str = "Postern webmail gateway

Usage:
  postern [run]        start the server (default)
  postern admin-link   print a single-use link for the admin console
  postern check        validate servers.toml and exit
  postern healthcheck  exit 0 if the local server answers (for container health checks)
  postern version      print the version

Settings are read from environment variables; see README.md.";

fn load_servers(cfg: &Config) -> Result<Servers, String> {
    let path = cfg.servers_file();
    match std::fs::read_to_string(&path) {
        Ok(text) => Servers::parse(&text).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Servers::default()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// First start only: copies the starter list named by POSTERN_SERVERS_SEED into
/// the data directory. An existing servers.toml is never touched, so changes
/// made in the admin console survive restarts and image rebuilds.
fn seed_servers(cfg: &Config) -> Result<(), String> {
    let Some(seed) = std::env::var_os("POSTERN_SERVERS_SEED").filter(|v| !v.is_empty()) else {
        return Ok(());
    };
    let dest = cfg.servers_file();
    if cfg.servers_file.is_some() || dest.exists() {
        return Ok(());
    }
    let seed = std::path::PathBuf::from(seed);
    let text = match std::fs::read_to_string(&seed) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!("POSTERN_SERVERS_SEED: {} not found, skipped", seed.display());
            return Ok(());
        }
        Err(e) => return Err(format!("{}: {e}", seed.display())),
    };
    let servers = Servers::parse(&text).map_err(|e| format!("{}: {e}", seed.display()))?;
    let tmp = dest.with_extension("toml.tmp");
    std::fs::write(&tmp, text)
        .and_then(|_| std::fs::rename(&tmp, &dest))
        .map_err(|e| format!("{}: {e}", dest.display()))?;
    tracing::info!(
        count = servers.servers.len(),
        "first start: server list copied from {}",
        seed.display()
    );
    Ok(())
}

fn main() -> ExitCode {
    let arg = std::env::args().nth(1).unwrap_or_else(|| "run".into());
    let cfg = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration error: {e}");
            return ExitCode::from(2);
        }
    };
    match arg.as_str() {
        "version" | "--version" | "-V" => {
            println!("postern {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        "help" | "--help" | "-h" => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        "check" => match load_servers(&cfg) {
            Ok(s) => {
                println!(
                    "{}: {} server(s), valid",
                    cfg.servers_file().display(),
                    s.servers.len()
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        },
        "admin-link" => match admin::mint_token(&cfg.data_dir) {
            Ok(token) => {
                println!(
                    "{}/login?token={token}",
                    cfg.admin_url.trim_end_matches('/')
                );
                println!("Valid for 10 minutes, works once.");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        },
        "healthcheck" => {
            if healthcheck(&cfg) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        "run" => match run(cfg) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("fatal: {e}");
                ExitCode::FAILURE
            }
        },
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// Asks the local server for /healthz over plain TCP. No shell or curl needed in the image.
fn healthcheck(cfg: &Config) -> bool {
    use std::io::{Read, Write};
    let port = cfg.listen.port();
    let Ok(mut s) = std::net::TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_secs(3),
    ) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
    if s.write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf).unwrap_or(0);
    buf[..n].starts_with(b"HTTP/1.0 200") || buf[..n].starts_with(b"HTTP/1.1 200")
}

fn run(cfg: Config) -> Result<(), String> {
    let level = std::env::var("POSTERN_LOG")
        .ok()
        .and_then(|l| l.parse::<tracing::Level>().ok())
        .unwrap_or(tracing::Level::INFO);
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_ansi(false)
        .with_target(false)
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();

    std::fs::create_dir_all(&cfg.data_dir)
        .map_err(|e| format!("cannot create {}: {e}", cfg.data_dir.display()))?;
    let sealer = seal::Sealer::load(&cfg.data_dir)?;
    seed_servers(&cfg)?;
    let servers = load_servers(&cfg)?;
    if servers.servers.is_empty() {
        tracing::warn!(
            "no mail servers configured yet: nobody can sign in. Add one in the admin console or in {}",
            cfg.servers_file().display()
        );
    }
    if !cfg.secure_cookies {
        tracing::warn!(
            "POSTERN_INSECURE_HTTP is set: cookies are sent without the Secure flag. Development only."
        );
    }
    let trust = smime::Trust::load(cfg.smime_ca_file.as_deref())?;
    tracing::info!(anchors = trust.len(), "S/MIME trust anchors loaded");
    let state = AppState::new(cfg.clone(), servers, sealer, trust);

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?
        .block_on(serve(cfg, state))
}

async fn serve(cfg: Config, state: AppState) -> Result<(), String> {
    let sweeper = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            sweeper.sweep();
        }
    });

    let app: Router = api::router(state.clone())
        .route("/healthz", get(assets::healthz))
        .fallback(assets::web)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            api::security_headers,
        ));

    let listener = tokio::net::TcpListener::bind(cfg.listen)
        .await
        .map_err(|e| format!("cannot listen on {}: {e}", cfg.listen))?;
    tracing::info!(
        "postern {} listening on http://{}",
        env!("CARGO_PKG_VERSION"),
        cfg.listen
    );

    if let Some(addr) = cfg.admin_listen {
        let admin_listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| format!("cannot listen on {addr}: {e}"))?;
        tracing::info!("admin console on http://{addr} (sign in with `postern admin-link`)");
        let admin_app = admin::router(state.clone());
        tokio::spawn(async move {
            if let Err(e) = axum::serve(admin_listener, admin_app).await {
                tracing::error!("admin console stopped: {e}");
            }
        });
    }

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown())
    .await
    .map_err(|e| e.to_string())
}

async fn shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
    tracing::info!("shutting down");
}
