use orchid_catalog::{
    api::{App, router},
    store::Store,
};

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("catalog startup or service failure");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|a| a == "bootstrap") {
        if args.len() != 2 {
            return Err("usage: orchid-catalog bootstrap DIRECTORY".into());
        }
        return bootstrap(&args[1]);
    }
    if !args.is_empty() {
        return Err("unknown catalog command".into());
    }
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "off,orchid_catalog=info",
        ))
        .init();
    let config_file = std::env::var("ORCHID_CATALOG_AUTH_CONFIG")?;
    let config = serde_json::from_slice(&tokio::fs::read(&config_file).await?)?;
    let authentication = orchid_catalog::auth::Authenticator::load(config).await?;
    let database = std::env::var("ORCHID_CATALOG_DATABASE")
        .unwrap_or_else(|_| "sqlite://catalog.db?mode=rwc".into());
    let app = App::with_authentication(Store::connect(&database).await?, authentication);
    #[cfg(unix)]
    {
        let authentication = app.authentication.clone();
        tokio::spawn(async move {
            let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
                .expect("SIGHUP handler");
            while signal.recv().await.is_some() {
                let next = async {
                    let bytes = tokio::fs::read(&config_file).await.map_err(|_| ())?;
                    let config = serde_json::from_slice(&bytes).map_err(|_| ())?;
                    orchid_catalog::auth::Authenticator::load(config)
                        .await
                        .map_err(|_| ())
                }
                .await;
                *authentication.write().await = next.ok().map(std::sync::Arc::new);
                tracing::info!("authentication configuration reloaded");
            }
        });
    }
    let address =
        std::env::var("ORCHID_CATALOG_LISTEN").unwrap_or_else(|_| "127.0.0.1:8182".into());
    let listener = tokio::net::TcpListener::bind(&address).await?;
    tracing::info!("Orchid Catalog listening");
    axum::serve(listener, router(app))
        .with_graceful_shutdown(async {
            #[cfg(unix)]
            {
                let mut terminate =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("SIGTERM handler");
                tokio::select! { _ = tokio::signal::ctrl_c() => (), _ = terminate.recv() => () }
            }
            #[cfg(not(unix))]
            {
                let _ = tokio::signal::ctrl_c().await;
            }
        })
        .await?;
    Ok(())
}

fn bootstrap(directory: &str) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    let directory = std::path::Path::new(directory);
    std::fs::create_dir(directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
    }
    let directory = directory.canonicalize()?;
    let write = |name: &str, data: &[u8]| -> std::io::Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(directory.join(name))?.write_all(data)
    };
    let secret = orchid_catalog::auth::new_secret();
    let key = orchid_catalog::auth::new_secret();
    write("signing.key", key.as_bytes())?;
    write("admin.secret", secret.as_bytes())?;
    let config = serde_json::json!({"default":{"mode":"internal","internal":{
        "issuer":"orchid-catalog","audience":"orchid-catalog","signing":{"type":"symmetric","key_file":directory.join("signing.key")},
        "clients":[{"client_id":"admin","secret_sha256":orchid_catalog::auth::fingerprint(&secret),
            "principal":{"subject":"admin","admin":true,"roles":["service_admin"]}}]}}});
    write("auth.json", &serde_json::to_vec_pretty(&config)?)?;
    println!("Created auth.json, signing.key and admin.secret in the bootstrap directory");
    Ok(())
}
