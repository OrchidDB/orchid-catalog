use orchid_catalog::{
    api::{App, router, validate_identities},
    model::Identity,
    store::Store,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "orchid_catalog=info,tower_http=info".into()),
        )
        .init();
    let identity_file = std::env::var("ORCHID_CATALOG_IDENTITIES")?;
    let identities: Vec<Identity> =
        serde_json::from_slice(&tokio::fs::read(&identity_file).await?)?;
    let database = std::env::var("ORCHID_CATALOG_DATABASE")
        .unwrap_or_else(|_| "sqlite://catalog.db?mode=rwc".into());
    let app = App::new(Store::connect(&database).await?, identities)?;
    let reload = app.identities.clone();
    // Explicit SIGHUP reload avoids per-request filesystem I/O. Invalid files fail closed.
    #[cfg(unix)]
    tokio::spawn(async move {
        let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            .expect("SIGHUP handler");
        while signal.recv().await.is_some() {
            let next = async {
                let bytes = tokio::fs::read(&identity_file)
                    .await
                    .map_err(|e| e.to_string())?;
                let identities: Vec<Identity> =
                    serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                validate_identities(&identities).map_err(|e| e.to_string())?;
                Ok::<_, String>(identities)
            }
            .await;
            match next {
                Ok(identities) => {
                    *reload.write().await = identities;
                    tracing::info!("identities reloaded");
                }
                Err(error) => {
                    reload.write().await.clear();
                    tracing::error!(%error,"invalid identities; access disabled until successful reload");
                }
            }
        }
    });
    let address =
        std::env::var("ORCHID_CATALOG_LISTEN").unwrap_or_else(|_| "127.0.0.1:8182".into());
    let listener = tokio::net::TcpListener::bind(&address).await?;
    tracing::info!(%address,"Orchid Catalog listening");
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
