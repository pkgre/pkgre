use tracing::info;

fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    info!("pkgre-indexer initialized");
}
