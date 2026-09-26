#[tokio::main]
async fn main() -> anyhow::Result<()> {
    diego::cli::run().await?;
    Ok(())
}
