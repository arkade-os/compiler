use arkade_lsp::run;
use lsp_server::Connection;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (connection, io_threads) = Connection::stdio();
    run(connection)?;
    io_threads.join()?;
    Ok(())
}
