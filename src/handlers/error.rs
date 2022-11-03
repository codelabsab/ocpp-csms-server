use axum::extract::ws::Message;
use pretty_env_logger;
use tracing::info;


pub async fn handle_error(error: Message) {
    info!("Entered error_handler");
}
