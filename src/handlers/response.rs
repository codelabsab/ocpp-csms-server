use axum::extract::ws::Message;
use tracing::log::{error, info};

pub async fn handle_response(response: Message) {
    info!("Entered handle_response");
}
