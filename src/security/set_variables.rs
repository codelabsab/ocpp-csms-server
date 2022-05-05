use crate::handlers::response::handle_response;
use crate::rpc::enums::SetVariablesKind;
use futures::stream::SplitSink;
use warp::ws::{Message, WebSocket};

pub async fn handle_set_variables(
    request: SetVariablesKind,
    tx: &mut SplitSink<WebSocket, Message>,
) {
    match request {
        SetVariablesKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        }
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}
