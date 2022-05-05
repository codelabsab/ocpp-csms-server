use futures::stream::SplitSink;
use warp::ws::{Message, WebSocket};
use crate::handlers::response::handle_response;
use crate::rpc::enums::TriggerMessageKind;

pub async fn handle_trigger_message(request: TriggerMessageKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        TriggerMessageKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}
