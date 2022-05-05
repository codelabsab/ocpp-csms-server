use futures::stream::SplitSink;
use warp::ws::{Message, WebSocket};
use crate::handlers::response::handle_response;
use crate::rpc::enums::AuthorizeKind;

pub async fn handle_authorize(request: AuthorizeKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        AuthorizeKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}
