use futures::stream::SplitSink;
use warp::ws::{Message, WebSocket};
use crate::handlers::response::handle_response;
use crate::rpc::enums::BootNotificationKind;

pub async fn handle_bootnotification(request: BootNotificationKind, tx: &mut SplitSink<WebSocket, Message>) {
    // check if its a request or response
    match request {
        BootNotificationKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}
