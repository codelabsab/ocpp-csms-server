use axum::extract::ws::Message;
use crate::handlers::response::handle_response;
use crate::rpc::enums::BootNotificationKind;

pub async fn handle_bootnotification(
    request: BootNotificationKind
) {
    // check if its a request or response
    match request {
        BootNotificationKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}
