use axum::extract::ws::Message;
use crate::handlers::response::handle_response;
use crate::rpc::enums::TriggerMessageKind;

pub async fn handle_trigger_message(
    request: TriggerMessageKind
) {
    match request {
        TriggerMessageKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}
