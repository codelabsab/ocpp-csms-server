use axum::extract::ws::Message;
use crate::handlers::response::handle_response;
use crate::rpc::enums::SetVariablesKind;

pub async fn handle_set_variables(
    request: SetVariablesKind
) {
    match request {
        SetVariablesKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}
