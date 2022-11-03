use crate::handlers::response::handle_response;
use crate::rpc::enums::AuthorizeKind;
use axum::extract::ws::Message;

pub async fn handle_authorize(request: AuthorizeKind) {
    match request {
        AuthorizeKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}
