use axum::extract::ws::Message;
use tracing::log::warn;

use crate::authorization::authorize::handle_authorize;
use crate::provisioning::bootnotification::handle_bootnotification;
use crate::rpc::enums::{OcppActionEnum, OcppPayload};
use crate::rpc::errors::RpcErrorCodes;
use crate::rpc::messages::{OcppCall, OcppCallError, OcppCallResult};
use crate::security::set_variables::handle_set_variables;
use crate::security::trigger_message::handle_trigger_message;
use crate::{handlers::error::handle_error, rpc::messages::OcppMessageType};
use crate::handlers::response::handle_response;

pub async fn parse(msg: Message) {
    // Skip any non-Text messages...


    // serialize or die
    let ocpp_message_type: OcppMessageType = match serde_json::from_str(msg.into_text().unwrap().as_str()) {
        Ok(o) => o,
        Err(_) => {
            handle_error(Message::Text("failed to parse call".to_string())).await;
            return;
        }
    };

    parse_ocpp_message_type(&ocpp_message_type).await;

    handle_response(
        Message::Text(serde_json::to_string(&ocpp_message_type).unwrap()),
    )
    .await;
}

async fn parse_ocpp_message_type(
    ocpp_message: &OcppMessageType,
) {
    match ocpp_message {
        // Call: [<MessageTypeId>, "<MessageId>", "<Action>", {<Payload>}]
        OcppMessageType::Call(message_type_id, message_id, action, payload) => {
            // Validate message type id is 2 for Call
            if message_type_id.ne(&2) {
                handle_error(Message::Text("Wrong message type id".into())).await;
            }
        }

        // CallResult: [<MessageTypeId>, "<MessageId>", {<Payload>}]
        OcppMessageType::CallResult(message_type_id, message_id, payload) => {
            // Validate message type id is 3 for CallResult
            if message_type_id.ne(&3) {
                handle_error(Message::Text("Wrong message type id".into())).await;
            }
        }

        // CallError: [<MessageTypeId>, "<MessageId>", "<errorCode>", "<errorDescription>", {<errorDetails>}]
        OcppMessageType::CallError(
            message_type_id,
            message_id,
            error_code,
            error_description,
            error_details,
        ) => {
            // Validate message type id is 4 for CallError
            if message_type_id.ne(&4) {
                handle_error(Message::Text("Wrong message type id".into())).await;
            }
        }
    }
}
