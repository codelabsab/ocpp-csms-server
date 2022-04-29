use futures::stream::SplitSink;
use log::warn;
use log::info;

use warp::ws::{Message, WebSocket};

use crate::{handlers::error::handle_error, rpc::messages::OcppMessageType};
use crate::rpc::enums::OcppActionEnum;
use crate::rpc::errors::RpcErrorCodes;
use crate::rpc::messages::{OcppCall, OcppCallError, OcppCallResult};

use super::response::handle_response;

pub async fn handle_message(msg: Message, tx: &mut SplitSink<WebSocket, Message>) {
    // Skip any non-Text messages...
    let msg = if let Ok(s) = msg.to_str() {
        s
    } else {
        warn!("Client sent non-text message");
        handle_error(
            Message::text("Failed to parse incoming message".to_string()),
            tx,
        )
        .await;
        return;
    };

    // serialize or die
    let ocpp_message: OcppMessageType = match serde_json::from_str(msg) {
        Ok(o) => o,
        Err(_) => {
            handle_error(Message::text("failed to parse payload"), tx).await;
            return;
        }
    };

    match ocpp_message {
            OcppMessageType::Call(_, _, _, _) => {
                let call: Result<OcppCall, _> = ocpp_message.clone().try_into();
                match call {
                    Ok(ok_call) => {
                        match ok_call.action {
                            OcppActionEnum::BootNotification => {
                                info!("New charging station booted");
                            }
                            _ => {}
                        }
                    }
                    _ => {
                        handle_error(Message::text(RpcErrorCodes::GenericError.description()), tx).await;
                    }
                };
            }
            OcppMessageType::CallResult(_, _, _) => {
                let call_result: Result<OcppCallResult, _> = ocpp_message.clone().try_into();
                match call_result {
                    Ok(ok_callresult) => {
                        info!("Got a CallResult: {ok_callresult:#?}");
                    }
                    _ => {
                        handle_error(Message::text(RpcErrorCodes::RpcFrameworkError.description()), tx).await;
                    }
                };
            }
            OcppMessageType::CallError(_, _, _, _, _) => {
                let call_error: Result<OcppCallError, _> = ocpp_message.clone().try_into();
                match call_error {
                    Ok(ok_callerror) => {
                        info!("Got a CallError: {ok_callerror:#?}");
                    }
                    _ => {
                        handle_error(Message::text(RpcErrorCodes::InternalError.description()), tx).await;
                    },
                }
            }
        }


    handle_response(
        Message::text(serde_json::to_string(&ocpp_message).unwrap()),
        tx,
    )
    .await;

}
