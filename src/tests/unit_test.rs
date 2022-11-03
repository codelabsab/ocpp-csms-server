use std::net::SocketAddr;
use crate::{
    handlers::message::parse,
    rpc::{
        enums::OcppActionEnum,
        messages::{OcppCall, OcppCallError, OcppCallResult, OcppMessageType},
    },
};
use serde_json::{self, Error};
extern crate pretty_env_logger;
extern crate tokio;
use futures::StreamExt;
use rust_ocpp::v2_0_1::messages::boot_notification::BootNotificationRequest;
use tokio::net::TcpListener;
use warp::{ws::Message, Filter};

#[tokio::test]
async fn ws_call_bootnotification_request_test() {

    let listener = TcpListener::bind("127.0.0.1:8000".parse::<SocketAddr>().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::Server::from_tcp(listener)
            .unwrap()
            .serve(app().await.into_make_service())
            .await
            .unwrap();
    });


    let req = r#"[2,"19223201","BootNotification",{"reason":"PowerUp","chargingStation":{"model":"SingleSocketCharger","vendorName":"VendorX"}}]"#;
    let res = client.recv().await.expect("Failed test");
    let res = res.to_str().unwrap();
    let bnr: Result<BootNotificationRequest, Error> =
        serde_json::from_str::<BootNotificationRequest>(&res);
    match bnr {
        Ok(o) => {
            assert_eq!(
                serde_json::to_string(&o).unwrap(),
                r#"{"reason":"PowerUp","chargingStation":{"model":"SingleSocketCharger","vendorName":"VendorX"}}"#
            )
        }
        Err(_) => {}
    }
}

#[tokio::test]
async fn ws_test_wrong_message_type_id() {
    let mut client = warp::test::ws()
        .handshake(mock_handle_connection())
        .await
        .expect("handshake");
    let req = r#"[3,"19223201","BootNotification",{"reason":"PowerUp","chargingStation":{"model":"SingleSocketCharger","vendorName":"VendorX"}}]"#;
    client.send(Message::text(req)).await;
    let res = client.recv().await.expect("Failed test");
    let res = res.to_str().unwrap();
    assert_eq!(res, "\"message_type_id\" should be 2 if it's a Call");
}

#[tokio::test]
async fn ws_call_authorize_request_test() {
    // mock a test client
    let mut client = warp::test::ws()
        .handshake(mock_handle_connection())
        .await
        .expect("handshake");

    // Setup our test message that the client will send
    let req = r#"[2,"19223201","BootNotification",{"reason":"PowerUp","chargingStation":{"model":"SingleSocketCharger","vendorName":"VendorX"}}]"#;

    // client sends message
    client.send(Message::text(req)).await;

    // receive sent message or die
    let res = client.recv().await.expect("Failed test");

    // convert to str and json
    let res = res.to_str().unwrap();

    // cast string to real BootNotificationRequest struct
    let bnr: Result<BootNotificationRequest, Error> =
        serde_json::from_str::<BootNotificationRequest>(&res);

    match bnr {
        Ok(o) => {
            assert_eq!(
                serde_json::to_string(&o).unwrap(),
                r#"{"reason":"PowerUp","chargingStation":{"model":"SingleSocketCharger","vendorName":"VendorX"}}"#
            )
        }
        Err(_) => {}
    }
}

#[tokio::test]
async fn ws_callresult_test() {
    // mock a test client
    let mut client = warp::test::ws()
        .handshake(mock_handle_connection())
        .await
        .expect("handshake");

    // Setup our test message that the client will send
    let req = r#"[3,"19223201",{"currentTime":"2013-02-01T20:53:32.486Z","interval":300,"status":"Accepted"}]"#;

    // client sends message
    client.send(Message::text(req)).await;

    // receive sent message or die
    let res = client.recv().await.expect("Failed test");

    // convert to str and json
    let res = res.to_str().unwrap();

    // cast string to real BootNotificationRequest struct
    let bnr: Result<OcppMessageType, Error> = serde_json::from_str::<OcppMessageType>(&res);

    match bnr {
        Ok(ocpp_message_type) => match ocpp_message_type {
            OcppMessageType::Call(_, _, _, _) => {
                let call: Result<OcppCall, _> = ocpp_message_type.try_into();
                match call {
                    Ok(ok_call) => {
                        // Do some more testing
                        assert_eq!(ok_call.action, OcppActionEnum::BootNotification);
                        assert_eq!(ok_call.message_type_id, 2);
                        assert_eq!(serde_json::to_string(&ok_call).unwrap(), req);
                    }
                    _ => {
                        panic!("Failed to parse Call")
                    }
                };
            }
            OcppMessageType::CallResult(_, _, _) => {
                let call_result: Result<OcppCallResult, _> = ocpp_message_type.try_into();
                match call_result {
                    Ok(ok_callresult) => {
                        assert_eq!(ok_callresult.message_type_id, 3);
                        assert_eq!(serde_json::to_string(&ok_callresult).unwrap(), req);
                    }
                    _ => {
                        panic!("Failed to parse CallResult")
                    }
                };
            }
            OcppMessageType::CallError(_, _, _, _, _) => {
                let call_error: Result<OcppCallError, _> = ocpp_message_type.try_into();
                match call_error {
                    Ok(ok_callerror) => {
                        assert_eq!(ok_callerror.message_type_id, 4);
                    }
                    _ => panic!("Failed to parse CallError"),
                }
            }
        },
        Err(_) => {
            panic!("Failed to parse Call")
        }
    };
}

#[tokio::test]
async fn ws_callerror_test() {
    // mock a test client
    let mut client = warp::test::ws()
        .handshake(mock_handle_connection())
        .await
        .expect("handshake");

    // Setup our test message that the client will send
    let req = r#"[4,"162376037","NotSupported","SetDisplayMessageRequest not implemented",{}]"#;

    // client sends message
    client.send(Message::text(req)).await;

    // receive sent message or die
    let res = client.recv().await.expect("Failed test");

    // convert to str and json
    let res = res.to_str().unwrap();

    // cast string to real BootNotificationRequest struct
    let bnr: Result<OcppMessageType, Error> = serde_json::from_str::<OcppMessageType>(&res);

    match bnr {
        Ok(ocpp_message_type) => match ocpp_message_type {
            OcppMessageType::Call(_, _, _, _) => {
                let call: Result<OcppCall, _> = ocpp_message_type.try_into();
                match call {
                    Ok(ok_call) => {
                        // Do some more testing
                        assert_eq!(ok_call.action, OcppActionEnum::BootNotification);
                        assert_eq!(ok_call.message_type_id, 2);
                        assert_eq!(serde_json::to_string(&ok_call).unwrap(), req);
                    }
                    _ => {
                        panic!("Failed to parse Call")
                    }
                };
            }
            OcppMessageType::CallResult(_, _, _) => {
                let call_result: Result<OcppCallResult, _> = ocpp_message_type.try_into();
                match call_result {
                    Ok(ok_callresult) => {
                        assert_eq!(ok_callresult.message_type_id, 3);
                        assert_eq!(serde_json::to_string(&ok_callresult).unwrap(), req);
                    }
                    _ => {
                        panic!("Failed to parse CallResult")
                    }
                };
            }
            OcppMessageType::CallError(_, _, _, _, _) => {
                let call_error: Result<OcppCallError, _> = ocpp_message_type.try_into();
                match call_error {
                    Ok(ok_callerror) => {
                        assert_eq!(ok_callerror.message_type_id, 4);
                    }
                    _ => panic!("Failed to parse CallError"),
                }
            }
        },
        Err(_) => {
            panic!("Failed to parse Call")
        }
    };
}
