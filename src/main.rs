use axum::{extract::{
    path::ErrorKind,
    rejection::PathRejection,
    ws::{Message, WebSocket, WebSocketUpgrade},
    FromRequestParts, TypedHeader,
}, response::IntoResponse, routing::{get, get_service}, Router, http, Json};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use axum::extract::Path;
use std::{env, net::SocketAddr, path::PathBuf};
use axum::response::Response;
use serde_json::{json, to_string, Value};

use tower_http::{
    services::ServeDir,
    trace::{DefaultMakeSpan, TraceLayer},
};
use tower_http::classify::ServerErrorsFailureClass::StatusCode;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use crate::rpc::messages::OcppMessageType;

mod tests;
mod handlers;
mod authorization;
mod provisioning;
mod rpc;
mod security;
mod ocpp;

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "csms=debug,tower_http=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // build our application with some routes
    let app = Router::new()
        .route("/ws/:station_id", get(ws_connect))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::default().include_headers(true)),
        );

    // run it with hyper
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

fn validate_station(station: String) -> Result<(), ErrorUnknownStationId> {
    if station == "123" {
        Ok(())
    } else {
        Err(ErrorUnknownStationId {})
    }
}

struct ErrorUnknownStationId {}

impl IntoResponse for ErrorUnknownStationId {
    fn into_response(self) -> Response {
        Response::default()
    }
}

async fn ws_connect(
    Path(station): Path<String>,
    ws: WebSocketUpgrade
) -> impl IntoResponse {
    tracing::info!("Incoming connection from station {}", station);

    match validate_station(station) {
        Ok(_) => {
            ws.on_upgrade(handle_socket)
        }
        Err(_) => {
            ws.on_upgrade(handle_error)
        }
    }
}

async fn handle_socket(mut socket: WebSocket) {
    if let Some(msg) = socket.recv().await {
        if let Ok(msg) = msg {
            match msg {
                Message::Text(t) => {
                    tracing::info!("client sent str: {:?}", t);
                    let msg = r#"[2,"19223201","BootNotification",{"reason":"PowerUp","chargingStation":{"model":"SingleSocketCharger", "vendorName":"VendorX"}}]"#.to_string();
                    let ocpp_message_type = serde_json::from_str::<OcppMessageType>(&msg).unwrap();
                    tracing::info!("client sent str: {:?}", ocpp_message_type);
                }
                Message::Binary(_) => {
                    tracing::info!("client sent binary data");
                }
                Message::Ping(_) => {
                    tracing::info!("socket ping");
                }
                Message::Pong(_) => {
                    tracing::info!("socket pong");
                }
                Message::Close(_) => {
                    tracing::info!("client disconnected");
                    return;
                }
            }
        } else {
            tracing::info!("client disconnected");
            return;
        }
    }

    loop {
        if socket
            .send(Message::Text(String::from("Hi!")))
            .await
            .is_err()
        {
            tracing::info!("client disconnected");
            return;
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
}

async fn handle_error(mut socket: WebSocket) {

    if socket
        .send(Message::Text(String::from("Not a valid station")))
        .await
        .is_err()
    {
        tracing::info!("client disconnected");
        return;
    }
    // close socket
    tracing::info!("closing socket due to invalid station");
    let _ = socket.close().await;
}
