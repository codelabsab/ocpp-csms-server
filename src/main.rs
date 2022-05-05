// #![deny(warnings)]

use log::info;

use std::env;
use warp::Filter;

use crate::handlers::connection::handle_connection;

mod handlers;
mod ocpp;
mod rpc;
mod provisioning;
mod authorization;
mod security;
mod local_authorization_list;
mod transactions;
mod remote_control;
mod availability;
mod reservation;
mod tariff_and_cost;
mod meter_values;
mod smart_charging;
mod firmware_management;
mod certificate_management;
mod diagnostics;
mod display_message;
mod data_transfer;


#[cfg(test)]
mod tests;

#[tokio::main]
pub async fn main() {
    // read loglevel from env or default to info and start logger
    let loglevel = "RUST_LOG";
    match env::var(loglevel) {
        Ok(v) => env::set_var(loglevel, v),
        _ => env::set_var(loglevel, "info"),
    };
    pretty_env_logger::init();

    let routes = warp::path("ws")
        .and(warp::ws())
        .map(|ws: warp::ws::Ws| ws.on_upgrade(handle_connection));

    let cert = option_env!("TLS_CERT").unwrap_or("certs/server.cert");
    let key = option_env!("TLS_KEY").unwrap_or("certs/server.key");

    // start with or without tls?
    match env::var("USE_TLS") {
        Ok(val) => match val.as_str() {
            "true" => {
                info!("Starting server with TLS");
                warp::serve(routes)
                    .tls()
                    .cert_path(cert)
                    .key_path(key)
                    .run(([0, 0, 0, 0], 3040))
                    .await;
            }
            _ => {
                info!("Starting server without TLS");
                warp::serve(routes).run(([0, 0, 0, 0], 3040)).await;
            }
        },
        Err(_) => {
            info!("Starting server without TLS");
            warp::serve(routes).run(([0, 0, 0, 0], 3040)).await;
        }
    }
}
