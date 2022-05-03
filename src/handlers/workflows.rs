use futures::stream::SplitSink;
use warp::ws::{Message, WebSocket};
use crate::handlers::response::handle_response;
use crate::rpc::enums::*;

pub async fn handle_authorize(request: AuthorizeKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        AuthorizeKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_cancel_reservation(request: CancelReservationKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        CancelReservationKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_certificate_signed(request: CertificateSignedKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        CertificateSignedKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_change_availability(request: ChangeAvailabilityKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        ChangeAvailabilityKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_clear_cache(request: ClearCacheKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        ClearCacheKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_clear_charging_profile(request: ClearChargingProfileKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        ClearChargingProfileKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_clear_display_message(request: ClearDisplayMessageKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        ClearDisplayMessageKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_cleared_charging_limit(request: ClearedChargingLimitKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        ClearedChargingLimitKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_clear_variable_monitoring(request: ClearVariableMonitoringKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        ClearVariableMonitoringKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_cost_updated(request: CostUpdatedKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        CostUpdatedKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_customer_information(request: CustomerInformationKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        CustomerInformationKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_data_transfer(request: DataTransferKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        DataTransferKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_delete_certificate(request: DeleteCertificateKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        DeleteCertificateKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_firmware_status_notification(request: FirmwareStatusNotificationKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        FirmwareStatusNotificationKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_get_15118_ev_certificate(request: Get15118EVCertificateKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        Get15118EVCertificateKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_get_base_report(request: GetBaseReportKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        GetBaseReportKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_get_certificate_status(request: GetCertificateStatusKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        GetCertificateStatusKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_get_charging_profiles(request: GetChargingProfilesKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        GetChargingProfilesKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_get_composite_schedule(request: GetCompositeScheduleKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        GetCompositeScheduleKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_get_display_message(request: GetDisplayMessagesKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        GetDisplayMessagesKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_get_installed_certificate_ids(request: GetInstalledCertificateIdsKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        GetInstalledCertificateIdsKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_get_local_list_version(request: GetLocalListVersionKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        GetLocalListVersionKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_get_log(request: GetLogKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        GetLogKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_get_monitoring_report(request: GetMonitoringReportKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        GetMonitoringReportKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_get_report(request: GetReportKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        GetReportKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_get_transaction_status(request: GetTransactionStatusKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        GetTransactionStatusKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_get_variables(request: GetVariablesKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        GetVariablesKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_heartbeat(request: HeartbeatKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        HeartbeatKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_install_certificate(request: InstallCertificateKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        InstallCertificateKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_log_status_notification(request: LogStatusNotificationKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        LogStatusNotificationKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_meter_values(request: MeterValuesKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        MeterValuesKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_notify_charging_limit(request: NotifyChargingLimitKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        NotifyChargingLimitKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_notify_customer_information(request: NotifyCustomerInformationKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        NotifyCustomerInformationKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_notify_display_messages(request: NotifyDisplayMessagesKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        NotifyDisplayMessagesKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_notify_ev_charging_needs(request: NotifyEVChargingNeedsKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        NotifyEVChargingNeedsKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_notify_ev_charging_schedule(request: NotifyEVChargingScheduleKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        NotifyEVChargingScheduleKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_notify_event(request: NotifyEventKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        NotifyEventKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_notify_monitoring_report(request: NotifyMonitoringReportKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        NotifyMonitoringReportKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_notify_report(request: NotifyReportKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        NotifyReportKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_publish_firmware(request: PublishFirmwareKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        PublishFirmwareKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_publish_firmware_status_notification(request: PublishFirmwareStatusNotificationKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        PublishFirmwareStatusNotificationKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_report_charging_profiles(request: ReportChargingProfilesKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        ReportChargingProfilesKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_request_start_transaction(request: RequestStartTransactionKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        RequestStartTransactionKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_request_stop_transaction(request: RequestStopTransactionKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        RequestStopTransactionKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_reservation_status_update(request: ReservationStatusUpdateKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        ReservationStatusUpdateKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_reserve_now(request: ReserveNowKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        ReserveNowKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_reset(request: ResetKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        ResetKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_security_event_notification(request: SecurityEventNotificationKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        SecurityEventNotificationKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_send_local_list(request: SendLocalListKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        SendLocalListKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_set_charging_profile(request: SetChargingProfileKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        SetChargingProfileKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_set_display_message(request: SetDisplayMessageKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        SetDisplayMessageKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_set_monitoring_base(request: SetMonitoringBaseKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        SetMonitoringBaseKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_set_monitoring_level(request: SetMonitoringLevelKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        SetMonitoringLevelKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_set_network_profile(request: SetNetworkProfileKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        SetNetworkProfileKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_set_variable_monitoring(request: SetVariableMonitoringKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        SetVariableMonitoringKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_set_variables(request: SetVariablesKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        SetVariablesKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_sign_certificate(request: SignCertificateKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        SignCertificateKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_status_notification(request: StatusNotificationKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        StatusNotificationKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_transaction_event(request: TransactionEventKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        TransactionEventKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_trigger_message(request: TriggerMessageKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        TriggerMessageKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_unlock_connector(request: UnlockConnectorKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        UnlockConnectorKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_unpublish_firmware(request: UnpublishFirmwareKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        UnpublishFirmwareKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}

pub async fn handle_update_firmware(request: UpdateFirmwareKind, tx: &mut SplitSink<WebSocket, Message>) {
    match request {
        UpdateFirmwareKind::Request(req) => {
            handle_response(Message::text(serde_json::to_string(&req).unwrap()), tx).await;
        },
        _ => {
            handle_response(Message::text("Got response"), tx).await;
        }
    }
}
