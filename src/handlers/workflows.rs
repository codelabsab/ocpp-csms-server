use axum::extract::ws::Message;
use crate::handlers::response::handle_response;
use crate::rpc::enums::*;

pub async fn handle_cancel_reservation(
    request: CancelReservationKind
) {
    match request {
        CancelReservationKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_certificate_signed(
    request: CertificateSignedKind,
) {
    match request {
        CertificateSignedKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_change_availability(
    request: ChangeAvailabilityKind,
) {
    match request {
        ChangeAvailabilityKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_clear_cache(request: ClearCacheKind) {
    match request {
        ClearCacheKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_clear_charging_profile(
    request: ClearChargingProfileKind,
) {
    match request {
        ClearChargingProfileKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_clear_display_message(
    request: ClearDisplayMessageKind,
) {
    match request {
        ClearDisplayMessageKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_cleared_charging_limit(
    request: ClearedChargingLimitKind,
) {
    match request {
        ClearedChargingLimitKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_clear_variable_monitoring(
    request: ClearVariableMonitoringKind,
) {
    match request {
        ClearVariableMonitoringKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_cost_updated(request: CostUpdatedKind) {
    match request {
        CostUpdatedKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_customer_information(
    request: CustomerInformationKind,
) {
    match request {
        CustomerInformationKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_data_transfer(
    request: DataTransferKind,
) {
    match request {
        DataTransferKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_delete_certificate(
    request: DeleteCertificateKind,
) {
    match request {
        DeleteCertificateKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_firmware_status_notification(
    request: FirmwareStatusNotificationKind,
) {
    match request {
        FirmwareStatusNotificationKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_get_15118_ev_certificate(
    request: Get15118EVCertificateKind,
) {
    match request {
        Get15118EVCertificateKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_get_base_report(
    request: GetBaseReportKind,
) {
    match request {
        GetBaseReportKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_get_certificate_status(
    request: GetCertificateStatusKind,

) {
    match request {
        GetCertificateStatusKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_get_charging_profiles(
    request: GetChargingProfilesKind,

) {
    match request {
        GetChargingProfilesKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_get_composite_schedule(
    request: GetCompositeScheduleKind,

) {
    match request {
        GetCompositeScheduleKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_get_display_message(
    request: GetDisplayMessagesKind,

) {
    match request {
        GetDisplayMessagesKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_get_installed_certificate_ids(
    request: GetInstalledCertificateIdsKind,

) {
    match request {
        GetInstalledCertificateIdsKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_get_local_list_version(
    request: GetLocalListVersionKind,

) {
    match request {
        GetLocalListVersionKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_get_log(request: GetLogKind) {
    match request {
        GetLogKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_get_monitoring_report(
    request: GetMonitoringReportKind,

) {
    match request {
        GetMonitoringReportKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_get_report(request: GetReportKind) {
    match request {
        GetReportKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_get_transaction_status(
    request: GetTransactionStatusKind,

) {
    match request {
        GetTransactionStatusKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_get_variables(
    request: GetVariablesKind,

) {
    match request {
        GetVariablesKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_heartbeat(request: HeartbeatKind) {
    match request {
        HeartbeatKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_install_certificate(
    request: InstallCertificateKind,

) {
    match request {
        InstallCertificateKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_log_status_notification(
    request: LogStatusNotificationKind,

) {
    match request {
        LogStatusNotificationKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_meter_values(request: MeterValuesKind) {
    match request {
        MeterValuesKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_notify_charging_limit(
    request: NotifyChargingLimitKind,

) {
    match request {
        NotifyChargingLimitKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_notify_customer_information(
    request: NotifyCustomerInformationKind,

) {
    match request {
        NotifyCustomerInformationKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_notify_display_messages(
    request: NotifyDisplayMessagesKind,

) {
    match request {
        NotifyDisplayMessagesKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_notify_ev_charging_needs(
    request: NotifyEVChargingNeedsKind,

) {
    match request {
        NotifyEVChargingNeedsKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_notify_ev_charging_schedule(
    request: NotifyEVChargingScheduleKind,

) {
    match request {
        NotifyEVChargingScheduleKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_notify_event(request: NotifyEventKind) {
    match request {
        NotifyEventKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_notify_monitoring_report(
    request: NotifyMonitoringReportKind,

) {
    match request {
        NotifyMonitoringReportKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_notify_report(
    request: NotifyReportKind,

) {
    match request {
        NotifyReportKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_publish_firmware(
    request: PublishFirmwareKind,

) {
    match request {
        PublishFirmwareKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_publish_firmware_status_notification(
    request: PublishFirmwareStatusNotificationKind,

) {
    match request {
        PublishFirmwareStatusNotificationKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_report_charging_profiles(
    request: ReportChargingProfilesKind,

) {
    match request {
        ReportChargingProfilesKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_request_start_transaction(
    request: RequestStartTransactionKind,

) {
    match request {
        RequestStartTransactionKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_request_stop_transaction(
    request: RequestStopTransactionKind,

) {
    match request {
        RequestStopTransactionKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_reservation_status_update(
    request: ReservationStatusUpdateKind,

) {
    match request {
        ReservationStatusUpdateKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_reserve_now(request: ReserveNowKind) {
    match request {
        ReserveNowKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_reset(request: ResetKind) {
    match request {
        ResetKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_security_event_notification(
    request: SecurityEventNotificationKind,

) {
    match request {
        SecurityEventNotificationKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_send_local_list(
    request: SendLocalListKind,

) {
    match request {
        SendLocalListKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_set_charging_profile(
    request: SetChargingProfileKind,

) {
    match request {
        SetChargingProfileKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_set_display_message(
    request: SetDisplayMessageKind,

) {
    match request {
        SetDisplayMessageKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_set_monitoring_base(
    request: SetMonitoringBaseKind,
) {
    match request {
        SetMonitoringBaseKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_set_monitoring_level(
    request: SetMonitoringLevelKind,
) {
    match request {
        SetMonitoringLevelKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_set_network_profile(
    request: SetNetworkProfileKind,
) {
    match request {
        SetNetworkProfileKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_set_variable_monitoring(
    request: SetVariableMonitoringKind,
) {
    match request {
        SetVariableMonitoringKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_sign_certificate(
    request: SignCertificateKind,
) {
    match request {
        SignCertificateKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_status_notification(
    request: StatusNotificationKind,
) {
    match request {
        StatusNotificationKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_transaction_event(
    request: TransactionEventKind,
) {
    match request {
        TransactionEventKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_unlock_connector(
    request: UnlockConnectorKind,
) {
    match request {
        UnlockConnectorKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_unpublish_firmware(
    request: UnpublishFirmwareKind,
) {
    match request {
        UnpublishFirmwareKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}

pub async fn handle_update_firmware(
    request: UpdateFirmwareKind,
) {
    match request {
        UpdateFirmwareKind::Request(req) => {
            handle_response(Message::Text(serde_json::to_string(&req).unwrap())).await;
        }
        _ => {
            handle_response(Message::Text("Got response".into())).await;
        }
    }
}
