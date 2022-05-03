use futures::stream::SplitSink;
use log::info;
use log::warn;

use warp::ws::{Message, WebSocket};

use crate::rpc::enums::{OcppActionEnum, OcppPayload};
use crate::rpc::errors::RpcErrorCodes;
use crate::rpc::messages::{OcppCall, OcppCallError, OcppCallResult};
use crate::{handlers::error::handle_error, rpc::messages::OcppMessageType};
use crate::handlers::workflows::*;
use crate::provisioning::bootnotification::handle_bootnotification;

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
    let ocpp_message_type: OcppMessageType = match serde_json::from_str(msg) {
        Ok(o) => o,
        Err(_) => {
            handle_error(Message::text("failed to parse call"), tx).await;
            return;
        }
    };

    parse_ocpp_message_type(tx, &ocpp_message_type).await;

    handle_response(
        Message::text(serde_json::to_string(&ocpp_message_type).unwrap()),
        tx,
    )
    .await;
}

async fn parse_ocpp_message_type(tx: &mut SplitSink<WebSocket, Message>, ocpp_message: &OcppMessageType) {
    match ocpp_message {
        OcppMessageType::Call(_, _, _, _) => {
            let call: Result<OcppCall, _> = ocpp_message.clone().try_into();
            match call {
                Ok(ok_call) => match ok_call.action {
                    OcppActionEnum::Authorize => {
                        match ok_call.payload {
                            OcppPayload::Authorize(kind) => {
                                handle_authorize(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse authorize"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::BootNotification => {
                        match ok_call.payload {
                            OcppPayload::BootNotification(kind) => {
                                handle_bootnotification(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse authorize"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::CancelReservation => {
                        match ok_call.payload {
                            OcppPayload::CancelReservation(kind) => {
                                handle_cancel_reservation(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse CancelReservation"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::CertificateSigned => {
                        match ok_call.payload {
                            OcppPayload::CertificateSigned(kind) => {
                                handle_certificate_signed(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse CertificateSigned"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::ChangeAvailability => {
                        match ok_call.payload {
                            OcppPayload::ChangeAvailability(kind) => {
                                handle_change_availability(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse ChangeAvailability"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::ClearCache => {
                        match ok_call.payload {
                            OcppPayload::ClearCache(kind) => {
                                handle_clear_cache(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse ClearCache"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::ClearChargingProfile => {
                        match ok_call.payload {
                            OcppPayload::ClearChargingProfile(kind) => {
                                handle_clear_charging_profile(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse ClearChargingProfile"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::ClearDisplayMessage => {
                        match ok_call.payload {
                            OcppPayload::ClearDisplayMessage(kind) => {
                                handle_clear_display_message(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse ClearDisplayMessage"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::ClearedChargingLimit => {
                        match ok_call.payload {
                            OcppPayload::ClearedChargingLimit(kind) => {
                                handle_cleared_charging_limit(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse ClearedChargingLimit"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::ClearVariableMonitoring => {
                        match ok_call.payload {
                            OcppPayload::ClearVariableMonitoring(kind) => {
                                handle_clear_variable_monitoring(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse ClearVariableMonitoring"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::CostUpdated => {
                        match ok_call.payload {
                            OcppPayload::CostUpdated(kind) => {
                                handle_cost_updated(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse CostUpdated"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::CustomerInformation => {
                        match ok_call.payload {
                            OcppPayload::CustomerInformation(kind) => {
                                handle_customer_information(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse CustomerInformation"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::DataTransfer => {
                        match ok_call.payload {
                            OcppPayload::DataTransfer(kind) => {
                                handle_data_transfer(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse DataTransfer"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::DeleteCertificate => {
                        match ok_call.payload {
                            OcppPayload::DeleteCertificate(kind) => {
                                handle_delete_certificate(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse DeleteCertificate"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::FirmwareStatusNotification => {
                        match ok_call.payload {
                            OcppPayload::FirmwareStatusNotification(kind) => {
                                handle_firmware_status_notification(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse FirmwareStatusNotification"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::Get15118EVCertificate => {
                        match ok_call.payload {
                            OcppPayload::Get15118EVCertificate(kind) => {
                                handle_get_15118_ev_certificate(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse Get15118EVCertificate"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::GetBaseReport => {
                        match ok_call.payload {
                            OcppPayload::GetBaseReport(kind) => {
                                handle_get_base_report(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse GetBaseReport"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::GetCertificateStatus => {
                        match ok_call.payload {
                            OcppPayload::GetCertificateStatus(kind) => {
                                handle_get_certificate_status(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse GetCertificateStatus"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::GetChargingProfile => {
                        match ok_call.payload {
                            OcppPayload::GetChargingProfile(kind) => {
                                handle_get_charging_profiles(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse GetChargingProfile"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::GetCompositeSchedule => {
                        match ok_call.payload {
                            OcppPayload::GetCompositeSchedule(kind) => {
                                handle_get_composite_schedule(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse GetCompositeSchedule"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::GetDisplayMessage => {
                        match ok_call.payload {
                            OcppPayload::GetDisplayMessage(kind) => {
                                handle_get_display_message(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse GetDisplayMessage"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::GetInstalledCertificateIds => {
                        match ok_call.payload {
                            OcppPayload::GetInstalledCertificateIds(kind) => {
                                handle_get_installed_certificate_ids(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse GetInstalledCertificateIds"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::GetLocalListVersion => {
                        match ok_call.payload {
                            OcppPayload::GetLocalListVersion(kind) => {
                                handle_get_local_list_version(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse GetLocalListVersion"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::GetLog => {
                        match ok_call.payload {
                            OcppPayload::GetLog(kind) => {
                                handle_get_log(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse GetLog"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::GetMonitoringReport => {
                        match ok_call.payload {
                            OcppPayload::GetMonitoringReport(kind) => {
                                handle_get_monitoring_report(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse GetMonitoringReport"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::GetReport => {
                        match ok_call.payload {
                            OcppPayload::GetReport(kind) => {
                                handle_get_report(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse GetReport"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::GetTransactionStatus => {
                        match ok_call.payload {
                            OcppPayload::GetTransactionStatus(kind) => {
                                handle_get_transaction_status(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse GetTransactionStatus"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::GetVariables => {
                        match ok_call.payload {
                            OcppPayload::GetVariables(kind) => {
                                handle_get_variables(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse GetVariables"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::Heartbeat => {
                        match ok_call.payload {
                            OcppPayload::Heartbeat(kind) => {
                                handle_heartbeat(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse Heartbeat"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::InstallCertificate => {
                        match ok_call.payload {
                            OcppPayload::InstallCertificate(kind) => {
                                handle_install_certificate(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse InstallCertificate"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::LogStatusNotification => {
                        match ok_call.payload {
                            OcppPayload::LogStatusNotification(kind) => {
                                handle_log_status_notification(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse LogStatusNotification"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::MeterValues => {
                        match ok_call.payload {
                            OcppPayload::MeterValues(kind) => {
                                handle_meter_values(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse MeterValues"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::NotifyChargingLimit => {
                        match ok_call.payload {
                            OcppPayload::NotifyChargingLimit(kind) => {
                                handle_notify_charging_limit(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse NotifyChargingLimit"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::NotifyCustomerInformation => {
                        match ok_call.payload {
                            OcppPayload::NotifyCustomerInformation(kind) => {
                                handle_notify_customer_information(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse NotifyCustomerInformation"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::NotifyDisplayMessages => {
                        match ok_call.payload {
                            OcppPayload::NotifyDisplayMessages(kind) => {
                                handle_notify_display_messages(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse NotifyDisplayMessages"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::NotifyEVChargingNeeds => {
                        match ok_call.payload {
                            OcppPayload::NotifyEVChargingNeeds(kind) => {
                                handle_notify_ev_charging_needs(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse NotifyEVChargingNeeds"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::NotifyEVChargingSchedule => {
                        match ok_call.payload {
                            OcppPayload::NotifyEVChargingSchedule(kind) => {
                                handle_notify_ev_charging_schedule(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse NotifyEVChargingSchedule"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::NotifyEvent => {
                        match ok_call.payload {
                            OcppPayload::NotifyEvent(kind) => {
                                handle_notify_event(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse NotifyEvent"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::NotifyMonitoringReport => {
                        match ok_call.payload {
                            OcppPayload::NotifyMonitoringReport(kind) => {
                                handle_notify_monitoring_report(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse NotifyMonitoringReport"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::NotifyReport => {
                        match ok_call.payload {
                            OcppPayload::NotifyReport(kind) => {
                                handle_notify_report(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse NotifyReport"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::PublishFirmware => {
                        match ok_call.payload {
                            OcppPayload::PublishFirmware(kind) => {
                                handle_publish_firmware(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse PublishFirmware"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::PublishFirmwareStatusNotification => {
                        match ok_call.payload {
                            OcppPayload::PublishFirmwareStatusNotification(kind) => {
                                handle_publish_firmware_status_notification(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse PublishFirmwareStatusNotification"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::ReportChargingProfiles => {
                        match ok_call.payload {
                            OcppPayload::ReportChargingProfiles(kind) => {
                                handle_report_charging_profiles(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse ReportChargingProfiles"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::RequestStartTransaction => {
                        match ok_call.payload {
                            OcppPayload::RequestStartTransaction(kind) => {
                                handle_request_start_transaction(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse RequestStartTransaction"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::RequestStopTransaction => {
                        match ok_call.payload {
                            OcppPayload::RequestStopTransaction(kind) => {
                                handle_request_stop_transaction(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse RequestStopTransaction"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::ReservationStatusUpdate => {
                        match ok_call.payload {
                            OcppPayload::ReservationStatusUpdate(kind) => {
                                handle_reservation_status_update(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse ReservationStatusUpdate"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::ReserveNow => {
                        match ok_call.payload {
                            OcppPayload::ReserveNow(kind) => {
                                handle_reserve_now(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse ReserveNow"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::Reset => {
                        match ok_call.payload {
                            OcppPayload::Reset(kind) => {
                                handle_reset(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse Reset"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::SecurityEventNotification => {
                        match ok_call.payload {
                            OcppPayload::SecurityEventNotification(kind) => {
                                handle_security_event_notification(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse SecurityEventNotification"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::SendLocalList => {
                        match ok_call.payload {
                            OcppPayload::SendLocalList(kind) => {
                                handle_send_local_list(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse SendLocalList"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::SetChargingProfile => {
                        match ok_call.payload {
                            OcppPayload::SetChargingProfile(kind) => {
                                handle_set_charging_profile(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse SetChargingProfile"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::SetDisplayMessage => {
                        match ok_call.payload {
                            OcppPayload::SetDisplayMessage(kind) => {
                                handle_set_display_message(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse SetDisplayMessage"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::SetMonitoringBase => {
                        match ok_call.payload {
                            OcppPayload::SetMonitoringBase(kind) => {
                                handle_set_monitoring_base(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse SetMonitoringBase"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::SetMonitoringLevel => {
                        match ok_call.payload {
                            OcppPayload::SetMonitoringLevel(kind) => {
                                handle_set_monitoring_level(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse SetMonitoringLevel"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::SetNetworkProfile => {
                        match ok_call.payload {
                            OcppPayload::SetNetworkProfile(kind) => {
                                handle_set_network_profile(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse SetNetworkProfile"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::SetVariableMonitoring => {
                        match ok_call.payload {
                            OcppPayload::SetVariableMonitoring(kind) => {
                                handle_set_variable_monitoring(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse SetVariableMonitoring"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::SetVariables => {
                        match ok_call.payload {
                            OcppPayload::SetVariables(kind) => {
                                handle_set_variables(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse SetVariables"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::SignCertificate => {
                        match ok_call.payload {
                            OcppPayload::SignCertificate(kind) => {
                                handle_sign_certificate(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse SignCertificate"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::StatusNotification => {
                        match ok_call.payload {
                            OcppPayload::StatusNotification(kind) => {
                                handle_status_notification(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse StatusNotification"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::TransactionEvent => {
                        match ok_call.payload {
                            OcppPayload::TransactionEvent(kind) => {
                                handle_transaction_event(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse TransactionEvent"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::TriggerMessage => {
                        match ok_call.payload {
                            OcppPayload::TriggerMessage(kind) => {
                                handle_trigger_message(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse TriggerMessage"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::UnlockConnector => {
                        match ok_call.payload {
                            OcppPayload::UnlockConnector(kind) => {
                                handle_unlock_connector(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse UnlockConnector"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::UnpublishFirmware => {
                        match ok_call.payload {
                            OcppPayload::UnpublishFirmware(kind) => {
                                handle_unpublish_firmware(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse UnpublishFirmware"), tx).await;
                                return;
                            }
                        };
                    }
                    OcppActionEnum::UpdateFirmware => {
                        match ok_call.payload {
                            OcppPayload::UpdateFirmware(kind) => {
                                handle_update_firmware(kind, tx).await;
                            },
                            _ => {
                                handle_error(Message::text("failed to parse UpdateFirmware"), tx).await;
                                return;
                            }
                        }
                    },
                },
                _ => {}
            }
        }
        OcppMessageType::CallResult(_, _, _) => {
            let call_result: Result<OcppCallResult, _> = ocpp_message.clone().try_into();
            match call_result {
                Ok(ok_callresult) => {
                    info!("Got a CallResult: {ok_callresult:#?}");
                }
                _ => {
                    handle_error(
                        Message::text(RpcErrorCodes::RpcFrameworkError.description()),
                        tx,
                    )
                        .await;
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
                    handle_error(
                        Message::text(RpcErrorCodes::InternalError.description()),
                        tx,
                    )
                        .await;
                }
            }
        }
    }
}
