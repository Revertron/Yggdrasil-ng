use std::ffi::OsString;
use std::sync::mpsc;

use windows_service::define_windows_service;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;

const SERVICE_NAME: &str = "yggdrasil-ng";

static SHUTDOWN_TX: std::sync::OnceLock<mpsc::Sender<()>> = std::sync::OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

pub fn run_as_service() -> Result<(), Box<dyn std::error::Error>> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!("Service failed: {}", e);
    }
}

fn run_service() -> Result<(), Box<dyn std::error::Error>> {
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
    SHUTDOWN_TX.set(shutdown_tx).map_err(|_| "shutdown channel already initialized")?;

    let status_handle = service_control_handler::register(SERVICE_NAME, move |control| {
        match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                if let Some(tx) = SHUTDOWN_TX.get() {
                    let _ = tx.send(());
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    })?;

    // Report StartPending
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::from_secs(10),
        process_id: None,
    })?;

    // Build a tokio runtime and run the node
    let rt = tokio::runtime::Runtime::new()?;
    let result = rt.block_on(async {
        let (watch_tx, watch_rx) = tokio::sync::watch::channel(false);

        // Bridge the sync shutdown_rx to the async watch channel
        std::thread::spawn(move || {
            let _ = shutdown_rx.recv();
            let _ = watch_tx.send(true);
        });

        // Report Running
        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::default(),
            process_id: None,
        })?;

        // Run the node
        let exit = super::run_node(watch_rx).await;

        // Report StopPending
        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::StopPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::from_secs(5),
            process_id: None,
        })?;

        exit
    });

    // Report Stopped
    let exit_code = if result.is_ok() {
        ServiceExitCode::Win32(0)
    } else {
        ServiceExitCode::Win32(1)
    };
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code,
        checkpoint: 0,
        wait_hint: std::time::Duration::default(),
        process_id: None,
    })?;

    result
}
