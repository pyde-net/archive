use tokio::sync::broadcast;
use tracing::info;

/// Shutdown coordinator: sends a signal to all subsystems.
#[derive(Clone)]
pub struct ShutdownSignal {
    sender: broadcast::Sender<()>,
}

impl ShutdownSignal {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(1);
        Self { sender }
    }

    /// Get a receiver that fires when shutdown is triggered.
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.sender.subscribe()
    }

    /// Trigger shutdown (called from signal handler).
    pub fn trigger(&self) {
        let _ = self.sender.send(());
    }
}

/// Wait for SIGTERM or SIGINT (Ctrl+C), then trigger shutdown.
pub async fn wait_for_signal(shutdown: ShutdownSignal) {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to register SIGTERM handler");

        tokio::select! {
            _ = ctrl_c => {
                info!("received SIGINT, shutting down...");
            }
            _ = sigterm.recv() => {
                info!("received SIGTERM, shutting down...");
            }
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.expect("failed to listen for ctrl-c");
        info!("received SIGINT, shutting down...");
    }

    shutdown.trigger();
}
