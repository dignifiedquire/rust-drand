use anyhow::{anyhow, Result};
use async_std::sync::Sender;
use serde::{Deserialize, Serialize};

pub struct Server {
    server: tide::Server<State>,
}

struct State {
    control_channel: Sender<crate::daemon::DaemonAction>,
}

impl Server {
    /// Construct the server part of the control flow.
    pub fn new(control_channel: Sender<crate::daemon::DaemonAction>) -> Server {
        let mut server = Server {
            server: tide::with_state(State { control_channel }),
        };

        server.server.at("/").post(|req| async move {
            match main_control_point(req).await {
                Ok(source) => tide::Response::new(source.status_code())
                    .body_json(&source)
                    .unwrap(),
                Err(err) => tide::Response::new(400)
                    .body_json(&ControlResponse::Error(err.to_string()))
                    .unwrap(),
            }
        });

        server
    }

    pub async fn listen(self, addr: impl async_std::net::ToSocketAddrs) -> Result<()> {
        self.server.listen(addr).await?;
        Ok(())
    }
}

async fn main_control_point(mut req: tide::Request<State>) -> Result<ControlResponse> {
    match req.body_json().await? {
        ControlRequest::Ping => Ok(ControlResponse::Pong),
        ControlRequest::Stop => {
            let state = req.state();
            state
                .control_channel
                .send(crate::daemon::DaemonAction::Stop)
                .await;
            Ok(ControlResponse::Stopped)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum ControlRequest {
    Ping,
    Stop,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum ControlResponse {
    Pong,
    Stopped,
    Error(String),
}

impl ControlResponse {
    pub fn status_code(&self) -> u16 {
        match self {
            ControlResponse::Error(_) => 400,
            _ => 200,
        }
    }
}

/// Client to control the running daemon.
pub struct Client {
    server: String,
    client: surf::Client<http_client::native::NativeClient>,
}

impl Client {
    /// Creates a new control client, bound to the given address.
    pub fn new(addr: impl AsRef<str>) -> Self {
        Client {
            server: addr.as_ref().to_string(),
            client: surf::Client::new(),
        }
    }

    /// Pings the daemon, returns `Ok(())` if sucessfull.
    pub async fn ping(&self) -> Result<()> {
        match self.post(&ControlRequest::Ping).await? {
            ControlResponse::Pong => Ok(()),
            res => Err(anyhow!("Invalid response: {:?}", res)),
        }
    }

    /// Stops a running daemon.
    pub async fn stop(&self) -> Result<()> {
        match self.post(&ControlRequest::Stop).await? {
            ControlResponse::Stopped => Ok(()),
            res => Err(anyhow!("invalid response: {:?}", res)),
        }
    }

    async fn post(&self, req: &ControlRequest) -> Result<ControlResponse> {
        let req = self.client.post(&self.server).body_json(req)?;
        let mut res = req.await.unwrap();

        if res.status() == 200 {
            let parsed = res.body_json().await?;
            Ok(parsed)
        } else {
            Err(anyhow!("not successfull: {}", res.status()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use async_std::{sync::channel, task};

    #[async_std::test]
    async fn test_server_client_basics() {
        let (sender, _receiver) = channel(1);
        let server = Server::new(sender);
        let s = task::spawn(async move { server.listen("127.0.0.1:8888").await.unwrap() });
        task::sleep(std::time::Duration::from_millis(400)).await;

        let client = Client::new("http://127.0.0.1:8888/");
        client.ping().await.unwrap();

        drop(s);
    }
}
