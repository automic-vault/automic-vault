use axum::Router;
use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post, put};
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, mpsc};

const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_NOTIFICATION_BYTES: usize = 2_500;
const RECENT_REGISTRATION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

#[derive(Clone)]
struct RelayState {
    rooms: Arc<Mutex<HashMap<String, Room>>>,
    revoked_rooms: Arc<Mutex<HashSet<String>>>,
    revocation_path: Arc<PathBuf>,
    apns: Option<ApnsClients>,
}

struct Room {
    credential: String,
    sender: broadcast::Sender<RoomMessage>,
    shutdown: broadcast::Sender<()>,
    registrations: HashMap<String, Registration>,
}

#[derive(Clone)]
struct RoomMessage {
    sender_id: String,
    bytes: Bytes,
}

struct Registration {
    token: String,
    environment: ApnsEnvironment,
    updated_at: Instant,
    updated_at_milliseconds: u64,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ApnsEnvironment {
    Sandbox,
    Production,
}

#[derive(Deserialize)]
struct RegistrationRequest {
    token: String,
    environment: ApnsEnvironment,
    proof: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationStatus {
    count: usize,
    most_recent_milliseconds: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Publication {
    message: Value,
    notification: Value,
    notification_id: Option<String>,
    #[serde(default)]
    silent: bool,
}

#[derive(Clone)]
struct ApnsClient {
    team_id: Arc<str>,
    key_id: Arc<str>,
    topic: Arc<str>,
    signing_key: Arc<EcdsaKeyPair>,
    client: reqwest::Client,
    token: Arc<Mutex<Option<(Instant, String)>>>,
}

#[derive(Clone)]
struct ApnsClients {
    sandbox: ApnsClient,
    production: ApnsClient,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind = env::var("AV_APPROVAL_RELAY_BIND").unwrap_or_else(|_| "127.0.0.1:8788".into());
    let revocation_path = env::var_os("AV_APPROVAL_RELAY_REVOCATIONS")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/av-approval-relay/revoked-rooms"));
    if let Some(parent) = revocation_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let revoked_rooms = load_revoked_rooms(&revocation_path)?;
    let state = RelayState {
        rooms: Arc::new(Mutex::new(HashMap::new())),
        revoked_rooms: Arc::new(Mutex::new(revoked_rooms)),
        revocation_path: Arc::new(revocation_path),
        apns: ApnsClients::from_environment()?,
    };
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    eprintln!("Automic Vault Approval relay listening on {bind}");
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn router(state: RelayState) -> Router {
    Router::new()
        .route("/health", get(|| async { StatusCode::NO_CONTENT }))
        .route("/v1/connect/{room}/{peer}", any(connect))
        .route("/v1/send/{room}/{peer}", post(send))
        .route("/v1/request/{room}/{peer}", post(publish))
        .route("/v1/register/{room}/{device}", put(register))
        .route("/v1/registrations/{room}", get(registration_status))
        .route("/v1/room/{room}", axum::routing::delete(revoke_room))
        .layer(DefaultBodyLimit::max(MAX_MESSAGE_BYTES))
        .with_state(state)
}

impl RelayState {
    fn authorize<T>(
        &self,
        room_id: &str,
        headers: &HeaderMap,
        body: impl FnOnce(&mut Room) -> T,
    ) -> Result<T, StatusCode> {
        if !valid_identifier(room_id) {
            return Err(StatusCode::BAD_REQUEST);
        }
        if self
            .revoked_rooms
            .lock()
            .expect("revoked rooms lock poisoned")
            .contains(room_id)
        {
            return Err(StatusCode::GONE);
        }
        let credential = bearer_credential(headers).ok_or(StatusCode::UNAUTHORIZED)?;
        let mut rooms = self.rooms.lock().expect("rooms lock poisoned");
        let room = rooms.entry(room_id.to_owned()).or_insert_with(|| {
            let (sender, _) = broadcast::channel(1024);
            let (shutdown, _) = broadcast::channel(1);
            Room {
                credential: credential.to_owned(),
                sender,
                shutdown,
                registrations: HashMap::new(),
            }
        });
        if room.credential != credential {
            return Err(StatusCode::UNAUTHORIZED);
        }
        Ok(body(room))
    }
}

async fn connect(
    ws: WebSocketUpgrade,
    Path((room_id, peer_id)): Path<(String, String)>,
    State(state): State<RelayState>,
    headers: HeaderMap,
) -> Response {
    if !valid_peer_id(&peer_id) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let channels = match state.authorize(&room_id, &headers, |room| {
        (room.sender.clone(), room.shutdown.subscribe())
    }) {
        Ok(channels) => channels,
        Err(status) => return status.into_response(),
    };
    ws.max_message_size(MAX_MESSAGE_BYTES)
        .on_upgrade(move |socket| relay_socket(socket, channels.0, channels.1, peer_id))
}

async fn relay_socket(
    socket: WebSocket,
    sender: broadcast::Sender<RoomMessage>,
    mut shutdown: broadcast::Receiver<()>,
    peer_id: String,
) {
    let mut receiver = sender.subscribe();
    let (mut websocket_sender, mut websocket_receiver) = socket.split();
    let (control_sender, mut control_receiver) = mpsc::unbounded_channel();
    let incoming_sender = sender.clone();
    let incoming_peer = peer_id.clone();
    let incoming = async move {
        while let Some(message) = websocket_receiver.next().await {
            match message {
                Ok(Message::Binary(bytes)) if bytes.len() <= MAX_MESSAGE_BYTES => {
                    let _ = incoming_sender.send(RoomMessage {
                        sender_id: incoming_peer.clone(),
                        bytes,
                    });
                }
                Ok(Message::Ping(bytes)) => {
                    if control_sender.send(Message::Pong(bytes)).is_err() {
                        break;
                    }
                }
                Ok(Message::Pong(_)) => {}
                Ok(Message::Close(_)) | Err(_) => break,
                Ok(Message::Text(_) | Message::Binary(_)) => break,
            }
        }
    };
    let outgoing = async move {
        loop {
            let message = tokio::select! {
                biased;
                value = control_receiver.recv() => match value {
                    Some(value) => value,
                    None => break,
                },
                value = receiver.recv() => match value {
                    Ok(value) if value.sender_id != peer_id => Message::Binary(value.bytes),
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                },
            };
            if websocket_sender.send(message).await.is_err() {
                break;
            }
        }
    };
    tokio::select! { _ = incoming => {}, _ = outgoing => {}, _ = shutdown.recv() => {} }
}

async fn revoke_room(
    Path(room_id): Path<String>,
    State(state): State<RelayState>,
    headers: HeaderMap,
) -> Result<StatusCode, StatusCode> {
    if !valid_identifier(&room_id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let credential = bearer_credential(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    if state
        .revoked_rooms
        .lock()
        .expect("revoked rooms lock poisoned")
        .contains(&room_id)
    {
        return Ok(StatusCode::NO_CONTENT);
    }
    let shutdown = {
        let rooms = state.rooms.lock().expect("rooms lock poisoned");
        if let Some(room) = rooms.get(&room_id) {
            if room.credential != credential {
                return Err(StatusCode::UNAUTHORIZED);
            }
            Some(room.shutdown.clone())
        } else {
            None
        }
    };
    append_revocation(&state.revocation_path, &room_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    state
        .revoked_rooms
        .lock()
        .expect("revoked rooms lock poisoned")
        .insert(room_id.clone());
    state
        .rooms
        .lock()
        .expect("rooms lock poisoned")
        .remove(&room_id);
    if let Some(shutdown) = shutdown {
        let _ = shutdown.send(());
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn send(
    Path((room_id, peer_id)): Path<(String, String)>,
    State(state): State<RelayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, StatusCode> {
    if !valid_peer_id(&peer_id) || body.is_empty() || body.len() > MAX_MESSAGE_BYTES {
        return Err(StatusCode::BAD_REQUEST);
    }
    let sender = state.authorize(&room_id, &headers, |room| room.sender.clone())?;
    let _ = sender.send(RoomMessage {
        sender_id: peer_id,
        bytes: body,
    });
    Ok(StatusCode::NO_CONTENT)
}

async fn publish(
    Path((room_id, peer_id)): Path<(String, String)>,
    State(state): State<RelayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, StatusCode> {
    if !valid_peer_id(&peer_id) || body.is_empty() || body.len() > MAX_MESSAGE_BYTES {
        return Err(StatusCode::BAD_REQUEST);
    }
    let publication: Publication =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let message = serde_json::to_vec(&publication.message).map_err(|_| StatusCode::BAD_REQUEST)?;
    let notification =
        serde_json::to_vec(&publication.notification).map_err(|_| StatusCode::BAD_REQUEST)?;
    if message.is_empty() || notification.is_empty() || notification.len() > MAX_NOTIFICATION_BYTES
    {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    if publication
        .notification_id
        .as_deref()
        .is_some_and(|value| !valid_identifier(value))
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let (sender, registrations) = state.authorize(&room_id, &headers, |room| {
        room.registrations
            .retain(|_, value| value.updated_at.elapsed() <= RECENT_REGISTRATION);
        let registrations = room
            .registrations
            .iter()
            .map(|(device, value)| (device.clone(), value.token.clone(), value.environment))
            .collect::<Vec<_>>();
        (room.sender.clone(), registrations)
    })?;
    let _ = sender.send(RoomMessage {
        sender_id: peer_id,
        bytes: Bytes::from(message),
    });
    if let Some(apns) = &state.apns {
        for (_, token, environment) in registrations {
            let _ = apns
                .push(
                    &token,
                    environment,
                    publication.notification.clone(),
                    publication.notification_id.as_deref(),
                    publication.silent,
                )
                .await;
        }
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn register(
    Path((room_id, device_id)): Path<(String, String)>,
    State(state): State<RelayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, StatusCode> {
    if !valid_peer_id(&device_id) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let request: RegistrationRequest =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    if !valid_device_token(&request.token) || !valid_identifier(&request.proof) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let apns = state.apns.as_ref().ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    apns.validate(&request.token, request.environment)
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    state.authorize(&room_id, &headers, |room| {
        room.registrations.insert(
            device_id,
            Registration {
                token: request.token,
                environment: request.environment,
                updated_at: Instant::now(),
                updated_at_milliseconds: unix_milliseconds(),
            },
        );
    })?;
    Ok(StatusCode::NO_CONTENT)
}

async fn registration_status(
    Path(room_id): Path<String>,
    State(state): State<RelayState>,
    headers: HeaderMap,
) -> Result<axum::Json<RegistrationStatus>, StatusCode> {
    state.authorize(&room_id, &headers, |room| {
        room.registrations
            .retain(|_, value| value.updated_at.elapsed() <= RECENT_REGISTRATION);
        axum::Json(RegistrationStatus {
            count: room.registrations.len(),
            most_recent_milliseconds: room
                .registrations
                .values()
                .map(|value| value.updated_at_milliseconds)
                .max(),
        })
    })
}

impl ApnsClients {
    fn from_environment() -> Result<Option<Self>, Box<dyn std::error::Error>> {
        let (sandbox_path, production_path) = match (
            env::var_os("AV_APNS_SANDBOX_PRIVATE_KEY"),
            env::var_os("AV_APNS_PRODUCTION_PRIVATE_KEY"),
        ) {
            (None, None) => return Ok(None),
            (Some(sandbox), Some(production)) => (sandbox, production),
            _ => return Err("both APNs private keys are required".into()),
        };
        let team_id: Arc<str> = env::var("AV_APNS_TEAM_ID")?.into();
        let topic: Arc<str> = env::var("AV_APNS_TOPIC")?.into();
        Ok(Some(Self {
            sandbox: ApnsClient::new(
                sandbox_path.into(),
                team_id.clone(),
                env::var("AV_APNS_SANDBOX_KEY_ID")?.into(),
                topic.clone(),
            )?,
            production: ApnsClient::new(
                production_path.into(),
                team_id,
                env::var("AV_APNS_PRODUCTION_KEY_ID")?.into(),
                topic,
            )?,
        }))
    }

    fn client(&self, environment: ApnsEnvironment) -> &ApnsClient {
        match environment {
            ApnsEnvironment::Sandbox => &self.sandbox,
            ApnsEnvironment::Production => &self.production,
        }
    }

    async fn push(
        &self,
        token: &str,
        environment: ApnsEnvironment,
        notification: Value,
        notification_id: Option<&str>,
        silent: bool,
    ) -> Result<(), ()> {
        self.client(environment)
            .push(token, environment, notification, notification_id, silent)
            .await
    }

    async fn validate(&self, token: &str, environment: ApnsEnvironment) -> Result<(), ()> {
        self.client(environment).validate(token, environment).await
    }
}

impl ApnsClient {
    fn new(
        path: PathBuf,
        team_id: Arc<str>,
        key_id: Arc<str>,
        topic: Arc<str>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let pem = std::fs::read_to_string(path)?;
        let encoded = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>();
        let der = base64::engine::general_purpose::STANDARD.decode(encoded)?;
        let rng = SystemRandom::new();
        let signing_key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der, &rng)
            .map_err(|_| "invalid APNs private key")?;
        Ok(Self {
            team_id,
            key_id,
            topic,
            signing_key: Arc::new(signing_key),
            client: reqwest::Client::builder().http2_prior_knowledge().build()?,
            token: Arc::new(Mutex::new(None)),
        })
    }

    async fn push(
        &self,
        token: &str,
        environment: ApnsEnvironment,
        notification: Value,
        notification_id: Option<&str>,
        silent: bool,
    ) -> Result<(), ()> {
        let host = match environment {
            ApnsEnvironment::Sandbox => "https://api.sandbox.push.apple.com",
            ApnsEnvironment::Production => "https://api.push.apple.com",
        };
        let (push_type, priority, payload) = apns_delivery(notification, silent);
        let mut request = self
            .client
            .post(format!("{host}/3/device/{token}"))
            .bearer_auth(self.bearer_token().map_err(|_| ())?)
            .header("apns-topic", self.topic.as_ref())
            .header("apns-push-type", push_type)
            .header("apns-priority", priority)
            .json(&payload);
        if let Some(notification_id) = notification_id {
            request = request.header("apns-collapse-id", notification_id);
        }
        let response = request.send().await.map_err(|_| ())?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(())
        }
    }

    async fn validate(&self, token: &str, environment: ApnsEnvironment) -> Result<(), ()> {
        let host = match environment {
            ApnsEnvironment::Sandbox => "https://api.sandbox.push.apple.com",
            ApnsEnvironment::Production => "https://api.push.apple.com",
        };
        let response = self
            .client
            .post(format!("{host}/3/device/{token}"))
            .bearer_auth(self.bearer_token().map_err(|_| ())?)
            .header("apns-topic", self.topic.as_ref())
            .header("apns-push-type", "background")
            .header("apns-priority", "5")
            .json(&json!({ "aps": { "content-available": 1 } }))
            .send()
            .await
            .map_err(|_| ())?;
        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let reason = response.text().await.unwrap_or_default();
            eprintln!("APNs device validation failed: status={status} response={reason}");
            Err(())
        }
    }

    fn bearer_token(&self) -> Result<String, ()> {
        let mut cached = self.token.lock().map_err(|_| ())?;
        if let Some((created, token)) = cached.as_ref()
            && created.elapsed() < Duration::from_secs(50 * 60)
        {
            return Ok(token.clone());
        }
        let encoder = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = encoder.encode(format!(r#"{{"alg":"ES256","kid":"{}"}}"#, self.key_id));
        let issued_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ())?
            .as_secs();
        let claims = encoder.encode(format!(r#"{{"iss":"{}","iat":{issued_at}}}"#, self.team_id));
        let signed = format!("{header}.{claims}");
        let signature = self
            .signing_key
            .sign(&SystemRandom::new(), signed.as_bytes())
            .map_err(|_| ())?;
        let token = format!("{signed}.{}", encoder.encode(signature.as_ref()));
        *cached = Some((Instant::now(), token.clone()));
        Ok(token)
    }
}

fn apns_delivery(notification: Value, silent: bool) -> (&'static str, &'static str, Value) {
    if silent {
        (
            "background",
            "5",
            json!({ "aps": { "content-available": 1 }, "av": notification }),
        )
    } else {
        (
            "alert",
            "10",
            json!({
                "aps": {
                    "alert": { "title": "Automic Vault update", "body": "Open Automic Vault to review" },
                    "mutable-content": 1,
                    "category": "AV_REVIEW"
                },
                "av": notification
            }),
        )
    }
}

fn bearer_credential(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .filter(|value| valid_identifier(value))
}

fn valid_identifier(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn valid_peer_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn valid_device_token(value: &str) -> bool {
    (64..=200).contains(&value.len())
        && value.len().is_multiple_of(2)
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn unix_milliseconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn load_revoked_rooms(path: &PathBuf) -> std::io::Result<HashSet<String>> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(HashSet::new()),
        Err(error) => return Err(error),
    };
    contents
        .lines()
        .map(|line| {
            if valid_identifier(line) {
                Ok(line.to_owned())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid revoked room identifier",
                ))
            }
        })
        .collect()
}

fn append_revocation(path: &PathBuf, room_id: &str) -> std::io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{room_id}")?;
    file.sync_data()
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_boundary_inputs_are_strict() {
        assert!(valid_identifier(&"a".repeat(43)));
        assert!(!valid_identifier(&"a".repeat(42)));
        assert!(valid_peer_id("phone-A1_2"));
        assert!(!valid_peer_id("two phones"));
        assert!(valid_device_token(&"0a".repeat(32)));
        assert!(!valid_device_token(&"zz".repeat(32)));
    }

    #[test]
    fn cancellation_delivery_is_silent() {
        let (push_type, priority, payload) = apns_delivery(json!({ "ciphertext": true }), true);
        assert_eq!(push_type, "background");
        assert_eq!(priority, "5");
        assert_eq!(payload["aps"], json!({ "content-available": 1 }));
        assert!(payload["aps"].get("alert").is_none());
    }

    #[test]
    fn revoked_rooms_are_strict_and_durable() {
        let path = std::env::temp_dir().join(format!(
            "av-approval-relay-revocations-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let room = "r".repeat(43);
        append_revocation(&path, &room).unwrap();
        assert_eq!(load_revoked_rooms(&path).unwrap(), HashSet::from([room]));
        std::fs::remove_file(path).unwrap();
    }
}
