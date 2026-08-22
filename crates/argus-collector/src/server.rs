use crate::storage::AuditStore;
use anyhow::Result;
use argus_common::codec::{decode_events_jsonl, decompress_and_deserialize_events};
use argus_common::events::AuditEvent;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
    routing::{get, post},
    Json, Router,
};
use bytes::Bytes;
use futures::stream::Stream;
use serde::Deserialize;
use std::collections::HashSet;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tracing::{error, info};
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub store: AuditStore,
    pub event_tx: broadcast::Sender<AuditEvent>,
    pub killed_sessions: Arc<Mutex<HashSet<Uuid>>>,
}

pub struct CollectorServer {
    state: AppState,
    bind_addr: SocketAddr,
}

impl CollectorServer {
    pub fn new(store: AuditStore, bind_addr: SocketAddr) -> Self {
        let (event_tx, _) = broadcast::channel(1024);
        Self {
            state: AppState {
                store,
                event_tx,
                killed_sessions: Arc::new(Mutex::new(HashSet::new())),
            },
            bind_addr,
        }
    }

    pub fn build_router(state: AppState) -> Router {
        Router::new()
            .route("/health", get(health_handler))
            .route("/api/v1/events", post(ingest_events_handler))
            .route("/api/v1/sessions", get(list_sessions_handler))
            .route(
                "/api/v1/sessions/:id/events",
                get(get_session_events_handler),
            )
            .route("/api/v1/sessions/:id/verify", get(verify_session_handler))
            .route("/api/v1/sessions/:id/live", get(live_session_sse_handler))
            .route("/api/v1/sessions/:id/kill", post(kill_session_handler))
            .route("/api/v1/sessions/:id/check-kill", get(check_kill_handler))
            .with_state(state)
    }

    pub async fn run(self) -> Result<()> {
        let app = Self::build_router(self.state);
        info!("Starting Argus Collector daemon on {}", self.bind_addr);
        let listener = tokio::net::TcpListener::bind(self.bind_addr).await?;
        axum::serve(listener, app).await?;
        Ok(())
    }
}

async fn health_handler() -> &'static str {
    "OK"
}

async fn ingest_events_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let is_zstd = headers
        .get("Content-Encoding")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("zstd"))
        .unwrap_or(false);

    let events_res: Result<Vec<AuditEvent>> = if is_zstd {
        decompress_and_deserialize_events(&body)
    } else {
        decode_events_jsonl(&body)
    };

    match events_res {
        Ok(events) => {
            if let Err(e) = state.store.insert_batch(&events) {
                error!("Failed to persist audit events batch: {e}");
                return (StatusCode::INTERNAL_SERVER_ERROR, HeaderMap::new());
            }

            let mut resp_headers = HeaderMap::new();
            let killed = state.killed_sessions.lock().unwrap();

            // Broadcast events to live stream listeners & check for kill status
            for ev in &events {
                let _ = state.event_tx.send(ev.clone());
                if let Some(sid) = ev.session_id() {
                    if killed.contains(&sid) {
                        resp_headers.insert("X-Argus-Force-Kill", "1".parse().unwrap());
                    }
                }
            }

            (StatusCode::ACCEPTED, resp_headers)
        }
        Err(e) => {
            error!("Failed to decode incoming audit events payload: {e}");
            (StatusCode::BAD_REQUEST, HeaderMap::new())
        }
    }
}

#[derive(Deserialize)]
struct ListQuery {
    limit: Option<usize>,
}

async fn list_sessions_handler(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<crate::storage::SessionSummary>>, StatusCode> {
    let limit = query.limit.unwrap_or(50);
    match state.store.list_sessions(limit) {
        Ok(sessions) => Ok(Json(sessions)),
        Err(e) => {
            error!("Failed to list sessions: {e}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn get_session_events_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Vec<AuditEvent>>, StatusCode> {
    let session_id = match Uuid::parse_str(&id) {
        Ok(uid) => uid,
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };

    match state.store.get_session_events(session_id) {
        Ok(events) => Ok(Json(events)),
        Err(e) => {
            error!("Failed to get session events for {session_id}: {e}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn verify_session_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let session_id = match Uuid::parse_str(&id) {
        Ok(uid) => uid,
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };

    match state.store.verify_session_integrity(session_id) {
        Ok(_) => Ok(Json(serde_json::json!({
            "session_id": session_id,
            "status": "verified",
            "tamper_detected": false,
            "message": "Cryptographic hash chain is mathematically intact"
        }))),
        Err(e) => Ok(Json(serde_json::json!({
            "session_id": session_id,
            "status": "tampered",
            "tamper_detected": true,
            "error": e.to_string()
        }))),
    }
}

async fn live_session_sse_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, StatusCode> {
    let target_sid = match Uuid::parse_str(&id) {
        Ok(uid) => uid,
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };

    let rx = state.event_tx.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(move |item| {
        if let Ok(event) = item {
            if event.session_id() == Some(target_sid) {
                if let Ok(json) = serde_json::to_string(&event) {
                    return Some(Ok(Event::default().data(json)));
                }
            }
        }
        None
    });

    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(5))))
}

async fn kill_session_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let session_id = match Uuid::parse_str(&id) {
        Ok(uid) => uid,
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };

    state.killed_sessions.lock().unwrap().insert(session_id);
    info!("Session {} added to force-kill list", session_id);

    Ok(Json(serde_json::json!({
        "session_id": session_id,
        "action": "force_kill_issued",
        "status": "pending_agent_termination"
    })))
}

async fn check_kill_handler(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let session_id = match Uuid::parse_str(&id) {
        Ok(uid) => uid,
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };

    let is_killed = state.killed_sessions.lock().unwrap().contains(&session_id);
    Ok(Json(serde_json::json!({
        "session_id": session_id,
        "killed": is_killed
    })))
}
