use crate::storage::AuditStore;
use anyhow::Result;
use argus_common::codec::{decode_events_jsonl, decompress_and_deserialize_events};
use argus_common::events::AuditEvent;
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use bytes::Bytes;
use serde::Deserialize;
use std::net::SocketAddr;
use tracing::{error, info};
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub store: AuditStore,
}

pub struct CollectorServer {
    state: AppState,
    bind_addr: SocketAddr,
}

impl CollectorServer {
    pub fn new(store: AuditStore, bind_addr: SocketAddr) -> Self {
        Self {
            state: AppState { store },
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
                return StatusCode::INTERNAL_SERVER_ERROR;
            }
            StatusCode::ACCEPTED
        }
        Err(e) => {
            error!("Failed to decode incoming audit events payload: {e}");
            StatusCode::BAD_REQUEST
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
