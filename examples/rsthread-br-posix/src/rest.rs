//! REST API and status page for rsthread-br-posix.
//!
//! Implements the otbr-agent–compatible `/api/v1/node` surface:
//!
//! | Method | Path                           | Description               |
//! |--------|--------------------------------|---------------------------|
//! | GET    | /                              | HTML status page          |
//! | GET    | /api/v1/node                   | Full node info (JSON)     |
//! | GET    | /api/v1/node/state             | Thread role (JSON)        |
//! | GET    | /api/v1/node/dataset/active    | Active dataset (hex)      |
//! | POST   | /api/v1/node/dataset/active    | Set active dataset (hex)  |
//! | DELETE | /api/v1/node                   | Factory reset (501)       |

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use tokio::sync::{mpsc, watch};

// ── Shared state ─────────────────────────────────────────────────────────────

/// Snapshot of node state, updated on every `wait_changed()` tick.
#[derive(Clone, Default, Serialize)]
pub struct NodeSnapshot {
    pub role: String,
    pub ext_address: String,
    pub rloc16: String,
    pub network_name: String,
    pub channel: u8,
    pub pan_id: String,
    pub omr_prefix: String,
    pub dataset_tlvs_hex: String,
}

/// Commands sent from the HTTP layer into the OT LocalSet.
pub enum BrCommand {
    SetDatasetTlv(Vec<u8>),
}

/// axum shared state — cheaply cloneable (watch + mpsc handles).
#[derive(Clone)]
pub struct AppState {
    pub node_rx: watch::Receiver<NodeSnapshot>,
    pub cmd_tx: mpsc::Sender<BrCommand>,
}

// ── Router ───────────────────────────────────────────────────────────────────

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(handle_index))
        .route("/api/v1/node", get(api_node).delete(api_node_delete))
        .route("/api/v1/node/state", get(api_node_state))
        .route(
            "/api/v1/node/dataset/active",
            get(api_dataset_get).post(api_dataset_set),
        )
        .with_state(state)
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn handle_index() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        STATUS_HTML,
    )
}

async fn api_node(State(s): State<AppState>) -> Json<NodeSnapshot> {
    Json(s.node_rx.borrow().clone())
}

async fn api_node_state(State(s): State<AppState>) -> impl IntoResponse {
    let role = s.node_rx.borrow().role.clone();
    Json(serde_json::json!({ "State": role }))
}

async fn api_dataset_get(State(s): State<AppState>) -> impl IntoResponse {
    let hex = s.node_rx.borrow().dataset_tlvs_hex.clone();
    if hex.is_empty() {
        StatusCode::NO_CONTENT.into_response()
    } else {
        (StatusCode::OK, [("content-type", "text/plain")], hex).into_response()
    }
}

async fn api_dataset_set(State(s): State<AppState>, body: Bytes) -> StatusCode {
    let text = String::from_utf8_lossy(&body);
    let Some(tlvs) = hex_to_bytes(text.trim()) else {
        return StatusCode::UNPROCESSABLE_ENTITY;
    };
    if s.cmd_tx.send(BrCommand::SetDatasetTlv(tlvs)).await.is_ok() {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn api_node_delete() -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

// ── Embedded status page ──────────────────────────────────────────────────────

const STATUS_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>rs-thread Border Router</title>
<style>
  :root { --bg:#fff; --fg:#111; --subtle:#666; --border:#e5e5e5; --tag-bg:#f0fdf4; --tag-fg:#166534 }
  @media (prefers-color-scheme:dark) {
    :root:not([data-theme="light"]) {
      --bg:#0f0f0f; --fg:#eee; --subtle:#999; --border:#2a2a2a;
      --tag-bg:#14532d; --tag-fg:#bbf7d0; color-scheme:dark
    }
  }
  :root[data-theme="dark"] { --bg:#0f0f0f; --fg:#eee; --subtle:#999; --border:#2a2a2a; --tag-bg:#14532d; --tag-fg:#bbf7d0; color-scheme:dark }
  * { box-sizing:border-box; margin:0; padding:0 }
  body { background:var(--bg); color:var(--fg); font:14px/1.6 system-ui,sans-serif;
         padding: max(1.5rem,env(safe-area-inset-top,0px)) max(1rem,env(safe-area-inset-right,0px))
                  max(1rem,env(safe-area-inset-bottom,0px)) max(1rem,env(safe-area-inset-left,0px)) }
  h1 { font-size:1.1rem; font-weight:600; letter-spacing:.02em; margin-bottom:1.25rem }
  table { width:100%; border-collapse:collapse }
  tr { border-bottom:1px solid var(--border) }
  td { padding:.5rem .25rem }
  td:first-child { color:var(--subtle); width:38%; font-size:.85rem; text-transform:uppercase; letter-spacing:.04em }
  .tag { display:inline-block; padding:.15em .55em; border-radius:4px; font-size:.8em; font-weight:600;
         background:var(--tag-bg); color:var(--tag-fg) }
  .tag.off { --tag-bg:#fef2f2; --tag-fg:#991b1b }
  .tag.mid { --tag-bg:#fefce8; --tag-fg:#854d0e }
  #status { font-size:.75rem; color:var(--subtle); margin-top:1rem }
</style>
</head>
<body>
<h1>rs-thread Border Router</h1>
<table id="tbl"><tr><td colspan="2">Loading…</td></tr></table>
<p id="status"></p>
<script>
function roleClass(r) {
  const lo = (r||'').toLowerCase();
  if (lo === 'leader' || lo === 'router') return '';
  if (lo === 'child') return 'mid';
  return 'off';
}
async function refresh() {
  try {
    const d = await fetch('/api/v1/node').then(r => r.json());
    const rows = [
      ['Role',    `<span class="tag ${roleClass(d.role)}">${d.role||'—'}</span>`],
      ['Ext Addr', d.ext_address || '—'],
      ['RLOC16',   d.rloc16 || '—'],
      ['Network',  d.network_name || '—'],
      ['Channel',  d.channel != null ? d.channel : '—'],
      ['PAN ID',   d.pan_id || '—'],
      ['OMR Prefix', d.omr_prefix || '—'],
    ];
    document.getElementById('tbl').innerHTML =
      rows.map(([k,v]) => `<tr><td>${k}</td><td>${v}</td></tr>`).join('');
    document.getElementById('status').textContent =
      'Last updated ' + new Date().toLocaleTimeString();
  } catch(e) {
    document.getElementById('status').textContent = 'Fetch error: ' + e;
  }
  setTimeout(refresh, 3000);
}
refresh();
</script>
</body>
</html>"#;
