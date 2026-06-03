#!/usr/bin/env bash
# Explainable Hierarchical Hybrid IDS — Phase 4 installer
#
# Dissertation-aligned data roles (see configs/phase4_dataset_manifest_v1.json):
#   - Model V1 (Parent): supervised training on ENT-01 (CIC-IDS2017) only.
#   - Model V2: optional hybrid Parent model trained later; not used for initial
#     baseline evaluation; must not reuse V1 test rows (policy + leakage guard).
#   - REP-01 (CTU-13): replay-only PCAP path — never for training, validation, or
#     supervised test accuracy.
#   - REF-01 (NSL-KDD): reference-only — never in experimental pipelines.
#   - Leakage guard / experiment_guard must pass before any training run.
#
# Host layout (DATA_ROOT, default ./data under repo): outputs, logs, and Chapter 4
# CSV placeholders. Canonical dataset files live under IDS_SCRATCH_RAW_DOWNLOADS
# (default /srv/scratch/ids_final_amity/raw_downloads on the server, or
# DATA_ROOT/raw_downloads for local dev). clean-install resets PostgreSQL data.
# clean-install --f wipes most host + stack data while preserving
# CLEAN_INSTALL_IMMUTABLE_RAW (default /srv/scratch/ids_final_amity/raw_downloads).
#
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SOURCE_REPO="${SOURCE_REPO:-$SCRIPT_DIR}"
SOURCE_REPO_REAL="$(cd "$SOURCE_REPO" && pwd -P)"

STACK_NAME="${STACK_NAME:-ids-project}"
PROJECT_LABEL="${IDS_PROJECT_LABEL:-IDS-Project}"
DASHBOARD_PORT="${IDS_DASHBOARD_PORT:-18081}"
DATA_ROOT="${DATA_ROOT:-$SOURCE_REPO_REAL/data}"

# Flat raw layout: IDS_SCRATCH_RAW_DOWNLOADS/<DATASET_ID> (Compose bind -> /data/raw_downloads).
IDS_SCRATCH_RAW_DOWNLOADS="${IDS_SCRATCH_RAW_DOWNLOADS:-$DATA_ROOT/raw_downloads}"

NETWORK_WAIT_SECONDS="${NETWORK_WAIT_SECONDS:-120}"
CLEAN_WAIT_SECONDS="${CLEAN_WAIT_SECONDS:-180}"
FORCE_CLEAN_WAIT_SECONDS="${FORCE_CLEAN_WAIT_SECONDS:-45}"
FORCE_NETWORK_WAIT_SECONDS="${FORCE_NETWORK_WAIT_SECONDS:-45}"
STEP1_TABLESPACE_NAME="${STEP1_TABLESPACE_NAME:-step2_tablespace}"
STEP1_TABLESPACE_LOCATION="${STEP1_TABLESPACE_LOCATION:-/srv/data/ids_final/step2_tablespace}"
STEP3_V2_TABLESPACE_NAME="${STEP3_V2_TABLESPACE_NAME:-step3_v2_cold}"
STEP3_V2_TABLESPACE_LOCATION="${STEP3_V2_TABLESPACE_LOCATION:-/srv/data/ids_final/step3_v2_tablespace}"
STEP3_V2_TABLESPACE_DIR="${STEP3_V2_TABLESPACE_DIR:-/srv/data/ids_final}"

STACK_FILE_REL="deploy/stack/phase4-data-pipeline-stack.yml"
PHASE4_PY_IMAGE_REL="deploy/images/phase4-python/Dockerfile"
PHASE4_DASHBOARD_IMAGE_REL="deploy/images/phase4-dashboard/Dockerfile"
PHASE4_POSTGRES_IMAGE_REL="deploy/images/phase4-postgres/Dockerfile"
MANIFEST_REL="configs/phase4_dataset_manifest_v1.json"
HYBRID_POLICY_REL="configs/phase4_hybrid_data_policy_v1.json"
DASHBOARD_NGINX_REL="docs/ops/nginx_phase4_dashboard.conf"
NEW_DASHBOARD_REL="docs/ops/new_dashboard"
NEW_DASHBOARD_INDEX_REL="${NEW_DASHBOARD_REL}/index.html"
NEW_DASHBOARD_APP_REL="${NEW_DASHBOARD_REL}/app.js"
NEW_DASHBOARD_STYLES_REL="${NEW_DASHBOARD_REL}/styles.css"
NEW_DASHBOARD_STEP3_TAB_REL="${NEW_DASHBOARD_REL}/step3_v2_tab.js"
POSTGRES_SCHEMA_REL="schemas/postgres_phase4_split_schema.sql"
POSTGRES_GOVERNANCE_REL="schemas/postgres_phase4_governance_v1.sql"
POSTGRES_GOVERNED_VIEWS_REL="schemas/postgres_phase4_governed_views_v1.sql"
POSTGRES_HYPOTHESIS_REL="schemas/postgres_phase4_hypothesis_results_v1.sql"
POSTGRES_MODEL_WORKFLOW_REL="schemas/postgres_phase4_model_v1_workflow.sql"
POSTGRES_PRUNE_STEP1_TO_STEP3_REL="schemas/postgres_phase4_prune_step1_to_step3.sql"
POSTGRES_PRUNE_STEP2_TO_STEP3_REL="schemas/postgres_phase4_prune_step2_to_step3.sql"
POSTGRES_PRUNE_STEP3_ONLY_REL="schemas/postgres_phase4_prune_step3_only.sql"
POSTGRES_PRUNE_STEP4_ONLY_REL="schemas/postgres_phase4_prune_step4_only.sql"
POSTGRES_LOADER_REL="scripts/phase4_load_splits_to_postgres.sh"
UPLOAD_API_REL="services_parent/upload_api/phase4_upload_api.py"
DASH_API_REL="services_parent/dashboard_api/phase4_dash_api.py"
INGESTION_WORKER_REL="services_parent/orchestration/phase4_ingestion_worker.py"

STACK_FILE_SRC="$SOURCE_REPO_REAL/$STACK_FILE_REL"
PHASE4_PY_IMAGE_SRC="$SOURCE_REPO_REAL/$PHASE4_PY_IMAGE_REL"
PHASE4_DASHBOARD_IMAGE_SRC="$SOURCE_REPO_REAL/$PHASE4_DASHBOARD_IMAGE_REL"
PHASE4_POSTGRES_IMAGE_SRC="$SOURCE_REPO_REAL/$PHASE4_POSTGRES_IMAGE_REL"
MANIFEST_SRC="$SOURCE_REPO_REAL/$MANIFEST_REL"
HYBRID_POLICY_SRC="$SOURCE_REPO_REAL/$HYBRID_POLICY_REL"
UPLOAD_API_SRC="$SOURCE_REPO_REAL/$UPLOAD_API_REL"
DASH_API_SRC="$SOURCE_REPO_REAL/$DASH_API_REL"
INGESTION_WORKER_SRC="$SOURCE_REPO_REAL/$INGESTION_WORKER_REL"
DASHBOARD_NGINX_SRC="$SOURCE_REPO_REAL/$DASHBOARD_NGINX_REL"
NEW_DASHBOARD_INDEX_SRC="$SOURCE_REPO_REAL/$NEW_DASHBOARD_INDEX_REL"
NEW_DASHBOARD_APP_SRC="$SOURCE_REPO_REAL/$NEW_DASHBOARD_APP_REL"
NEW_DASHBOARD_STYLES_SRC="$SOURCE_REPO_REAL/$NEW_DASHBOARD_STYLES_REL"
NEW_DASHBOARD_STEP3_TAB_SRC="$SOURCE_REPO_REAL/$NEW_DASHBOARD_STEP3_TAB_REL"
POSTGRES_SCHEMA_SRC="$SOURCE_REPO_REAL/$POSTGRES_SCHEMA_REL"
POSTGRES_GOVERNANCE_SRC="$SOURCE_REPO_REAL/$POSTGRES_GOVERNANCE_REL"
POSTGRES_GOVERNED_VIEWS_SRC="$SOURCE_REPO_REAL/$POSTGRES_GOVERNED_VIEWS_REL"
POSTGRES_HYPOTHESIS_SRC="$SOURCE_REPO_REAL/$POSTGRES_HYPOTHESIS_REL"
POSTGRES_MODEL_WORKFLOW_SRC="$SOURCE_REPO_REAL/$POSTGRES_MODEL_WORKFLOW_REL"
POSTGRES_PRUNE_STEP1_TO_STEP3_SRC="$SOURCE_REPO_REAL/$POSTGRES_PRUNE_STEP1_TO_STEP3_REL"
POSTGRES_PRUNE_STEP2_TO_STEP3_SRC="$SOURCE_REPO_REAL/$POSTGRES_PRUNE_STEP2_TO_STEP3_REL"
POSTGRES_PRUNE_STEP3_ONLY_SRC="$SOURCE_REPO_REAL/$POSTGRES_PRUNE_STEP3_ONLY_REL"
POSTGRES_PRUNE_STEP4_ONLY_SRC="$SOURCE_REPO_REAL/$POSTGRES_PRUNE_STEP4_ONLY_REL"
POSTGRES_LOADER_SRC="$SOURCE_REPO_REAL/$POSTGRES_LOADER_REL"

ENV_EXAMPLE="$SOURCE_REPO_REAL/.env.example"
ENV_FILE="$SOURCE_REPO_REAL/.env"

MODE="clean-install"
CLEAN_INSTALL_FORCE=0
INSTALL_SAFE_MODE="${INSTALL_SAFE_MODE:-true}"
PRESERVE_DATA="${PRESERVE_DATA:-true}"
PRESERVE_POSTGRES="${PRESERVE_POSTGRES:-false}"
PRESERVE_MODEL_ARTIFACTS="${PRESERVE_MODEL_ARTIFACTS:-true}"

info() { printf '[install][info] %s\n' "$*"; }
warn() { printf '[install][warn] %s\n' "$*" >&2; }
error() { printf '[install][error] %s\n' "$*" >&2; }
success() { printf '[install][ok] %s\n' "$*"; }

log() { info "$@"; }
die() { error "$1"; exit 1; }

usage() {
  cat <<'EOF'
Explainable Hierarchical Hybrid IDS — install.sh

Usage:
  ./install.sh clean-install [--f]
  ./install.sh STEP1
  ./install.sh STEP2
  ./install.sh STEP3
  ./install.sh STEP4
  ./install.sh DASHBOARD
  ./install.sh REBUILD

Options:
  --f                      With clean-install only: delete stack volumes and host data except
                           CLEAN_INSTALL_IMMUTABLE_RAW.
  --network-wait-seconds N Wait for Compose networks and dashboard port (default: 120, 0 to skip).
  --no-network-wait        Same as --network-wait-seconds 0.
  --f in clean-install uses shorter default waits unless explicitly overridden:
                           FORCE_CLEAN_WAIT_SECONDS (default 45),
                           FORCE_NETWORK_WAIT_SECONDS (default 45).

Environment (common):
  SOURCE_REPO              Repo root (default: directory containing this script).
  STACK_NAME               Docker Compose project name (default: ids-project).
  DATA_ROOT                Host data root (default: <repo>/data).
  IDS_DASHBOARD_PORT       Published dashboard port (default: 18081).
  IDS_DASHBOARD_HOST_BIND  Host bind address for that port (default: 0.0.0.0 = all interfaces;
                           use 127.0.0.1 for localhost-only). Remote clients open http://<host-ip>:PORT.
  IDS_SCRATCH_RAW_DOWNLOADS
                           Host bind mount for /data/raw_downloads (default DATA_ROOT/raw_downloads;
                           set to /srv/scratch/ids_final_amity/raw_downloads on the dissertation server).
  CLEAN_INSTALL_IMMUTABLE_RAW
                           Absolute path preserved when running clean-install --f
                           (default /srv/scratch/ids_final_amity/raw_downloads).
  IDS_MANIFEST_HOST_ROOT   Prefix for manifest server_target_dir remapping in containers (default
                           /srv/scratch/ids_final_amity; exported to PHASE4_MANIFEST_HOST_ROOT in Compose).
  STEP1_TABLESPACE_NAME    PostgreSQL tablespace name for Step 1 large split/canonical tables
                           (default: step2_tablespace).
  STEP1_TABLESPACE_LOCATION
                           PostgreSQL tablespace path inside container host mount
                           (default: /srv/data/ids_final/step2_tablespace).
  STEP3_V2_TABLESPACE_NAME Step3 V2 tablespace name for simulation cold tables
                           (default: step3_v2_cold).
  STEP3_V2_TABLESPACE_LOCATION
                           Step3 V2 tablespace location inside Postgres host mount
                           (default: /srv/data/ids_final/step3_v2_tablespace).
  STEP3_V2_TABLESPACE_DIR  Host path bind-mounted to /srv/data/ids_final in Postgres container
                           (default: /srv/data/ids_final).

Compose images (optional overrides):
  IDS_PHASE4_PY_IMAGE IDS_DASHBOARD_IMAGE IDS_POSTGRES_IMAGE

Modes:
  clean-install
    Resets PostgreSQL host data, preserves Postgres container, and rebuilds all non-Postgres containers.
  clean-install --f
    Full destructive teardown; removes stack containers (including Postgres container), volumes, and host data except immutable RAW path.
  STEP1
    Reset Step1-Step3 data (filesystem + PostgreSQL tables), preserving RAW_DOWNLOADS, then rebuild non-Postgres containers.
    Also reapplies Step 1 schema bundle and Step 1 tablespace layout for large split/canonical tables.
  STEP2
    Reset Step2-Step3 data (filesystem + PostgreSQL tables), preserving Step1 and RAW_DOWNLOADS, then rebuild non-Postgres containers.
  STEP3
    Reset Step3 data only (filesystem + PostgreSQL tables), then rebuild non-Postgres containers.
  STEP4
    Reset Step4/dissertation result data only (filesystem + PostgreSQL tables), then rebuild non-Postgres containers.
  DASHBOARD
    Rebuild and recreate dashboard-only services (`dataset-download-dashboard`, `phase4-dash-api`)
    without resetting data, PostgreSQL, or other services.
    Main route:
      - /            (new dashboard: Step1/Step2/Step3/Step4/Governance/Storage)
    Compatibility route:
      - /new_dashboard/index.html
  REBUILD
    Rebuild and force-recreate the full Compose stack without deleting host data,
    Docker volumes, or PostgreSQL data.

Named Docker volumes for this stack (e.g. Redis) are removed only with clean-install --f.

Dissertation reminders:
  - Model V1: train on ENT-01 only.
  - Model V2: optional; leakage-safe; not baseline for initial Chapter 4 tables unless enabled.
  - REP-01: replay-only (no supervised training or accuracy benchmarking).
  - REF-01: reference-only (not in experiments).
EOF
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

compose_cmd() {
  docker compose -p "$STACK_NAME" -f "$STACK_FILE_SRC" "$@"
}

canonical_path() {
  local target="$1"
  if [[ -d "$target" ]]; then
    (cd "$target" >/dev/null 2>&1 && pwd -P) || die "Unable to resolve path: $target"
    return
  fi
  (cd "$(dirname "$target")" >/dev/null 2>&1 && printf '%s/%s\n' "$(pwd -P)" "$(basename "$target")") ||
    die "Unable to resolve path: $target"
}

immutable_clean_install_root() {
  local imm="${CLEAN_INSTALL_IMMUTABLE_RAW:-/srv/scratch/ids_final_amity/raw_downloads}"
  imm="${imm%/}"
  if [[ -d "$imm" ]]; then
    (cd "$imm" >/dev/null 2>&1 && pwd -P) || printf '%s\n' "$imm"
  else
    printf '%s\n' "$imm"
  fi
}

# Deletes target with rm -rf unless it is the immutable raw tree or inside it; if target is an
# ancestor of that tree, only non-immutable children are removed.
force_delete_path_respecting_immutable() {
  local target="$1"
  local imm
  imm="$(immutable_clean_install_root)"
  [[ -n "$target" ]] || return 0
  [[ -e "$target" ]] || return 0

  local t
  if [[ -d "$target" ]]; then
    t="$(cd "$target" >/dev/null 2>&1 && pwd -P)" || t="$target"
  else
    t="$(canonical_path "$target")"
  fi

  if [[ "$t" == "$imm" ]] || [[ "$t" == "$imm/"* ]]; then
    return 0
  fi
  if [[ "$imm" == "$t/"* ]]; then
    local item
    shopt -s dotglob nullglob
    for item in "$t"/*; do
      [[ -e "$item" ]] || continue
      force_delete_path_respecting_immutable "$item"
    done
    shopt -u dotglob nullglob 2>/dev/null || true
    return 0
  fi
  warn "Force deleting: $t"
  rm -rf "$t"
}

force_clean_install_wipe_host() {
  local imm
  imm="$(immutable_clean_install_root)"
  warn "Force clean-install: wiping host paths (immutable: $imm); PostgreSQL data will be reset."
  if [[ -d "$DATA_ROOT" ]]; then
    local item item_real
    shopt -s dotglob nullglob
    for item in "$DATA_ROOT"/*; do
      [[ -e "$item" ]] || continue
      if [[ -d "$item" ]]; then
        item_real="$(cd "$item" >/dev/null 2>&1 && pwd -P)" || item_real="$item"
      else
        item_real="$(canonical_path "$item")"
      fi
      force_delete_path_respecting_immutable "$item"
    done
    shopt -u dotglob nullglob 2>/dev/null || true
  fi
  force_delete_path_respecting_immutable "${IDS_MANIFEST_HOST_ROOT:-/srv/scratch/ids_final_amity}"
  mkdir -p "$DATA_ROOT" "$IDS_SCRATCH_RAW_DOWNLOADS" "$POSTGRES_DATA_DIR" || true
}

wipe_postgres_host_data() {
  local pg_path=""
  if [[ -d "$POSTGRES_DATA_DIR" ]]; then
    pg_path="$(cd "$POSTGRES_DATA_DIR" >/dev/null 2>&1 && pwd -P)" || pg_path="$POSTGRES_DATA_DIR"
  else
    pg_path="$(canonical_path "$POSTGRES_DATA_DIR")"
  fi
  info "Postgres data reset checklist:"
  rm -rf "$pg_path"
  mkdir -p "$POSTGRES_DATA_DIR"
  info "  [x] cluster data directory reset"
}

wipe_postgres_tablespace_host_data() {
  local paths=()
  local seen='|'
  local p=""
  local resolved=""
  local wiped_count=0
  paths+=("${STEP1_TABLESPACE_LOCATION:-}")
  paths+=("${STEP3_V2_TABLESPACE_LOCATION:-}")

  info "Postgres tablespace reset checklist:"
  for p in "${paths[@]}"; do
    p="${p%/}"
    [[ -n "$p" ]] || continue
    if [[ "$p" == "/" ]]; then
      continue
    fi
    if [[ "$seen" == *"|${p}|"* ]]; then
      continue
    fi
    seen="${seen}${p}|"
    if [[ -d "$p" ]]; then
      resolved="$(cd "$p" >/dev/null 2>&1 && pwd -P)" || resolved="$p"
    else
      resolved="$p"
    fi
    rm -rf "$resolved"
    mkdir -p "$p"
    wiped_count=$((wiped_count + 1))
  done
  info "  [x] tablespace host paths reset (${wiped_count})"
}

parse_args() {
  local positional=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      clean-install)
        MODE="clean-install"
        positional=1
        shift
        ;;
      STEP1|STEP2|STEP3|STEP4|DASHBOARD|REBUILD)
        MODE="$1"
        positional=1
        shift
        ;;
      --f)
        CLEAN_INSTALL_FORCE=1
        shift
        ;;
      --network-wait-seconds)
        [[ $# -ge 2 && "$2" =~ ^[0-9]+$ ]] || die "--network-wait-seconds requires a non-negative integer"
        NETWORK_WAIT_SECONDS="$2"
        shift 2
        ;;
      --no-network-wait)
        NETWORK_WAIT_SECONDS=0
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "Unknown argument: $1 (use --help)"
        ;;
    esac
  done

  if [[ "$positional" -eq 0 ]]; then
    MODE="clean-install"
  fi

  if [[ "$CLEAN_INSTALL_FORCE" -eq 1 && "$MODE" != "clean-install" ]]; then
    die "--f is only valid with clean-install."
  fi
}

preflight_os() {
  case "$(uname -s)" in
    Linux|Darwin) info "Host OS: $(uname -s) ($(uname -m))" ;;
    *) warn "Unsupported or untested OS: $(uname -s). Script expects Linux or macOS." ;;
  esac
}

preflight_tools() {
  require_cmd dirname
  require_cmd mkdir
  require_cmd pwd
  require_cmd docker
  docker compose version >/dev/null 2>&1 || die "Docker Compose v2 plugin is required (docker compose)."
  if command -v python3 >/dev/null 2>&1; then
    info "Python: $(python3 --version 2>&1)"
  else
    warn "python3 not found on PATH (optional for local scripts; Docker images bundle Python)."
  fi
}

port_in_use() {
  local host="$1" port="$2"
  if command -v nc >/dev/null 2>&1; then
    nc -z "$host" "$port" >/dev/null 2>&1
    return $?
  fi
  if bash -c "exec 3<>/dev/tcp/${host}/${port}" >/dev/null 2>&1; then
    exec 3<&-
    exec 3>&-
    return 0
  fi 2>/dev/null
  return 1
}

preflight_ports_optional() {
  local ports=("$DASHBOARD_PORT" 8080 8090 8070 8060)
  local p
  for p in "${ports[@]}"; do
    if port_in_use 127.0.0.1 "$p"; then
      warn "Port ${p} appears in use on localhost — Compose may fail to bind (dashboard uses IDS_DASHBOARD_PORT)."
    fi
  done
}

ensure_env_example() {
  if [[ -f "$ENV_EXAMPLE" ]]; then
    info ".env.example already exists: $ENV_EXAMPLE"
    return
  fi
  info "Creating .env.example at repo root."
  cat >"$ENV_EXAMPLE" <<EOF
# Copy to .env and adjust. Loaded by install.sh before Compose (set -a).
# Dissertation: Model V1 = ENT-01 only; Model V2 optional; REP-01 replay-only; REF-01 reference-only.

POSTGRES_DB=ids_phase4
POSTGRES_USER=ids_phase4
POSTGRES_PASSWORD=ids_phase4_local_change_me

IDS_POSTGRES_DB=ids_phase4
IDS_POSTGRES_USER=ids_phase4
IDS_POSTGRES_PASSWORD=ids_phase4_local_change_me

REDIS_URL=redis://phase4-redis:6379/0

DASHBOARD_PORT=${DASHBOARD_PORT}
IDS_DASHBOARD_PORT=${DASHBOARD_PORT}
IDS_DASHBOARD_HOST_BIND=0.0.0.0

API_PORT=8070
IDS_CHILD_PARENT_SHARED_TOKEN=ids-child-parent-local-token

MODEL_VERSION_DEFAULT=parent_model_v1_enterprise_baseline
DATA_ROOT=${DATA_ROOT}

IDS_SCRATCH_RAW_DOWNLOADS=${IDS_SCRATCH_RAW_DOWNLOADS}

IDS_MANIFEST_HOST_ROOT=${IDS_MANIFEST_HOST_ROOT:-/srv/scratch/ids_final_amity}
STEP1_TABLESPACE_NAME=${STEP1_TABLESPACE_NAME}
STEP1_TABLESPACE_LOCATION=${STEP1_TABLESPACE_LOCATION}
STEP3_V2_TABLESPACE_NAME=${STEP3_V2_TABLESPACE_NAME}
STEP3_V2_TABLESPACE_LOCATION=${STEP3_V2_TABLESPACE_LOCATION}
STEP3_V2_TABLESPACE_DIR=${STEP3_V2_TABLESPACE_DIR}

STACK_NAME=${STACK_NAME}
IDS_PROJECT_LABEL=${PROJECT_LABEL}

INSTALL_SAFE_MODE=true
PRESERVE_DATA=true
PRESERVE_POSTGRES=false
PRESERVE_MODEL_ARTIFACTS=true

RAW_DOWNLOADS_ROOT=${DATA_ROOT}/raw_downloads
PROCESSED_CSV_ROOT=${DATA_ROOT}/processed_csv
CANONICAL_ROOT=${DATA_ROOT}/canonical
PHASE4_OUTPUT_ROOT=${DATA_ROOT}/outputs/phase4
MODEL_V1_OUTPUT_ROOT=${DATA_ROOT}/outputs/model_v1
POSTGRES_DATA_DIR=${DATA_ROOT}/postgres
BACKUP_ROOT=${DATA_ROOT}/backups
STORAGE_ROOT=${DATA_ROOT}

# Unified metrics worker profile (all step-end metric jobs).
METRICS_WORKER_TOTAL_CORES=20
METRICS_WORKER_CPU_CAP_PCT=0.80
EOF
}

ensure_dotenv() {
  ensure_env_example
  info "Regenerating $ENV_FILE from $ENV_EXAMPLE."
  cp "$ENV_EXAMPLE" "$ENV_FILE"
  # shellcheck disable=SC1090
  set -a && source "$ENV_FILE" && set +a || die "Failed to source $ENV_FILE"
  # Re-apply script-resolved paths if .env omitted them
  : "${DATA_ROOT:=$SOURCE_REPO_REAL/data}"
  if [[ "${DATA_ROOT}" != /* ]]; then
    DATA_ROOT="$SOURCE_REPO_REAL/${DATA_ROOT#./}"
  fi
  mkdir -p "$DATA_ROOT"
  DATA_ROOT="$(cd "$DATA_ROOT" && pwd -P)"
  : "${IDS_DASHBOARD_PORT:=$DASHBOARD_PORT}"
  export IDS_DASHBOARD_HOST_BIND="${IDS_DASHBOARD_HOST_BIND:-0.0.0.0}"
  export IDS_POSTGRES_DB="${IDS_POSTGRES_DB:-${POSTGRES_DB:-ids_phase4}}"
  export IDS_POSTGRES_USER="${IDS_POSTGRES_USER:-${POSTGRES_USER:-ids_phase4}}"
  export IDS_POSTGRES_PASSWORD="${IDS_POSTGRES_PASSWORD:-${POSTGRES_PASSWORD:-ids_phase4_local_change_me}}"
  export INSTALL_SAFE_MODE="${INSTALL_SAFE_MODE:-true}"
  export PRESERVE_DATA="${PRESERVE_DATA:-true}"
  export PRESERVE_POSTGRES="${PRESERVE_POSTGRES:-false}"
  export PRESERVE_MODEL_ARTIFACTS="${PRESERVE_MODEL_ARTIFACTS:-true}"
  export RAW_DOWNLOADS_ROOT="${RAW_DOWNLOADS_ROOT:-$DATA_ROOT/raw_downloads}"
  export PROCESSED_CSV_ROOT="${PROCESSED_CSV_ROOT:-$DATA_ROOT/processed_csv}"
  export CANONICAL_ROOT="${CANONICAL_ROOT:-$DATA_ROOT/canonical}"
  export PHASE4_OUTPUT_ROOT="${PHASE4_OUTPUT_ROOT:-$DATA_ROOT/outputs/phase4}"
  export MODEL_V1_OUTPUT_ROOT="${MODEL_V1_OUTPUT_ROOT:-$DATA_ROOT/outputs/model_v1}"
  export POSTGRES_DATA_DIR="${POSTGRES_DATA_DIR:-$DATA_ROOT/postgres}"
  export BACKUP_ROOT="${BACKUP_ROOT:-$DATA_ROOT/backups}"
  export STORAGE_ROOT="${STORAGE_ROOT:-$DATA_ROOT}"
  export METRICS_WORKER_TOTAL_CORES="${METRICS_WORKER_TOTAL_CORES:-20}"
  export METRICS_WORKER_CPU_CAP_PCT="${METRICS_WORKER_CPU_CAP_PCT:-0.80}"
  export IDS_SCRATCH_RAW_DOWNLOADS="${IDS_SCRATCH_RAW_DOWNLOADS:-$DATA_ROOT/raw_downloads}"
  export IDS_MANIFEST_HOST_ROOT="${IDS_MANIFEST_HOST_ROOT:-/srv/scratch/ids_final_amity}"
  export CLEAN_INSTALL_IMMUTABLE_RAW="${CLEAN_INSTALL_IMMUTABLE_RAW:-/srv/scratch/ids_final_amity/raw_downloads}"
  export STEP1_TABLESPACE_NAME="${STEP1_TABLESPACE_NAME:-step2_tablespace}"
  export STEP1_TABLESPACE_LOCATION="${STEP1_TABLESPACE_LOCATION:-/srv/data/ids_final/step2_tablespace}"
  export STEP3_V2_TABLESPACE_NAME="${STEP3_V2_TABLESPACE_NAME:-step3_v2_cold}"
  export STEP3_V2_TABLESPACE_LOCATION="${STEP3_V2_TABLESPACE_LOCATION:-/srv/data/ids_final/step3_v2_tablespace}"
  export STEP3_V2_TABLESPACE_DIR="${STEP3_V2_TABLESPACE_DIR:-/srv/data/ids_final}"
}

PROTECTED_PATHS=()

build_protected_paths() {
  if [[ "${CLEAN_INSTALL_FORCE:-0}" -eq 1 ]]; then
    local imm="${CLEAN_INSTALL_IMMUTABLE_RAW:-/srv/scratch/ids_final_amity/raw_downloads}"
    imm="${imm%/}"
    if [[ -d "$imm" ]]; then
      imm="$(cd "$imm" >/dev/null 2>&1 && pwd -P)" || true
    fi
    PROTECTED_PATHS=("$imm")
    return
  fi
  PROTECTED_PATHS=(
    "$DATA_ROOT"
    "$RAW_DOWNLOADS_ROOT"
    "$PROCESSED_CSV_ROOT"
    "$CANONICAL_ROOT"
    "$PHASE4_OUTPUT_ROOT"
    "$MODEL_V1_OUTPUT_ROOT"
    "$POSTGRES_DATA_DIR"
    "$BACKUP_ROOT"
    "$STORAGE_ROOT"
    "$DATA_ROOT/outputs/model_v1"
    "$DATA_ROOT/outputs/phase4"
    "$DATA_ROOT/outputs/phase4/audit"
    "$DATA_ROOT/outputs/phase4/dashboard_state"
    "$IDS_SCRATCH_RAW_DOWNLOADS"
  )
}

print_protected_paths() {
  if [[ "${CLEAN_INSTALL_FORCE:-0}" -eq 1 ]]; then
    info "Force clean-install: only this path is preserved on disk:"
  else
    info "Protected storage paths (deletion blocked by default):"
  fi
  local p
  for p in "${PROTECTED_PATHS[@]}"; do
    [[ -n "$p" ]] || continue
    printf '  - %s\n' "$p"
  done
}

ensure_storage_directories() {
  mkdir -p \
    "$RAW_DOWNLOADS_ROOT" \
    "$PROCESSED_CSV_ROOT" \
    "$CANONICAL_ROOT" \
    "$PHASE4_OUTPUT_ROOT" \
    "$MODEL_V1_OUTPUT_ROOT" \
    "$POSTGRES_DATA_DIR" \
    "$BACKUP_ROOT" \
    "$STORAGE_ROOT"
}

ensure_placeholder_csv() {
  local path="$1"
  local header="$2"
  if [[ -e "$path" ]]; then
    return
  fi
  mkdir -p "$(dirname "$path")"
  printf '%s\n' "$header" >"$path"
  success "Created placeholder CSV: $path"
}

ensure_chapter4_csv_placeholders() {
  local base="$DATA_ROOT/outputs/phase4/metrics/chapter4"
  mkdir -p "$base"
  ensure_placeholder_csv "$base/within_dataset_results.csv" \
    "experiment_id,dataset_id,model_version,split,precision,recall,f1,notes"
  ensure_placeholder_csv "$base/cross_dataset_results.csv" \
    "experiment_id,train_dataset,eval_dataset,model_version,precision,recall,f1,degradation_notes"
  ensure_placeholder_csv "$base/categorization_results.csv" \
    "experiment_id,dataset_id,metric_name,metric_value,notes"
  ensure_placeholder_csv "$base/cross_scope_results.csv" \
    "experiment_id,model_version,child_scope,cross_scope_detected,escalation_correct,notes"
  ensure_placeholder_csv "$base/shap_results.csv" \
    "experiment_id,model_version,shap_mode,coverage,usefulness,notes"
  ensure_placeholder_csv "$base/rule_validation_results.csv" \
    "experiment_id,rule_pack_version,check_name,passed,notes"
  ensure_placeholder_csv "$base/replay_results.csv" \
    "experiment_id,replay_phase,metric_name,metric_value,behavioral_only,notes"
  ensure_placeholder_csv "$base/governance_results.csv" \
    "experiment_id,registry,check_name,passed,notes"
  ensure_placeholder_csv "$base/h1_workflow_results.csv" \
    "experiment_id,model_version,metric_name,metric_value,interpretation"
  ensure_placeholder_csv "$base/h2_categorization_results.csv" \
    "experiment_id,model_version,metric_name,metric_value,interpretation"
  ensure_placeholder_csv "$base/h3_cross_scope_results.csv" \
    "experiment_id,model_version,metric_name,metric_value,interpretation"
  ensure_placeholder_csv "$base/h4_shap_results.csv" \
    "experiment_id,model_version,metric_name,metric_value,interpretation"
  ensure_placeholder_csv "$base/h5_governance_results.csv" \
    "experiment_id,model_version,metric_name,metric_value,interpretation"
}

ensure_data_directories() {
  info "Creating host data layout under DATA_ROOT=$DATA_ROOT"

  mkdir -p \
    "$DATA_ROOT/raw/ENT-01" \
    "$DATA_ROOT/raw/ENT-02" \
    "$DATA_ROOT/raw/DNS-01" \
    "$DATA_ROOT/raw/IOT-01" \
    "$DATA_ROOT/raw/IOT-02" \
    "$DATA_ROOT/raw/REP-01" \
    "$DATA_ROOT/raw/REF-01" \
    "$DATA_ROOT/normalized" \
    "$DATA_ROOT/splits" \
    "$DATA_ROOT/replay" \
    "$DATA_ROOT/outputs/phase4/adapter_reports" \
    "$DATA_ROOT/outputs/phase4/replay_reports" \
    "$DATA_ROOT/outputs/phase4/governance" \
    "$DATA_ROOT/outputs/phase4/governance/dataset_registry" \
    "$DATA_ROOT/outputs/model_v1/runs" \
    "$DATA_ROOT/outputs/model_v1/models" \
    "$DATA_ROOT/outputs/model_v1/metrics" \
    "$DATA_ROOT/outputs/model_v1/shap" \
    "$DATA_ROOT/outputs/model_v1/rulepacks" \
    "$DATA_ROOT/outputs/model_v1/audit" \
    "$DATA_ROOT/outputs/model_v1/dashboard_state" \
    "$DATA_ROOT/processed_csv" \
    "$DATA_ROOT/canonical" \
    "$DATA_ROOT/backups" \
    "$DATA_ROOT/postgres" \
    "$DATA_ROOT/outputs/phase4/leakage_guard" \
    "$DATA_ROOT/outputs/phase4/shap" \
    "$DATA_ROOT/outputs/phase4/metrics" \
    "$DATA_ROOT/outputs/phase4/rules" \
    "$DATA_ROOT/outputs/phase4/models" \
    "$DATA_ROOT/outputs/phase4/cross_test" \
    "$DATA_ROOT/outputs/phase4/logs" \
    "$DATA_ROOT/outputs/phase4/audit" \
    "$DATA_ROOT/outputs/phase4/failed" \
    "$DATA_ROOT/failed" \
    "$DATA_ROOT/logs" \
    "$DATA_ROOT/datasets_normalized" \
    "$IDS_SCRATCH_RAW_DOWNLOADS" \
    "$DATA_ROOT/phase4_upload_incoming"

  # Manifest-aligned dataset folders (Compose bind-mount host tree by default).
  mkdir -p \
    "$IDS_SCRATCH_RAW_DOWNLOADS/ENT-01" \
    "$IDS_SCRATCH_RAW_DOWNLOADS/ENT-02" \
    "$IDS_SCRATCH_RAW_DOWNLOADS/DNS-01" \
    "$IDS_SCRATCH_RAW_DOWNLOADS/IOT-01" \
    "$IDS_SCRATCH_RAW_DOWNLOADS/IOT-02" \
    "$IDS_SCRATCH_RAW_DOWNLOADS/REF-01" \
    "$IDS_SCRATCH_RAW_DOWNLOADS/REP-01"

  if [[ ! -e "$DATA_ROOT/README.md" ]]; then
    cat >"$DATA_ROOT/README.md" <<'EOF'
# Host data directory

- **raw/** — Dissertation-facing role folders (optional mirror; governed files live under IDS_SCRATCH_RAW_DOWNLOADS).
- **datasets_normalized/** — Pipeline normalized outputs (mirrors `/data/datasets_normalized` in containers).
- **outputs/phase4/** — Adapter reports, replay reports, governance, leakage guard, SHAP, metrics, rules, models, failed-row quarantine.
- **failed/** — Legacy host quarantine path (pipeline defaults to outputs/phase4/failed in containers).
- **logs/** — Host-side logs if you run services outside Docker.

Docker Compose binds `IDS_SCRATCH_RAW_DOWNLOADS` to `/data/raw_downloads` (flat per dataset_id). clean-install resets PostgreSQL data; `clean-install --f` preserves only `CLEAN_INSTALL_IMMUTABLE_RAW` (default scratch raw_downloads).
The stack also uses a Docker named volume for `/data` inside containers; sync host trees into that volume
for runtime (`docker cp`, volume tools, or a future bind-mount of `DATA_ROOT`).
EOF
  fi

  ensure_chapter4_csv_placeholders
}

ensure_readme_rep_ref() {
  if [[ ! -f "$DATA_ROOT/raw/REP-01/README.md" ]]; then
    cat >"$DATA_ROOT/raw/REP-01/README.md" <<'EOF'
# REP-01 (CTU-13 PCAP replay)

REP-01 is replay-only. It must never be used for training, validation, or supervised testing.

Place PCAPs and adapter metadata according to `configs/phase4_dataset_manifest_v1.json`.
EOF
  fi
  if [[ ! -f "$DATA_ROOT/raw/REF-01/README.md" ]]; then
    cat >"$DATA_ROOT/raw/REF-01/README.md" <<'EOF'
# REF-01 (NSL-KDD reference)

REF-01 is reference-only. It must never be used in experimental pipelines.

Do not mount REF-01 into training or evaluation tensors; use only for external citation or manual comparison.
EOF
  fi
}

validate_source_repo() {
  [[ -d "$SOURCE_REPO_REAL" ]] || die "SOURCE_REPO does not exist: $SOURCE_REPO"
  [[ -f "$SOURCE_REPO_REAL/$STACK_FILE_REL" ]] || die "Missing stack file: $STACK_FILE_REL"
  [[ -f "$SOURCE_REPO_REAL/$PHASE4_PY_IMAGE_REL" ]] || die "Missing: $PHASE4_PY_IMAGE_REL"
  [[ -f "$SOURCE_REPO_REAL/$PHASE4_DASHBOARD_IMAGE_REL" ]] || die "Missing: $PHASE4_DASHBOARD_IMAGE_REL"
  [[ -f "$SOURCE_REPO_REAL/$PHASE4_POSTGRES_IMAGE_REL" ]] || die "Missing: $PHASE4_POSTGRES_IMAGE_REL"
  [[ -f "$MANIFEST_SRC" ]] || die "Missing manifest: $MANIFEST_REL"
  [[ -f "$HYBRID_POLICY_SRC" ]] || die "Missing hybrid policy: $HYBRID_POLICY_REL"
  [[ -f "$UPLOAD_API_SRC" ]] || die "Missing upload API: $UPLOAD_API_REL"
  [[ -f "$DASH_API_SRC" ]] || die "Missing dashboard API: $DASH_API_REL"
  [[ -f "$INGESTION_WORKER_SRC" ]] || die "Missing ingestion worker: $INGESTION_WORKER_REL"
  [[ -f "$DASHBOARD_NGINX_SRC" ]] || die "Missing nginx config: $DASHBOARD_NGINX_REL"
  [[ -f "$NEW_DASHBOARD_INDEX_SRC" ]] || die "Missing unified dashboard page: $NEW_DASHBOARD_INDEX_REL"
  [[ -f "$NEW_DASHBOARD_APP_SRC" ]] || die "Missing unified dashboard app: $NEW_DASHBOARD_APP_REL"
  [[ -f "$NEW_DASHBOARD_STYLES_SRC" ]] || die "Missing unified dashboard styles: $NEW_DASHBOARD_STYLES_REL"
  [[ -f "$NEW_DASHBOARD_STEP3_TAB_SRC" ]] || die "Missing unified Step3 tab lifecycle module: $NEW_DASHBOARD_STEP3_TAB_REL"
  [[ -f "$POSTGRES_SCHEMA_SRC" ]] || die "Missing Postgres schema: $POSTGRES_SCHEMA_REL"
  [[ -f "$POSTGRES_LOADER_SRC" ]] || die "Missing Postgres loader: $POSTGRES_LOADER_REL"
  [[ -f "$POSTGRES_GOVERNANCE_SRC" ]] || die "Missing governance schema: $POSTGRES_GOVERNANCE_REL"
  [[ -f "$POSTGRES_GOVERNED_VIEWS_SRC" ]] || die "Missing governed views schema: $POSTGRES_GOVERNED_VIEWS_REL"
  [[ -f "$POSTGRES_HYPOTHESIS_SRC" ]] || die "Missing hypothesis schema: $POSTGRES_HYPOTHESIS_REL"
  [[ -f "$POSTGRES_MODEL_WORKFLOW_SRC" ]] || die "Missing model workflow schema: $POSTGRES_MODEL_WORKFLOW_REL"
  [[ -f "$POSTGRES_PRUNE_STEP1_TO_STEP3_SRC" ]] || die "Missing prune SQL: $POSTGRES_PRUNE_STEP1_TO_STEP3_REL"
  [[ -f "$POSTGRES_PRUNE_STEP2_TO_STEP3_SRC" ]] || die "Missing prune SQL: $POSTGRES_PRUNE_STEP2_TO_STEP3_REL"
  [[ -f "$POSTGRES_PRUNE_STEP3_ONLY_SRC" ]] || die "Missing prune SQL: $POSTGRES_PRUNE_STEP3_ONLY_REL"
  [[ -f "$POSTGRES_PRUNE_STEP4_ONLY_SRC" ]] || die "Missing prune SQL: $POSTGRES_PRUNE_STEP4_ONLY_REL"
}

wait_for_empty_output() {
  local description="$1"
  local wait_seconds="$2"
  shift 2
  local deadline=$((SECONDS + wait_seconds))
  local output
  log "Waiting up to ${wait_seconds}s for ${description}..."
  while ((SECONDS <= deadline)); do
    output="$("$@" 2>/dev/null || true)"
    if [[ -z "$output" ]]; then
      log "${description} complete."
      return
    fi
    sleep 2
  done
  die "Timed out waiting for ${description}."
}

wait_for_project_networks() {
  local wait_seconds="$1"
  [[ "$wait_seconds" -gt 0 ]] || {
    info "Skipping Docker network wait."
    return
  }
  local expected_networks=(
    "${STACK_NAME}_dashboard_edge_net"
    "${STACK_NAME}_dash_net"
    "${STACK_NAME}_ics_int_net"
    "${STACK_NAME}_postgres_net"
    "${STACK_NAME}_redis_net"
  )
  local deadline=$((SECONDS + wait_seconds))
  local missing=()
  local network
  info "Waiting up to ${wait_seconds}s for Compose networks..."
  while ((SECONDS <= deadline)); do
    missing=()
    for network in "${expected_networks[@]}"; do
      if ! docker network inspect "$network" >/dev/null 2>&1; then
        missing+=("$network")
      fi
    done
    if [[ "${#missing[@]}" -eq 0 ]]; then
      success "Compose networks are ready."
      return
    fi
    sleep 2
  done
  error "Timed out waiting for networks: ${missing[*]}"
  exit 1
}

ensure_dashboard_publish() {
  local publish_output=""
  local last_publish_output=""
  local publish_wait_seconds="$NETWORK_WAIT_SECONDS"
  if [[ "$publish_wait_seconds" -le 0 ]]; then
    publish_wait_seconds=60
  fi
  local deadline=$((SECONDS + publish_wait_seconds))
  info "Waiting up to ${publish_wait_seconds}s for dashboard port ${IDS_DASHBOARD_PORT}..."
  while ((SECONDS <= deadline)); do
    publish_output="$(compose_cmd port dataset-download-dashboard 18081 2>/dev/null || true)"
    last_publish_output="$publish_output"
    if [[ -n "$publish_output" && "$publish_output" == *":${IDS_DASHBOARD_PORT}"* ]]; then
      success "Dashboard publishes ${publish_output}"
      return
    fi
    sleep 2
  done
  if [[ -n "$last_publish_output" ]]; then
    die "Dashboard did not publish host port ${IDS_DASHBOARD_PORT}. Compose port output: ${last_publish_output}"
  fi
  die "Dashboard did not publish host port ${IDS_DASHBOARD_PORT} (no compose port output)."
}

wait_for_postgres_ready() {
  local max_wait="${1:-90}"
  local deadline=$((SECONDS + max_wait))
  info "Waiting for Postgres (phase4-postgres) to accept connections..."
  while ((SECONDS <= deadline)); do
    if compose_cmd exec -T phase4-postgres pg_isready -U "$IDS_POSTGRES_USER" -d "$IDS_POSTGRES_DB" >/dev/null 2>&1; then
      success "Postgres is ready."
      return
    fi
    sleep 2
  done
  warn "Postgres did not become ready within ${max_wait}s; skipping optional SQL apply (retry manually)."
  return 1
}

apply_psql_file_checklist_item() {
  local label="$1"
  local sql_file="$2"
  compose_cmd exec -T phase4-postgres \
    psql -q -v ON_ERROR_STOP=1 -U "$IDS_POSTGRES_USER" -d "$IDS_POSTGRES_DB" <"$sql_file" >/dev/null
  info "  [x] ${label}"
}

ensure_metrics_table_host() {
  compose_cmd exec -T phase4-postgres \
    psql -q -v ON_ERROR_STOP=1 -U "$IDS_POSTGRES_USER" -d "$IDS_POSTGRES_DB" <<'SQL' >/dev/null
CREATE TABLE IF NOT EXISTS phase4.metrics (
    createdat timestamptz NOT NULL DEFAULT now(),
    updatedat timestamptz NOT NULL DEFAULT now(),
    unique_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    step text NOT NULL CHECK (step IN ('step1', 'step2', 'step3', 'step4')),
    step_unique_id text NOT NULL,
    metric text NOT NULL,
    calculation_method text,
    numerator numeric(24,6),
    denominator numeric(24,6),
    metric_value numeric(18,6),
    status text NOT NULL DEFAULT 'missing',
    calculation_status text NOT NULL DEFAULT 'not_collected',
    details_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (step, step_unique_id, metric)
);
CREATE INDEX IF NOT EXISTS idx_metrics_step_unique_metric
    ON phase4.metrics(step, step_unique_id, metric, updatedat DESC);
CREATE INDEX IF NOT EXISTS idx_metrics_step_metric
    ON phase4.metrics(step, metric, updatedat DESC);
CREATE INDEX IF NOT EXISTS idx_metrics_step_details_run_id
    ON phase4.metrics(step, (COALESCE(details_json->>'run_id', '')));
CREATE INDEX IF NOT EXISTS idx_metrics_step_details_model_id
    ON phase4.metrics(step, (COALESCE(details_json->>'model_id', '')));

CREATE TABLE IF NOT EXISTS phase4.audit_log (
    audit_id uuid PRIMARY KEY,
    event_type text NOT NULL,
    actor text NOT NULL,
    dataset_id text,
    artifact_id uuid,
    experiment_id text,
    model_version text,
    rule_version text,
    replay_id uuid,
    step text,
    step_unique_id text,
    event_details_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS phase4.audit_logs (
    audit_id uuid PRIMARY KEY,
    event_type text NOT NULL,
    actor text NOT NULL,
    dataset_id text,
    artifact_id uuid,
    experiment_id text,
    model_version text,
    rule_version text,
    replay_id uuid,
    step text,
    step_unique_id text,
    event_details_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE phase4.audit_log
    ADD COLUMN IF NOT EXISTS step text;
ALTER TABLE phase4.audit_log
    ADD COLUMN IF NOT EXISTS step_unique_id text;
ALTER TABLE phase4.audit_logs
    ADD COLUMN IF NOT EXISTS step text;
ALTER TABLE phase4.audit_logs
    ADD COLUMN IF NOT EXISTS step_unique_id text;
CREATE INDEX IF NOT EXISTS idx_phase4_audit_log_created
    ON phase4.audit_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_phase4_audit_log_step_unique
    ON phase4.audit_log(step, step_unique_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_phase4_audit_log_event_type
    ON phase4.audit_log(event_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_phase4_audit_logs_created
    ON phase4.audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_phase4_audit_logs_step_unique
    ON phase4.audit_logs(step, step_unique_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_phase4_audit_logs_event_type
    ON phase4.audit_logs(event_type, created_at DESC);

DO $$
BEGIN
  -- Legacy step2_metric_results bootstrap removed: only step-end jobs writing to
  -- phase4.metrics are authoritative.
END $$;

DO $$
BEGIN
  IF to_regclass('phase4.step3_replay_metrics') IS NOT NULL THEN
    EXECUTE $q$
      INSERT INTO phase4.metrics (
          step, step_unique_id, metric, calculation_method, numerator, denominator, metric_value, status, calculation_status, details_json
      )
      SELECT
          'step3' AS step,
          COALESCE(
            NULLIF(sm.simulation_session_id::text, ''),
            NULLIF(sm.preparation_replay_id::text, ''),
            sm.replay_run_id::text
          ) AS step_unique_id,
          kv.key AS metric,
          '' AS calculation_method,
          NULL::numeric(24,6),
          NULL::numeric(24,6),
          CASE
            WHEN jsonb_typeof(kv.value) = 'number' THEN (kv.value #>> '{}')::numeric(18,6)
            ELSE NULL
          END AS metric_value,
          'collected_as_principle' AS status,
          CASE
            WHEN jsonb_typeof(kv.value) = 'number' THEN 'measured'
            ELSE 'not_collected'
          END AS calculation_status,
          jsonb_build_object(
            'source_ref', 'phase4.step3_replay_metrics.metrics',
            'replay_run_id', sm.replay_run_id::text,
            'model_id', COALESCE(sm.model_id::text, ''),
            'model_version', COALESCE(sm.model_version, '')
          ) AS details_json
      FROM phase4.step3_replay_metrics sm
      CROSS JOIN LATERAL jsonb_each(sm.metrics) kv
      ON CONFLICT (step, step_unique_id, metric) DO UPDATE
      SET updatedat = now(),
          metric_value = EXCLUDED.metric_value,
          status = EXCLUDED.status,
          calculation_status = EXCLUDED.calculation_status,
          details_json = EXCLUDED.details_json
    $q$;
  END IF;
END $$;

DO $$
BEGIN
  IF to_regclass('phase4.results_metrics_required_matrix') IS NOT NULL THEN
    EXECUTE $q$
      INSERT INTO phase4.metrics (
          step, step_unique_id, metric, calculation_method, numerator, denominator, metric_value, status, calculation_status, details_json
      )
      SELECT
          'step4' AS step,
          COALESCE(NULLIF(rm.lineage_sim_id, ''), NULLIF(rm.lineage_model_id, ''), NULLIF(rm.lineage_step2_run_id, ''), rm.lineage_step1_run_id) AS step_unique_id,
          rm.metric_name AS metric,
          '' AS calculation_method,
          NULL::numeric(24,6),
          NULL::numeric(24,6),
          CASE WHEN rm.value ~ '^-?[0-9]+(\\.[0-9]+)?$' THEN rm.value::numeric(18,6) ELSE NULL END AS metric_value,
          'collected_as_principle' AS status,
          COALESCE(NULLIF(rm.status, ''), 'not_collected') AS calculation_status,
          jsonb_build_object(
            'source_ref', COALESCE(rm.source_ref, 'phase4.results_metrics_required_matrix'),
            'unit', COALESCE(rm.unit, ''),
            'lineage_step1_run_id', COALESCE(rm.lineage_step1_run_id, ''),
            'lineage_step2_run_id', COALESCE(rm.lineage_step2_run_id, ''),
            'lineage_model_id', COALESCE(rm.lineage_model_id, ''),
            'lineage_model_version', COALESCE(rm.lineage_model_version, ''),
            'lineage_sim_id', COALESCE(rm.lineage_sim_id, '')
          ) AS details_json
      FROM phase4.results_metrics_required_matrix rm
      WHERE COALESCE(NULLIF(rm.lineage_sim_id, ''), NULLIF(rm.lineage_model_id, ''), NULLIF(rm.lineage_step2_run_id, ''), rm.lineage_step1_run_id) IS NOT NULL
        AND rm.metric_name NOT IN ('mismatch_escalation_correctness', 'vector_mapping_accuracy', 'failed_input_archive_coverage')
      ON CONFLICT (step, step_unique_id, metric) DO UPDATE
      SET updatedat = now(),
          metric_value = EXCLUDED.metric_value,
          calculation_status = EXCLUDED.calculation_status,
          details_json = EXCLUDED.details_json
    $q$;
  END IF;
END $$;

DO $$
BEGIN
  DELETE FROM phase4.metrics
  WHERE step = 'step1'
    AND metric IN ('mismatch_escalation_correctness', 'vector_mapping_accuracy', 'failed_input_archive_coverage');

  IF to_regclass('phase4.results_metrics_required_matrix') IS NOT NULL THEN
    DELETE FROM phase4.results_metrics_required_matrix
    WHERE metric_name IN ('mismatch_escalation_correctness', 'vector_mapping_accuracy', 'failed_input_archive_coverage');
  END IF;
END $$;
SQL
  info "  [x] unified metrics table applied"
}

configure_step1_tablespace_layout() {
  wait_for_postgres_ready 90 || return 0
  local ts_name="${STEP1_TABLESPACE_NAME:-step2_tablespace}"
  local ts_loc="${STEP1_TABLESPACE_LOCATION:-/srv/data/ids_final/step2_tablespace}"
  info "Step 1 tablespace checklist:"
  compose_cmd exec -T phase4-postgres sh -lc "mkdir -p '${ts_loc}' && chown postgres:postgres '${ts_loc}' && chmod 700 '${ts_loc}'"
  info "  [x] tablespace path prepared (owner=postgres mode=700)"

  compose_cmd exec -T phase4-postgres \
    psql -q -v ON_ERROR_STOP=1 -U "$IDS_POSTGRES_USER" -d "$IDS_POSTGRES_DB" \
    -v ts_name="$ts_name" -v ts_loc="$ts_loc" <<'SQL'
SELECT format('CREATE TABLESPACE %I LOCATION %L', :'ts_name', :'ts_loc')
WHERE NOT EXISTS (
  SELECT 1
  FROM pg_tablespace
  WHERE spcname = :'ts_name'
) \gexec

SELECT format('ALTER TABLE IF EXISTS phase4.%I SET TABLESPACE %I', t.tbl_name, :'ts_name')
FROM (
  VALUES
    ('dataset_splits'),
    ('split_manifests'),
    ('dataset_train'),
    ('dataset_validate'),
    ('dataset_test'),
    ('dataset_replay'),
    ('canonical_events_train'),
    ('canonical_events_validation'),
    ('canonical_events_test'),
    ('canonical_events_replay')
) AS t(tbl_name) \gexec

SELECT format('ALTER INDEX IF EXISTS phase4.%I SET TABLESPACE %I', i.relname, :'ts_name')
FROM pg_class i
JOIN pg_index ix ON ix.indexrelid = i.oid
JOIN pg_class t ON t.oid = ix.indrelid
JOIN pg_namespace n ON n.oid = t.relnamespace
WHERE n.nspname = 'phase4'
  AND t.relname = ANY(ARRAY[
    'dataset_splits',
    'split_manifests',
    'dataset_train',
    'dataset_validate',
    'dataset_test',
    'dataset_replay',
    'canonical_events_train',
    'canonical_events_validation',
    'canonical_events_test',
    'canonical_events_replay'
  ]) \gexec
SQL
  info "  [x] tablespace exists"
  info "  [x] Step 1 table placement applied"
  info "  [x] Step 1 index placement applied"
}

wait_for_migration_service() {
  local max_wait="${1:-120}"
  local cid=""
  cid="$(compose_cmd ps -q migration-service 2>/dev/null || true)"
  if [[ -z "$cid" ]]; then
    warn "migration-service container not found in compose project ${STACK_NAME}; skipping explicit migration wait."
    return 0
  fi
  local deadline=$((SECONDS + max_wait))
  local status=""
  local exit_code=""
  info "Waiting for migration-service completion..."
  while ((SECONDS <= deadline)); do
    status="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || true)"
    exit_code="$(docker inspect -f '{{.State.ExitCode}}' "$cid" 2>/dev/null || true)"
    case "$status" in
      exited)
        if [[ "$exit_code" == "0" ]]; then
          success "migration-service completed successfully."
          return 0
        fi
        warn "migration-service failed (exit=${exit_code}). Recent logs:"
        docker logs --tail 200 "$cid" || true
        die "migration-service exited non-zero (exit=${exit_code})."
        ;;
      running|created|restarting)
        sleep 2
        ;;
      *)
        sleep 2
        ;;
    esac
  done
  warn "Timed out waiting for migration-service completion; current status=${status:-unknown}, exit=${exit_code:-unknown}."
  if [[ -n "$cid" ]]; then
    docker logs --tail 200 "$cid" || true
  fi
  die "migration-service did not complete in ${max_wait}s."
}

apply_postgres_schemas_host() {
  wait_for_postgres_ready 90 || return 0
  info "Postgres schema checklist:"
  apply_psql_file_checklist_item "split schema applied" "$POSTGRES_SCHEMA_SRC"
  apply_psql_file_checklist_item "governance schema applied" "$POSTGRES_GOVERNANCE_SRC"
  apply_psql_file_checklist_item "model workflow schema applied" "$POSTGRES_MODEL_WORKFLOW_SRC"
  apply_psql_file_checklist_item "governed views applied" "$POSTGRES_GOVERNED_VIEWS_SRC"
  apply_psql_file_checklist_item "hypothesis schema applied" "$POSTGRES_HYPOTHESIS_SRC"
  ensure_metrics_table_host
  info "  [x] legacy metric table bootstraps removed (phase4.metrics is authoritative)"

  local mig_dir="$SOURCE_REPO_REAL/migrations"
  if [[ -d "$mig_dir" ]] && compgen -G "$mig_dir/*.sql" >/dev/null; then
    local migration_count=0
    local f
    while IFS= read -r f; do
      [[ -f "$f" ]] || continue
      compose_cmd exec -T phase4-postgres \
        psql -q -v ON_ERROR_STOP=1 -U "$IDS_POSTGRES_USER" -d "$IDS_POSTGRES_DB" <"$f" >/dev/null
      migration_count=$((migration_count + 1))
    done < <(find "$mig_dir" -maxdepth 1 -type f -name '*.sql' | LC_ALL=C sort)
    info "  [x] migrations applied (${migration_count})"
  else
    info "  [x] migrations applied (0)"
  fi
  configure_step1_tablespace_layout
  success "Postgres SQL bundle checklist complete."
}

run_postgres_prune_script() {
  local sql_path="$1"
  local phase_label="$2"
  compose_cmd ps phase4-postgres >/dev/null 2>&1 || \
    die "phase4-postgres is not running; start stack services before running ${phase_label}."
  wait_for_postgres_ready 90 || die "Postgres is not ready for ${phase_label}."
  info "PostgreSQL reset checklist (${phase_label}):"
  compose_cmd exec -T phase4-postgres \
    psql -q -v ON_ERROR_STOP=1 -U "$IDS_POSTGRES_USER" -d "$IDS_POSTGRES_DB" <"$sql_path" >/dev/null
  info "  [x] reset/prune SQL applied"
  apply_postgres_schemas_host
  success "PostgreSQL reset checklist complete for ${phase_label}."
}

detect_tailscale_ip() {
  local TAILSCALE_IP=""
  if command -v tailscale >/dev/null 2>&1; then
    TAILSCALE_IP="$(tailscale ip -4 2>/dev/null | awk 'NR==1 {print; exit}' || true)"
  fi
  printf '%s\n' "$TAILSCALE_IP"
}

print_dashboard_urls() {
  local host_port="${IDS_DASHBOARD_PORT:-$DASHBOARD_PORT}"
  local host_bind="${IDS_DASHBOARD_HOST_BIND:-0.0.0.0}"
  local ts_ip="${1:-}"
  info "Dashboard (local): http://127.0.0.1:${host_port}/"
  info "Dashboard compatibility URL (local): http://127.0.0.1:${host_port}/new_dashboard/index.html"
  info "Dashboard (remote): http://<this-host-ip>:${host_port}/ — host bind ${host_bind}:${host_port} (set IDS_DASHBOARD_HOST_BIND=127.0.0.1 to disable off-box access)"
  if [[ -n "$ts_ip" ]]; then
    info "Tailscale dashboard URL: http://${ts_ip}:${host_port}/"
    info "Tailscale dashboard compatibility URL: http://${ts_ip}:${host_port}/new_dashboard/index.html"
  fi
}

compose_non_postgres_services() {
  compose_cmd config --services 2>/dev/null | awk '$1 != "phase4-postgres" {print $1}'
}

rebuild_non_postgres_services() {
  local services=()
  local svc
  while IFS= read -r svc; do
    [[ -n "$svc" ]] || continue
    services+=("$svc")
  done < <(compose_non_postgres_services)

  if [[ "${#services[@]}" -eq 0 ]]; then
    warn "No non-Postgres services found in compose config."
    return 0
  fi

  info "Rebuilding/recreating non-Postgres services (${#services[@]} services)."
  compose_cmd up -d --remove-orphans --force-recreate "${services[@]}"
}

rebuild_dashboard_services() {
  local services=("phase4-dash-api" "dataset-download-dashboard")
  info "Rebuilding dashboard images (python + dashboard)..."
  docker build --label "com.ids.project=$PROJECT_LABEL" -t "${IDS_PHASE4_PY_IMAGE:-ids-project-phase4-python:local}" -f "$PHASE4_PY_IMAGE_SRC" "$SOURCE_REPO_REAL"
  docker build --label "com.ids.project=$PROJECT_LABEL" -t "${IDS_DASHBOARD_IMAGE:-ids-project-phase4-dashboard:local}" -f "$PHASE4_DASHBOARD_IMAGE_SRC" "$SOURCE_REPO_REAL"
  info "Recreating dashboard services (${services[*]})..."
  compose_cmd up -d --no-deps --force-recreate "${services[@]}"
  wait_for_project_networks "$NETWORK_WAIT_SECONDS"
  ensure_dashboard_publish
  local ts_ip
  ts_ip="$(detect_tailscale_ip)"
  print_dashboard_urls "$ts_ip"
  success "Dashboard services rebuilt and restarted."
}

restart_postgres_container_without_delete() {
  info "Restarting existing Postgres container without deleting it."
  compose_cmd stop phase4-postgres >/dev/null 2>&1 || true
  wipe_postgres_host_data
  wipe_postgres_tablespace_host_data
  compose_cmd up -d --no-deps phase4-postgres
}

deploy_compose() {
  local include_postgres="${1:-1}"
  export IDS_PROJECT_LABEL="$PROJECT_LABEL"
  export IDS_DASHBOARD_PORT="${IDS_DASHBOARD_PORT:-$DASHBOARD_PORT}"
  export IDS_DASHBOARD_HOST_BIND="${IDS_DASHBOARD_HOST_BIND:-0.0.0.0}"
  export IDS_SCRATCH_RAW_DOWNLOADS
  export IDS_PHASE4_PY_IMAGE="${IDS_PHASE4_PY_IMAGE:-ids-project-phase4-python:local}"
  export IDS_DASHBOARD_IMAGE="${IDS_DASHBOARD_IMAGE:-ids-project-phase4-dashboard:local}"
  export IDS_POSTGRES_IMAGE="${IDS_POSTGRES_IMAGE:-ids-project-phase4-postgres:local}"
  export IDS_CHILD_PARENT_SHARED_TOKEN="${IDS_CHILD_PARENT_SHARED_TOKEN:-ids-child-parent-local-token}"
  export STACK_NAME
  export COMPOSE_PROJECT_NAME="$STACK_NAME"

  mkdir -p "$IDS_SCRATCH_RAW_DOWNLOADS" "$DATA_ROOT/phase4_upload_incoming" ||
    die "Cannot create raw_downloads dirs (set IDS_SCRATCH_RAW_DOWNLOADS to a writable path for local dev)."

  info "Building images..."
  docker build --label "com.ids.project=$PROJECT_LABEL" -t "$IDS_PHASE4_PY_IMAGE" -f "$PHASE4_PY_IMAGE_SRC" "$SOURCE_REPO_REAL"
  docker build --label "com.ids.project=$PROJECT_LABEL" -t "$IDS_DASHBOARD_IMAGE" -f "$PHASE4_DASHBOARD_IMAGE_SRC" "$SOURCE_REPO_REAL"
  docker build --label "com.ids.project=$PROJECT_LABEL" -t "$IDS_POSTGRES_IMAGE" -f "$PHASE4_POSTGRES_IMAGE_SRC" "$SOURCE_REPO_REAL"

  info "Starting Compose stack: $STACK_NAME"
  if [[ "$include_postgres" -eq 1 ]]; then
    compose_cmd up -d --remove-orphans --force-recreate
  else
    rebuild_non_postgres_services
  fi
  wait_for_migration_service 180
  wait_for_project_networks "$NETWORK_WAIT_SECONDS"
  ensure_dashboard_publish
  apply_postgres_schemas_host

  local ts_ip
  ts_ip="$(detect_tailscale_ip)"
  print_dashboard_urls "$ts_ip"
}

remove_compose_project() {
  local remove_volumes="${1:-0}"
  info "Stopping Compose stack: $STACK_NAME"
  if [[ "$remove_volumes" -eq 1 ]]; then
    warn "Requested --volumes cleanup; using explicit volume cleanup flow."
  fi
  compose_cmd down --remove-orphans >/dev/null 2>&1 || true
  wait_for_empty_output \
    "Docker Compose container removal for ${STACK_NAME}" \
    "$CLEAN_WAIT_SECONDS" \
    docker ps -aq --filter "label=com.docker.compose.project=${STACK_NAME}"
}

apply_force_clean_timing_overrides() {
  [[ "${CLEAN_INSTALL_FORCE:-0}" -eq 1 ]] || return 0
  if [[ "${FORCE_CLEAN_WAIT_SECONDS}" =~ ^[0-9]+$ ]] && [[ "$CLEAN_WAIT_SECONDS" -gt "$FORCE_CLEAN_WAIT_SECONDS" ]]; then
    CLEAN_WAIT_SECONDS="$FORCE_CLEAN_WAIT_SECONDS"
  fi
  if [[ "${FORCE_NETWORK_WAIT_SECONDS}" =~ ^[0-9]+$ ]] && [[ "$NETWORK_WAIT_SECONDS" -gt "$FORCE_NETWORK_WAIT_SECONDS" ]]; then
    NETWORK_WAIT_SECONDS="$FORCE_NETWORK_WAIT_SECONDS"
  fi
  info "Force clean-install timing overrides: CLEAN_WAIT_SECONDS=${CLEAN_WAIT_SECONDS}, NETWORK_WAIT_SECONDS=${NETWORK_WAIT_SECONDS}"
}

remove_labelled_containers() {
  local containers
  containers="$(docker ps -aq --filter "label=com.ids.project=$PROJECT_LABEL" || true)"
  if [[ -z "$containers" ]]; then
    info "No labelled containers to remove."
    return
  fi
  # shellcheck disable=SC2086
  docker rm -f $containers >/dev/null 2>&1 || true
}

stack_volume_names() {
  # Compose defines ids_project_redis; never remove Postgres volume from install flows.
  printf '%s\n' \
    "${STACK_NAME}_ids_project_redis" \
    "${STACK_NAME}_ids_project_data"
}

stack_network_names() {
  printf '%s\n' \
    "${STACK_NAME}_dash_net" \
    "${STACK_NAME}_dashboard_edge_net" \
    "${STACK_NAME}_ics_int_net" \
    "${STACK_NAME}_postgres_net" \
    "${STACK_NAME}_redis_net"
}

legacy_stack_network_names() {
  printf '%s\n' \
    "${STACK_NAME}_dashboard_internal" \
    "${STACK_NAME}_ingestion_internal" \
    "${STACK_NAME}_worker_internal" \
    "${STACK_NAME}_validation_internal" \
    "${STACK_NAME}_training_internal" \
    "${STACK_NAME}_redis_internal" \
    "${STACK_NAME}_postgres_internal"
}

remove_stack_attached_containers() {
  local existing=()
  local container resource
  while IFS= read -r resource; do
    [[ -n "$resource" ]] || continue
    while IFS= read -r container; do
      [[ -n "$container" ]] || continue
      existing+=("$container")
    done < <(docker ps -aq --filter "network=$resource" 2>/dev/null || true)
  done < <(
    stack_network_names
    legacy_stack_network_names
  )
  while IFS= read -r resource; do
    [[ -n "$resource" ]] || continue
    while IFS= read -r container; do
      [[ -n "$container" ]] || continue
      existing+=("$container")
    done < <(docker ps -aq --filter "volume=$resource" 2>/dev/null || true)
  done < <(stack_volume_names)
  if [[ "${#existing[@]}" -eq 0 ]]; then
    return
  fi
  printf '%s\n' "${existing[@]}" | sort -u | xargs docker rm -f >/dev/null 2>&1 || true
}

remove_step3_runtime_containers() {
  local ids=()
  local id name
  while IFS=$'\t' read -r id name; do
    [[ -n "$id" ]] || continue
    [[ -n "$name" ]] || continue
    if [[ "$name" =~ ^ids-step3-child- ]] || [[ "$name" =~ ^ids-step3-factory- ]]; then
      ids+=("$id")
    fi
  done < <(docker ps -a --format '{{.ID}}\t{{.Names}}' 2>/dev/null || true)

  if [[ "${#ids[@]}" -eq 0 ]]; then
    info "No Step3 runtime child/factory containers to remove."
    return
  fi

  info "Removing Step3 runtime containers (child/factory) with attached container volumes..."
  docker rm -f -v "${ids[@]}" >/dev/null 2>&1 || true
}

step3_runtime_network_names() {
  docker network ls --format '{{.Name}}' 2>/dev/null \
    | grep -E '^(simulation_replay_net|child-[a-z0-9-]+-(client|mgmt|db)-net)$' || true
}

remove_step3_runtime_networks() {
  local existing=()
  local network
  while IFS= read -r network; do
    [[ -n "$network" ]] || continue
    docker network inspect "$network" >/dev/null 2>&1 && existing+=("$network")
  done < <(step3_runtime_network_names)

  if [[ "${#existing[@]}" -eq 0 ]]; then
    info "No Step3 runtime networks to remove."
    return
  fi

  info "Removing Step3 runtime networks (child client/mgmt/db + simulation network)..."
  cleanup_with_warning "Step3 runtime network removal" docker network rm "${existing[@]}"
}

purge_directory_contents() {
  local path="$1"
  [[ -d "$path" ]] || return 0
  shopt -s dotglob nullglob
  local item
  for item in "$path"/*; do
    [[ -e "$item" ]] || continue
    rm -rf "$item"
  done
  shopt -u dotglob nullglob 2>/dev/null || true
}

remove_glob_matches() {
  local base="$1"
  local pattern="$2"
  [[ -d "$base" ]] || return 0
  find "$base" -maxdepth 1 -name "$pattern" -exec rm -rf {} + >/dev/null 2>&1 || true
}

reset_step_filesystem() {
  local step="$1"
  case "$step" in
    STEP1)
      purge_directory_contents "$DATA_ROOT/normalized"
      purge_directory_contents "$DATA_ROOT/splits"
      purge_directory_contents "$DATA_ROOT/replay"
      purge_directory_contents "$DATA_ROOT/datasets_normalized"
      purge_directory_contents "$DATA_ROOT/processed_csv"
      purge_directory_contents "$DATA_ROOT/canonical"
      purge_directory_contents "$MODEL_V1_OUTPUT_ROOT"
      purge_directory_contents "$DATA_ROOT/outputs/phase4/adapter_reports"
      purge_directory_contents "$DATA_ROOT/outputs/phase4/replay_reports"
      purge_directory_contents "$DATA_ROOT/outputs/phase4/leakage_guard"
      purge_directory_contents "$DATA_ROOT/outputs/phase4/shap"
      purge_directory_contents "$DATA_ROOT/outputs/phase4/rules"
      purge_directory_contents "$DATA_ROOT/outputs/phase4/models"
      purge_directory_contents "$DATA_ROOT/outputs/phase4/cross_test"
      purge_directory_contents "$DATA_ROOT/outputs/phase4/dashboard_state"
      ;;
    STEP2)
      purge_directory_contents "$MODEL_V1_OUTPUT_ROOT"
      purge_directory_contents "$DATA_ROOT/replay"
      purge_directory_contents "$DATA_ROOT/outputs/phase4/replay_reports"
      purge_directory_contents "$DATA_ROOT/outputs/phase4/shap"
      purge_directory_contents "$DATA_ROOT/outputs/phase4/rules"
      purge_directory_contents "$DATA_ROOT/outputs/phase4/models"
      purge_directory_contents "$DATA_ROOT/outputs/phase4/cross_test"
      purge_directory_contents "$DATA_ROOT/outputs/phase4/dashboard_state"
      ;;
    STEP3)
      purge_directory_contents "$DATA_ROOT/replay"
      purge_directory_contents "$DATA_ROOT/outputs/phase4/replay_reports"
      purge_directory_contents "$DATA_ROOT/outputs/model_v1/step3_v2"
      remove_glob_matches "$DATA_ROOT/outputs/phase4/dashboard_state" "step3*"
      remove_glob_matches "$DATA_ROOT/outputs/phase4/dashboard_state" "step3_v2*"
      remove_glob_matches "$DATA_ROOT/outputs/phase4/metrics" "step3*"
      remove_glob_matches "$DATA_ROOT/outputs/phase4/metrics" "step3_v2*"
      ;;
    STEP4)
      purge_directory_contents "$DATA_ROOT/outputs/phase4/metrics/chapter4"
      remove_glob_matches "$DATA_ROOT/outputs/phase4/metrics" "h1*"
      remove_glob_matches "$DATA_ROOT/outputs/phase4/metrics" "h2*"
      remove_glob_matches "$DATA_ROOT/outputs/phase4/metrics" "h3*"
      remove_glob_matches "$DATA_ROOT/outputs/phase4/metrics" "h4*"
      remove_glob_matches "$DATA_ROOT/outputs/phase4/metrics" "h5*"
      ;;
    *)
      die "Unsupported reset step for filesystem cleanup: $step"
      ;;
  esac

  ensure_storage_directories
  ensure_data_directories
  ensure_readme_rep_ref
}

run_phase_reset_mode() {
  local step="$1"
  preflight_os
  preflight_tools
  ensure_dotenv
  validate_source_repo
  ensure_storage_directories
  ensure_data_directories
  ensure_readme_rep_ref

  if [[ "$step" == "STEP1" || "$step" == "STEP2" || "$step" == "STEP3" ]]; then
    remove_step3_runtime_containers
    remove_step3_runtime_networks
  fi

  info "Resetting filesystem data for ${step} (RAW downloads preserved at ${IDS_SCRATCH_RAW_DOWNLOADS})."
  reset_step_filesystem "$step"

  case "$step" in
    STEP1)
      run_postgres_prune_script "$POSTGRES_PRUNE_STEP1_TO_STEP3_SRC" "STEP1"
      ;;
    STEP2)
      run_postgres_prune_script "$POSTGRES_PRUNE_STEP2_TO_STEP3_SRC" "STEP2"
      ;;
    STEP3)
      run_postgres_prune_script "$POSTGRES_PRUNE_STEP3_ONLY_SRC" "STEP3"
      ;;
    STEP4)
      run_postgres_prune_script "$POSTGRES_PRUNE_STEP4_ONLY_SRC" "STEP4"
      ;;
    *)
      die "Unknown step reset mode: $step"
      ;;
  esac

  deploy_compose 0
  success "${step} reset finished."
}

run_dashboard_rebuild_mode() {
  preflight_os
  preflight_tools
  ensure_dotenv
  validate_source_repo
  ensure_storage_directories
  ensure_data_directories
  ensure_readme_rep_ref
  export IDS_PROJECT_LABEL="$PROJECT_LABEL"
  export IDS_DASHBOARD_PORT="${IDS_DASHBOARD_PORT:-$DASHBOARD_PORT}"
  export IDS_DASHBOARD_HOST_BIND="${IDS_DASHBOARD_HOST_BIND:-0.0.0.0}"
  export IDS_PHASE4_PY_IMAGE="${IDS_PHASE4_PY_IMAGE:-ids-project-phase4-python:local}"
  export IDS_DASHBOARD_IMAGE="${IDS_DASHBOARD_IMAGE:-ids-project-phase4-dashboard:local}"
  export STACK_NAME
  export COMPOSE_PROJECT_NAME="$STACK_NAME"
  rebuild_dashboard_services
}

run_full_rebuild_mode() {
  preflight_os
  preflight_tools
  ensure_dotenv
  validate_source_repo
  ensure_storage_directories
  ensure_data_directories
  ensure_readme_rep_ref
  info "REBUILD mode: rebuilding and force-recreating full stack without data deletion."
  deploy_compose 1
  success "Full stack rebuild finished."
}

cleanup_with_warning() {
  local description="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    info "${description} complete."
  else
    warn "${description} could not be fully completed; continuing."
  fi
}

remove_stack_volumes() {
  if [[ "${CLEAN_INSTALL_FORCE:-0}" -eq 1 ]]; then
    local vol
    while IFS= read -r vol; do
      [[ -n "$vol" ]] || continue
      docker volume inspect "$vol" >/dev/null 2>&1 || continue
      warn "Removing Docker volume: $vol"
      docker volume rm -f "$vol" >/dev/null 2>&1 || warn "Could not remove volume: $vol (still in use?)"
    done < <(stack_volume_names)
    return
  fi
  warn "Volume deletion is disabled unless clean-install --f is used; preserving Docker volumes."
}

remove_stack_networks() {
  local existing=()
  local network
  while IFS= read -r network; do
    [[ -n "$network" ]] || continue
    docker network inspect "$network" >/dev/null 2>&1 && existing+=("$network")
  done < <(
    stack_network_names
    legacy_stack_network_names
  )
  [[ "${#existing[@]}" -eq 0 ]] && return
  info "Removing stack networks for ${STACK_NAME}"
  cleanup_with_warning "Docker network removal" docker network rm "${existing[@]}"
}

remove_labelled_images() {
  local images
  images="$(docker image ls -q --filter "label=com.ids.project=$PROJECT_LABEL" || true)"
  [[ -z "$images" ]] && return
  info "Removing labelled images for ${PROJECT_LABEL}"
  # shellcheck disable=SC2086
  cleanup_with_warning "Docker image removal" docker image rm -f $images
}

do_clean_install() {
  preflight_os
  preflight_tools
  validate_source_repo
  ensure_dotenv
  apply_force_clean_timing_overrides
  build_protected_paths
  if [[ "${CLEAN_INSTALL_FORCE:-0}" -eq 1 ]]; then
    print_protected_paths
    warn "FORCE clean-install: Docker named volumes for this stack and most host data under DATA_ROOT / IDS_MANIFEST_HOST_ROOT will be removed."
    warn "PostgreSQL data at POSTGRES_DATA_DIR will be reset."
    warn "CLEAN_INSTALL_IMMUTABLE_RAW is also preserved (see protected list above)."
    remove_compose_project 1
    remove_stack_volumes
    remove_labelled_containers
    remove_stack_attached_containers
    remove_stack_networks
    force_clean_install_wipe_host
    ensure_data_directories
    ensure_readme_rep_ref
    wipe_postgres_host_data
    wipe_postgres_tablespace_host_data
    remove_labelled_images
    deploy_compose 1
  else
    ensure_storage_directories
    ensure_data_directories
    ensure_readme_rep_ref
    print_protected_paths
    warn "Clean-install mode: PostgreSQL data will be reset while preserving the existing Postgres container."
    warn "Host datasets under IDS_SCRATCH_RAW_DOWNLOADS are not removed unless you use --f."
    restart_postgres_container_without_delete
    deploy_compose 0
  fi
  success "Clean install finished."
}

print_next_steps() {
  cat <<EOF

=== Next steps (dissertation-aligned) ===

1) Place datasets
   - Manifest: ${MANIFEST_REL}
   - Host role tree: ${DATA_ROOT}/raw/<DATASET_ID>/ (optional) and governed files under ${IDS_SCRATCH_RAW_DOWNLOADS}/<DATASET_ID>/
   - Compose bind mount (default): ${IDS_SCRATCH_RAW_DOWNLOADS} -> /data/raw_downloads
   - Pipeline paths inside containers: /data/raw_downloads, /data/datasets_normalized, /data/outputs/phase4

2) Start / restart Docker Compose
   cd ${SOURCE_REPO_REAL}
   docker compose -p ${STACK_NAME} -f ${STACK_FILE_REL} up -d

3) Dashboard (host; published on ${IDS_DASHBOARD_HOST_BIND:-0.0.0.0}:${IDS_DASHBOARD_PORT:-18081})
   Local: http://127.0.0.1:${IDS_DASHBOARD_PORT}/
   Local (compatibility): http://127.0.0.1:${IDS_DASHBOARD_PORT}/new_dashboard/index.html
   Remote: http://<this-server-ip>:${IDS_DASHBOARD_PORT}/

4) APIs (this stack publishes the dashboard port only; other services are on Docker networks)
   - Parent API: service parent-api:8070 (e.g. curl from another container, or add a ports: block to compose for host access)
   - Child API: service child-api:8060
   - Dashboard API: phase4-dash-api:8090 (dash_net)
   - Upload API: dataset-upload-api:8080 (dash_net)
   - Redis: phase4-redis:6379 (redis_net)
   - Example: docker compose -p ${STACK_NAME} -f ${STACK_FILE_REL} exec phase4-dash-api curl -sS http://parent-api:8070/

5) Leakage guard (before training Model V1)
   python3 scripts/experiment_guard.py --help
   (Use manifest + hybrid policy; training must be blocked if leakage is detected.)

6) Train Model V1 (ENT-01 only)
   Follow docs and pipeline entrypoints; Model V2 is optional and policy-gated after V1 freeze.

7) REP-01 replay (CTU-13)
   Place PCAPs under ${IDS_SCRATCH_RAW_DOWNLOADS}/REP-01 per manifest; replay validates workflows, not supervised accuracy.

8) Chapter 4 CSV placeholders (headers only; never overwritten if present)
   ${DATA_ROOT}/outputs/phase4/metrics/chapter4/*.csv

Host logs / audit exports: ${DATA_ROOT}/logs and ${DATA_ROOT}/outputs/phase4/audit
Backups (before destructive reset): ${BACKUP_ROOT}
EOF
}

# ---- main ----
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -eq 0 ]]; then
  set -- clean-install
fi

parse_args "$@"

SOURCE_REPO_REAL="$(canonical_path "$SOURCE_REPO")"
STACK_FILE_SRC="$SOURCE_REPO_REAL/$STACK_FILE_REL"
# Re-resolve paths after SOURCE_REPO may have changed via env
MANIFEST_SRC="$SOURCE_REPO_REAL/$MANIFEST_REL"
HYBRID_POLICY_SRC="$SOURCE_REPO_REAL/$HYBRID_POLICY_REL"
ENV_EXAMPLE="$SOURCE_REPO_REAL/.env.example"
ENV_FILE="$SOURCE_REPO_REAL/.env"
POSTGRES_MODEL_WORKFLOW_SRC="$SOURCE_REPO_REAL/$POSTGRES_MODEL_WORKFLOW_REL"
POSTGRES_PRUNE_STEP1_TO_STEP3_SRC="$SOURCE_REPO_REAL/$POSTGRES_PRUNE_STEP1_TO_STEP3_REL"
POSTGRES_PRUNE_STEP2_TO_STEP3_SRC="$SOURCE_REPO_REAL/$POSTGRES_PRUNE_STEP2_TO_STEP3_REL"
POSTGRES_PRUNE_STEP3_ONLY_SRC="$SOURCE_REPO_REAL/$POSTGRES_PRUNE_STEP3_ONLY_REL"
POSTGRES_PRUNE_STEP4_ONLY_SRC="$SOURCE_REPO_REAL/$POSTGRES_PRUNE_STEP4_ONLY_REL"

case "$MODE" in
  clean-install)
    do_clean_install
    ;;
  DASHBOARD)
    run_dashboard_rebuild_mode
    ;;
  REBUILD)
    run_full_rebuild_mode
    ;;
  STEP1|STEP2|STEP3|STEP4)
    run_phase_reset_mode "$MODE"
    ;;
  *)
    usage
    die "Unknown mode: $MODE"
    ;;
esac
