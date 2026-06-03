# Dissertation Code Export

This directory is a curated copy of the live dashboard code and installer used in the completed build.

It is organized for dissertation sharing, while keeping the original dashboard module layout intact so the copied JavaScript files still reference each other correctly.

## Layout

- `dashboard/` - copied live dashboard shell from `docs/ops/new_dashboard`
- `dashboard/api/` - dashboard API helper modules used by the shell and embedded Step 3 V2 view
- `dashboard/backend/` - mirrored Python backend package used by the live dashboard service
- `docker/` - deployment installer copy (`install.sh`)
- `step1/` - structural folder reserved for Step 1 dissertation materials
- `step2/` - structural folder reserved for Step 2 dissertation materials
- `step3/` - structural folder reserved for Step 3 dissertation materials
- `step3/backend/` - mirrored Python backend package for the Step 3 V2 API and simulation engine
- `governance/` - structural folder reserved for governance materials
- `governance/backend/` - mirrored governance/helper Python modules used by the dashboard policy layer

## System Requirements

### Hardware

The repository does not define a strict hardware minimum. For the full Docker stack, a practical working setup is:

- 64-bit CPU
- 4+ CPU cores
- 8 GB RAM minimum
- 16 GB RAM recommended for comfortable dashboard, PostgreSQL, and worker use
- SSD storage with enough free space for Docker images, PostgreSQL data, and copied datasets

### Software

- Docker Engine
- Docker Compose v2 plugin (`docker compose`)
- Bash
- Python 3 (optional for local helper scripts; the container images bundle Python)
- A modern browser with module support and `EventSource` support
- `curl` and `jq` for common smoke checks and diagnostics
- `psql` is used by the installer workflow through the PostgreSQL container

## Configuration

The copied installer and dashboard code use these environment variables and runtime settings.

### Installer / stack variables

From `docker/install.sh`:

- `SOURCE_REPO`
- `STACK_NAME`
- `IDS_DASHBOARD_PORT`
- `IDS_DASHBOARD_HOST_BIND`
- `DATA_ROOT`
- `IDS_SCRATCH_RAW_DOWNLOADS`
- `NETWORK_WAIT_SECONDS`
- `CLEAN_WAIT_SECONDS`
- `FORCE_CLEAN_WAIT_SECONDS`
- `FORCE_NETWORK_WAIT_SECONDS`
- `STEP1_TABLESPACE_NAME`
- `STEP1_TABLESPACE_LOCATION`
- `STEP3_V2_TABLESPACE_NAME`
- `STEP3_V2_TABLESPACE_LOCATION`
- `STEP3_V2_TABLESPACE_DIR`
- `IDS_MANIFEST_HOST_ROOT`
- `IDS_POSTGRES_DB`
- `IDS_POSTGRES_USER`
- `IDS_POSTGRES_PASSWORD`
- `PRESERVE_POSTGRES`
- `PRESERVE_MODEL_ARTIFACTS`
- `INSTALL_SAFE_MODE`

The installer also documents stack-image overrides such as:

- `IDS_PHASE4_PY_IMAGE`
- `IDS_DASHBOARD_IMAGE`
- `IDS_POSTGRES_IMAGE`

### Dashboard runtime settings

From `dashboard/api/http.js`:

- `?api_base=http://host:port` can be added to the dashboard URL to set the API base for that browser session
- the resolved API base is persisted in `localStorage` under `ids_dashboard_api_base`
- `window.__IDS_CLEAR_DASHBOARD_API_BASE__()` clears the persisted API base in DevTools

### Stack notes from the repo docs

The broader stack documentation also refers to:

- `IDS_DASH_API_PORT` for the dash API service exposure
- `PHASE4_MANIFEST_HOST_ROOT` inside containers for manifest path remapping
- `PHASE4_IGNORE_SERVER_TARGET_DIR` to bypass manifest remapping when needed
