# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Apache Superset — a Flask (Python) + React/TypeScript business intelligence platform. This is a **customized fork**: commit history is in Chinese and there are fork-specific features layered on top of upstream (Copilot integration via `COPILOT_URL`, dynamic dataset table refresh, mobile dashboard pages, draggable menus). When upstream behavior and this fork's `superset_config.py` disagree, the local config wins.

## Commands

### Backend (Python, 3.9–3.11)
- Full dev setup (venv, deps, db upgrade, admin user, init, load examples, npm ci): `make install`
- Run Flask dev server: `superset run -p 8088 --with-threads --reload --debugger --debug` (or `make flask-app`)
- Run all tests for an env: `tox -e py311` (also `py39`, `py310`)
- Run a single test directly: `pytest tests/unit_tests/path/to/test_file.py::test_name` — test files match `*_test.py`, `test_*.py`, `*_tests.py` (see `pytest.ini`)
- Integration test runner: `scripts/tests/run.sh`
- Lint: `pylint -j 0 superset` (or `make py-lint`); type check via mypy config in `setup.cfg`
- Format: `make py-format` (black via pre-commit); import sorting via isort config in `setup.cfg` (line length 88, `known_first_party = superset`)
- All pre-commit hooks: `pre-commit run --all-files`
- DB migrations (Alembic): after changing models run `flask db revision`; migrations live in `superset/migrations/`

### Frontend (`superset-frontend/`, Node 16 + npm 7, see `.nvmrc`)
- Install: `npm ci`
- Dev server (webpack, proxies API to Flask on :8088): `npm run dev-server` (or `make node-app`)
- Run all Jest tests: `npm run test`
- Run a single Jest test: `npm run test -- path/to/File.test.tsx` (or `-t "test name"`); watch mode: `npm run tdd`
- Lint (eslint + tsc): `npm run lint`; auto-fix: `npm run lint-fix`; types only: `npm run type`
- Format: `npm run prettier`
- Production build: `npm run build`
- Cypress E2E: `make build-cypress` then `make open-cypress` (specs in `superset-frontend/cypress-base/cypress/e2e`, requires instrumented build)

### Async workers (Celery)
- Worker: `celery --app=superset.tasks.celery_app:app worker` (or `make report-celery-worker`)
- Beat scheduler: `make report-celery-beat`

### Docs (`docs/`, Docusaurus)
- Live docs: `cd docs && yarn start`

## Architecture

### Backend layering (`superset/`)
Boots via `superset/app.py` + `SupersetAppInitializer` in `superset/initialization/__init__.py`, which wires Flask App Builder (FAB) views, REST APIs, Celery, caching, and feature flags.

Requests flow through distinct layers — **keep view handlers thin and reuse the lower layers**:
- **Views** (`superset/views/**`) — FAB `ModelRestApi` / `BaseSupersetView` subclasses; serialize with Marshmallow schemas (`superset/schemas.py` or module-local schemas). API surface is `/api/v1`.
- **Commands** (`superset/commands/**`) — business logic; invoke these from new endpoints instead of duplicating logic in views.
- **DAOs** (`superset/daos/**`) — data access objects over the models.
- **Models** (`superset/models/**`, `superset/connectors/`) — `SqlaTable` in `superset/connectors/sqla/models.py` is the SQLAlchemy-backed datasource and carries this fork's dynamic table refresh helpers.

Global extensions (`appbuilder`, `db`, `celery_app`, `cache_manager`, `feature_flag_manager`, etc.) are instantiated once in `superset/extensions/__init__.py`; modules import these proxies rather than creating their own.

Query execution flows through `superset/common/query_context_factory.py` and `superset/charts/data` commands; async chart jobs write results to cache via `superset/tasks/async_queries.py`.

### Async & scheduling (`superset/tasks/`)
Celery is configured by `CELERY_CONFIG` in `superset_config.py`; `SupersetAppInitializer.configure_celery` wraps tasks in an app context. Core tasks: `async_queries.py`, `scheduler.py`, `cache.py`, `thumbnails.py`. Alert/report scheduling (`reports.*` tasks) is gated by the `ALERT_REPORTS` feature flag. **Fork-specific:** dynamic dataset refresh jobs (`dynamic_table.refresh_datas*` in `scheduler.py`) call `SqlaTable.refresh_dataset_datas*` — review these and `superset/daos/dynamic_model.py` before touching dataset/refresh logic to avoid corrupting materialized tables.

### Frontend (`superset-frontend/src/`)
React apps talk to `/api/v1`. Folder conventions:
- `src/dashboard` — dashboards; `src/explore` — chart builder; `src/SqlLab` — SQL editor; `src/features` — newer product surfaces; `src/pages` — page-level routes; `src/visualizations` — lightweight viz wrappers.
- Cross-app reusable components go in `src/components`; shared chart/control logic and the design system live in `packages/superset-ui-*`; visualization plugins live in `plugins/plugin-chart-*` and register via their `src`.
- Prefer colocated Redux Toolkit slices for stateful features. Jest tests sit beside source as `*.test.tsx`.

### Feature flags
Centrally managed via `FEATURE_FLAGS` in config and `FeatureFlagManager`. Check a flag before depending on optional functionality.

## Gotchas

- Many modules rely on Flask globals (`g.form_data`, `security_manager`). When unit testing, wrap logic in `app.app_context()` and seed roles/permissions via command helpers.
- Cache access goes through `CacheManager` (`superset/utils/cache_manager.py`) — reuse `generate_cache_key` / `set_and_log_cache` instead of hitting Redis directly.
- Webpack emits `superset/static/assets/manifest.json` and backend templates fetch bundles via `manifest_processor`. Missing manifest entries usually mean the frontend assets were not rebuilt.
- Configuration overrides go in `superset_config.py` (not committed upstream config). This fork sets Redis-backed `CACHE_CONFIG`, `TALISMAN_*`, `MSSQL_URL`, and external app URLs (`COPILOT_URL`, `REPORT_URL`).
