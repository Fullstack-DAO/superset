# Superset Copilot Guide
## Architecture Map
- Backend lives under `superset/` and boots via `superset/app.py` + `SupersetAppInitializer` in `superset/initialization/__init__.py`, which wires Flask App Builder views, REST APIs, Celery, caching, and feature flags defined in config.
- Global extensions (`appbuilder`, `db`, `celery_app`, `cache_manager`, `feature_flag_manager`, etc.) are instantiated in `superset/extensions/__init__.py`; most modules import these proxies instead of creating their own instances.
- Business logic funnels through the command layer (`superset/commands/**`) and DAO layer (`superset/daos/**`), keeping view handlers (`superset/views/**`) thin—reuse commands when adding new endpoints.
- Datasets, queries, and visualizations are modelled in `superset/connectors/` and `superset/models/`; `SqlaTable` in `superset/connectors/sqla/models.py` powers the SQLAlchemy-backed datasource layer and includes custom dynamic table refresh helpers.
- Frontend lives in `superset-frontend/`; React apps under `src/` (e.g. `src/dashboard`, `src/explore`, `src/pages`) talk to the `/api/v1` REST endpoints and rely on shared UI packages in `superset-frontend/packages/*` and viz plugins in `superset-frontend/plugins/*`.

## Async & Scheduling
- Celery is configured via `CELERY_CONFIG` in `superset_config.py`; `SupersetAppInitializer.configure_celery` wraps tasks with an app context.
- Core tasks sit in `superset/tasks/` (`async_queries.py`, `scheduler.py`, `cache.py`, `thumbnails.py`); start workers with `celery --app=superset.tasks.celery_app:app worker` and beats via `--beat`.
- Alert/report scheduling uses `reports.scheduler`, `reports.execute`, and `reports.prune_log` tasks from `superset/tasks/scheduler.py`, gated by the `ALERT_REPORTS` feature flag and beat schedules.
- Dynamic dataset refresh jobs (`dynamic_table.refresh_datas*`) also live in `superset/tasks/scheduler.py` and call `SqlaTable.refresh_dataset_datas*`; review these helpers before changing refresh logic.

## Backend Patterns
- API endpoints typically subclass FAB `ModelRestApi` or `BaseSupersetView` inside `superset/views/**`; they invoke command objects (e.g. `AsyncExecuteReportScheduleCommand`) and serialize with Marshmallow schemas in `superset/schemas.py` or module-specific schemas.
- Query execution flows through `superset/common/query_context_factory.py` and `superset/charts/data` commands; async chart jobs write to cache via `superset/tasks/async_queries.py`.
- Configuration overrides go in `superset_config.py`; note project-specific settings like Redis-backed `CACHE_CONFIG`, security `TALISMAN_*`, `MSSQL_URL`, and external app URLs (`COPILOT_URL`, `REPORT_URL`).
- Feature toggles are centrally managed (`FEATURE_FLAGS` in config and `FeatureFlagManager`); check before depending on optional functionality.

## Frontend Patterns
- Use Node 16 + npm 7 (`.nvmrc`); install deps with `npm ci` and run dev assets with `npm run dev-server` (webpack proxying to Flask on `:8088`).
- Folder conventions: `src/dashboard` for dashboards, `src/explore` for chart builder, `src/features` for newer product surfaces, and `src/visualizations` for lightweight viz wrappers; prefer colocated Redux Toolkit slices when stateful.
- New reusable components belong in `src/components` (cross-app) or `packages/superset-ui-*` for shared chart control logic; visualization plugins live under `plugins/` and register via `plugins/plugin-chart-*/src`.
- Jest tests live beside source (`*.test.tsx`), run via `npm run test` or `npm run tdd`; Cypress specs sit in `superset-frontend/cypress-base/cypress/e2e` and require instrumented builds (`npm run build-instrumented`).

## Developer Workflow
- Python setup: create a venv, `pip install -r requirements/local.txt`, `pip install -e .`, then run `superset db upgrade`, `superset fab create-admin`, `superset init`, and optionally `superset load-examples`; `make install` automates these steps.
- Start services locally with `superset run -p 8088 --with-threads --reload --debugger --debug` and `cd superset-frontend && npm run dev-server`; ensure Redis/Postgres are running if you depend on local `superset_config.py` defaults.
- Run lint/format via `pre-commit run --all-files`, `npm run lint`, and `npm run prettier`; backend pylint and mypy configs live under `lintconf.yaml` and `setup.cfg`.
- Tests: backend via `tox -e py39` (or other envs) or direct `pytest tests/...`; integration scripts live in `scripts/tests/run.sh`. Frontend unit tests with `npm run test`, end-to-end with Cypress commands documented in `CONTRIBUTING.md`.
- Migrations use Alembic in `superset/migrations/`; add new revisions with `flask db revision` after updating models, and verify ordering with existing autogenerate scripts.

## Gotchas & Tips
- Many modules rely on Flask globals (e.g. `g.form_data`, `security_manager`); when unit testing, wrap logic in `app.app_context()` and seed roles/permissions via command helpers.
- Cached responses go through `CacheManager` (`superset/utils/cache_manager.py`); reuse `generate_cache_key`/`set_and_log_cache` utilities instead of manual Redis calls.
- Before changing dataset logic, inspect dynamic helpers in `superset/daos/dynamic_model.py` and related `SqlaTable` hooks to avoid corrupting materialized tables.
- Keep UI manifests in sync: webpack emits `superset/static/assets/manifest.json`; backend templates fetch bundles via `manifest_processor`—missing entries usually mean frontend assets were not rebuilt.
- Docs site under `docs/` uses Docusaurus; use `yarn start` for live docs and keep developer workflow notes aligned with `CONTRIBUTING.md`.
