# Fixture: fastapi_minimal

Minimal FastAPI app with two decorated route handlers and a `pyproject.toml`
listing `fastapi` as a dependency. Used by discovery tests to verify that
FastAPI routes are identified as `EntryPoint(kind=HTTP_ROUTE, framework="fastapi")`.

Expected findings:
- Two `EntryPoint` records with `http_method` in `{"GET", "POST"}` and
  `route_path` set from the decorator argument.
