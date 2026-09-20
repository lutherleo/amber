# Fixture: go_http_handler

Minimal Go program registering an HTTP handler via `http.HandleFunc` and
opening a PostgreSQL connection via `sql.Open("postgres", ...)`. Used by
discovery tests to verify Go support: both `EntryPoint(kind=HTTP_ROUTE,
language="go")` and `DataStore(technology="postgresql")` should be produced.
