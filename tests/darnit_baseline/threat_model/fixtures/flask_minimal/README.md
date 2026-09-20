# Fixture: flask_minimal

Minimal Flask app with two `@app.route` handlers. Used by discovery tests to
verify that Flask routes are identified as `EntryPoint(kind=HTTP_ROUTE,
framework="flask")` with `route_path` and `http_method` extracted from the
decorator call.
