-- name: InsertRequestLog :exec
INSERT INTO request_log (
    created_at,
    user_agent,
    ja3,
    h2,
    peet_print,
    ip_address
) VALUES (
    ?,?,?,?,?,?
)


