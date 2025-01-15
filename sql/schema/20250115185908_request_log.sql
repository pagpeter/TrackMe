-- +goose Up
-- +goose StatementBegin
CREATE TABLE
    request_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TIMESTAMP NOT NULL,
        user_agent TEXT,
        ja3 TEXT,
        h2 TEXT,
        peet_print TEXT,
        ip_address TEXT
    )
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE request_log;

-- +goose StatementEnd