.PHONY: migrate sqlc db-setup install-deps

migrate:
	goose -dir sql/schema sqlite3 database.db up


sqlc:
	sqlc generate

db-setup: migrate sqlc


install-deps:
	go install github.com/pressly/goose/v3/cmd/goose@latest
	go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest