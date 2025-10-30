SHELL := /bin/sh

.PHONY: dev test build lint fmt

# Run app with nodemon
dev:
	npm run dev

# Run tests
test:
	npm test

# Build Docker images
build:
	docker compose build --no-cache

# Lint
lint:
	npm run lint

# Format
fmt:
	npm run format
