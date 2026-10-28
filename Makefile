.PHONY: build clean all

BINARY_NAME_CTRL=stealth-controller
BINARY_NAME_AGENT=stealth-agent
BINARY_NAME_CLI=stealth-admin

build:
	@echo "Building for Linux (AMD64)..."
	GOOS=linux GOARCH=amd64 go build -o bin/$(BINARY_NAME_CTRL) ./cmd/controller
	GOOS=linux GOARCH=amd64 go build -o bin/$(BINARY_NAME_AGENT) ./cmd/agent
	GOOS=linux GOARCH=amd64 go build -o bin/$(BINARY_NAME_CLI) ./cmd/admin-cli
	@echo "Build completed. Binaries are in ./bin/ directory."

clean:
	rm -rf bin/
	@echo "Cleaned."

all: clean build
