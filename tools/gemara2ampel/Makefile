# Makefile for gemara2ampel

# Binary name
BINARY_NAME=ampel_export
BIN_DIR=bin
CMD_DIR=cmd/ampel_export

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet

# Build flags
LDFLAGS=-ldflags "-s -w"

.PHONY: all build test clean install fmt vet help

# Default target
all: build

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BIN_DIR)/$(BINARY_NAME) ./$(CMD_DIR)
	@echo "Binary built: $(BIN_DIR)/$(BINARY_NAME)"

# Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -f $(BIN_DIR)/$(BINARY_NAME)
	rm -f coverage.out coverage.html
	@echo "Clean complete"

# Install/update dependencies
install:
	@echo "Installing dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy
	@echo "Dependencies installed"

# Format code
fmt:
	@echo "Formatting code..."
	$(GOFMT) ./...

# Run go vet
vet:
	@echo "Running go vet..."
	$(GOVET) ./...

# Run all checks (fmt, vet, test)
check: fmt vet test
	@echo "All checks passed"

# Display help
help:
	@echo "Gemara2Ampel Makefile targets:"
	@echo "  make build          - Build the ampel_export binary"
	@echo "  make test           - Run all tests"
	@echo "  make test-coverage  - Run tests with coverage report"
	@echo "  make clean          - Remove build artifacts"
	@echo "  make install        - Install/update dependencies"
	@echo "  make fmt            - Format Go code"
	@echo "  make vet            - Run go vet"
	@echo "  make check          - Run fmt, vet, and test"
	@echo "  make help           - Show this help message"
