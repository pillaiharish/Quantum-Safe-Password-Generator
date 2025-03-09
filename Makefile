.PHONY: build run test clean

# Build the application
build:
	go build -o password-generator ./cmd/server

# Run the application
run:
	go run ./cmd/server/main.go

# Run tests
test:
	go test -v ./...

# Clean build artifacts
clean:
	rm -f password-generator

# Build and run
dev: build
	./password-generator 