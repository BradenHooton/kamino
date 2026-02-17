# Stage 1: Build the Go application
FROM golang:1.24.5-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go.mod and go.sum first (better caching)
COPY go.mod go.sum ./

# Download dependencies (cached if go.mod/go.sum unchanged)
RUN go mod download && go mod verify

# Copy entire source code
COPY . .

# Build the application
# CGO_ENABLED=0: Static binary (no C dependencies)
# -ldflags="-w -s": Strip debug info for smaller binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -a -installsuffix cgo \
    -o /app/kamino \
    ./cmd/api

# Stage 2: Create minimal runtime image
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user for security
RUN addgroup -g 1000 kamino && \
    adduser -D -u 1000 -G kamino kamino

# Set working directory
WORKDIR /home/kamino

# Copy binary from builder
COPY --from=builder /app/kamino .

# Change ownership to non-root user
RUN chown kamino:kamino kamino

# Switch to non-root user
USER kamino

# Expose application port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Run the application
CMD ["./kamino"]
