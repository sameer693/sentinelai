FROM golang:1.24.5-alpine AS build

# Install build dependencies
RUN apk add --no-cache gcc musl-dev linux-headers libpcap-dev

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build SentinelAI
RUN CGO_ENABLED=1 GOOS=linux go build -o sentinelai cmd/api/main.go

FROM alpine:latest AS prod

# Install runtime dependencies and upgrade all packages
RUN apk update && apk upgrade && apk add --no-cache libpcap ca-certificates

# Create non-root user
RUN addgroup -g 1001 sentinelai && \
    adduser -D -s /bin/sh -u 1001 -G sentinelai sentinelai

# Create directories
RUN mkdir -p /app/configs /app/models /app/logs /app/data && \
    chown -R sentinelai:sentinelai /app

WORKDIR /app

# Copy binary and configuration
COPY --from=build /app/sentinelai /app/sentinelai
COPY --chown=sentinelai:sentinelai configs/sentinelai.yaml /app/configs/
COPY --chown=sentinelai:sentinelai dashboards/ /app/dashboards/

# Set up permissions
RUN chmod +x /app/sentinelai

# Switch to non-root user
USER sentinelai

# Expose ports
EXPOSE 8080 9090

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Default command
CMD ["./sentinelai"]


