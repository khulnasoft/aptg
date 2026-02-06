# Build stage
FROM rust:1.75-bookworm as builder

WORKDIR /usr/src/aptg
COPY . .

# Install build dependencies
RUN apt-get update && apt-get install -y \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Build the application
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    gpg \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy the binaries from builder
COPY --from=builder /usr/src/aptg/target/release/aptg /usr/local/bin/aptg
COPY --from=builder /usr/src/aptg/target/release/gen_certs /usr/local/bin/gen_certs
COPY --from=builder /usr/src/aptg/target/release/geoip_manager /usr/local/bin/geoip_manager
COPY --from=builder /usr/src/aptg/target/release/gpg_manager /usr/local/bin/gpg_manager

# Copy configuration and data
COPY config.toml .
# Create necessary directories
RUN mkdir -p certs keyring geoip

# Expose ports
EXPOSE 8080 8443

# Start the application
CMD ["aptg"]
