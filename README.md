# aptg

A secure, Rust-based Debian mirror redirector (aptg) with verification, caching, and policy enforcement.

## Features

- **Secure Reverse Proxy**: Fetches, verifies, and caches Debian packages
- **GPG Verification**: Verifies Debian package signatures using official keys
- **Hash Validation**: Validates package integrity using SHA256 hashes
- **Smart Caching**: Different TTLs for different file types
- **Policy Engine**: Access control based on suites, components, and architectures
- **Audit Logging**: Complete audit trail of all requests and actions
- **APT Compatible**: Works seamlessly with APT package manager

## Architecture

```
APT Client
   |
   v
Rust aptg
   ├── GPG Verification
   ├── Hash Validation (SHA256)
   ├── Cache (FS / Object storage)
   ├── Policy Engine
   └── Audit Logs
   |
   v
Upstream Debian Mirror
```

## Quick Start

1. **Build and run**:
   ```bash
   cargo run
   ```

2. **Configure APT**:
   ```bash
   echo "deb https://localhost:8080/debian bookworm main" | sudo tee /etc/apt/sources.list.d/mirror.list
   ```

3. **Update package lists**:
   ```bash
   sudo apt update
   ```

## Configuration

Edit `config.toml` to customize:

- **Server settings**: Host, port
- **Upstream**: Debian mirror URL and timeout
- **Cache**: TTL values for different file types
- **Policy**: Allowed/denied suites, components, architectures
- **Verification**: GPG keyring path and verification settings
- **Audit**: Logging configuration

## Security Features

### GPG Verification
- Verifies `InRelease` files
- Verifies `Release` + `Release.gpg` pairs
- Uses official Debian archive keys

### Hash Validation
- Validates SHA256 hashes from Release files
- Ensures package integrity
- Prevents tampering

### Policy Enforcement
- Suite restrictions (bookworm, bullseye, etc.)
- Component filtering (main, contrib, non-free)
- Architecture controls (amd64, arm64, etc.)
- Package blacklisting

### Audit Trail
- Request logging with timestamps
- Cache hit/miss tracking
- Fetch success/failure records
- Policy violation alerts

## File Types and TTLs

| File Type | TTL | Description |
|-----------|-----|-------------|
| `InRelease`, `Release`, `Release.gpg` | 6 hours | Metadata files |
| `Packages*`, `Sources*` | 12 hours | Package indices |
| `*.deb` | 1 year | Package files (immutable) |

## Policy Examples

### Allow only stable
```toml
[policy.allow]
suites = ["bookworm"]
```

### Deny non-free
```toml
[policy.allow]
components = ["main", "contrib"]
```

### Architecture restrictions
```toml
[policy.deny]
architectures = ["i386", "armhf"]
```

## Monitoring

The service provides comprehensive logging:

```bash
# View audit logs
tail -f /var/log/aptg.log

# Monitor cache hits
grep "Cache hit" /var/log/aptg.log

# Check policy violations
grep "Policy violation" /var/log/aptg.log
```

## Production Deployment

### Systemd Service
```ini
[Unit]
Description=aptg - Debian Mirror Redirector
After=network.target

[Service]
Type=simple
User=mirror
WorkingDirectory=/opt/aptg
ExecStart=/opt/aptg/target/release/aptg
Restart=always

[Install]
WantedBy=multi-user.target
```

### Nginx Reverse Proxy
```nginx
server {
    listen 443 ssl;
    server_name mirror.example.com;
    
    location /debian/ {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Security Considerations

1. **Key Management**: Keep Debian archive keys secure
2. **Network Isolation**: Run in isolated network segment
3. **Resource Limits**: Set appropriate memory and CPU limits
4. **Access Control**: Use firewall rules to restrict access
5. **Regular Updates**: Keep the service and keys updated

## Development

### Build
```bash
cargo build --release
```

### Test
```bash
cargo test
```

### Run with GPG verification
```bash
cargo run --features gpg-verify
```

### Build with Docker
```bash
docker build -t aptg .
```

### Run with Docker Compose
```bash
docker-compose up -d
```

## CI/CD

This project uses GitHub Actions for Continuous Integration:
- **Check**: Validates that the code compiles.
- **Test**: Runs the unit test suite.
- **Format**: Ensures code style consistency.
- **Clippy**: Performs static analysis to catch common mistakes.
- **Docker**: Validates the Docker build on pushes to `main`.

## Releases

To create a new release with cross-platform binaries:
1. Update version in `Cargo.toml`.
2. Create and push a new tag:
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```
The Release workflow will automatically build binaries for Linux (amd64, arm64) and macOS (Intel, Apple Silicon) and attach them to a new GitHub Release.

## License

This project is dual-licensed under the MIT and Apache 2.0 licenses.
- [MIT License](LICENSE-MIT)
- [Apache License 2.0](LICENSE-APACHE)

Users can choose either license based on their requirements.

## Contributing

Contributions are welcome! Please read our [CONTRIBUTING.md](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md) before submitting a Pull Request.

## Security

To report a security vulnerability, please see our [Security Policy](SECURITY.md).

## Support

For issues and questions:
- Open a [Bug Report or Feature Request](https://github.com/khulnasoft/mirror/issues/new/choose)
- Create an issue on GitHub
- Check the audit logs for troubleshooting
- Review the configuration documentation
