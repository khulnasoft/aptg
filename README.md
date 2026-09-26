# aptg

[![CI](https://github.com/mdselim606570-cloud/aptg/workflows/Rust%20CI/badge.svg)](https://github.com/mdselim606570-cloud/aptg/actions)
[![Docker Build](https://github.com/mdselim606570-cloud/aptg/workflows/Docker%20Build/badge.svg)](https://github.com/mdselim606570-cloud/aptg/pkgs/container/aptg)
[![Crates.io](https://img.shields.io/crates/v/aptg.svg)](https://crates.io/crates/aptg)
[![Rust](https://img.shields.io/badge/rust-1.88+-934488?logo=rust)](https://www.rust-lang.org)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](https://opensource.org/licenses/MIT)

A secure, Rust-based Debian mirror redirector with GPG verification, hash validation, smart caching, and policy enforcement.

## Architecture

```
┌─────────────┐      ┌──────────────────────────────────────────────────┐      ┌──────────────────┐
│  APT Client  │─────▶│                    aptg                          │─────▶│  Upstream Mirror  │
│  (apt-get)   │      │                                                │      │  (deb.debian.org)│
└─────────────┘      │  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │      └──────────────────┘
                     │  │   GPG    │  │   SHA256 │  │    Cache     │  │              │
                     │  │Verify    │  │ Validate │  │  (FS/local)  │  │              ▼
                     │  └──────────┘  └──────────┘  └──────────────┘  │      ┌──────────┐
                     │         │                │          │          │      │ Debian   │
                     │         ▼                ▼          ▼          │      │ Package  │
                     │  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │      │ .deb     │
                     │  │  Policy  │  │  Audit   │  │   Banlist    │  │      │  Cache   │
                     │  │  Engine  │  │  Logger  │  │  (persist)   │  │      └──────────┘
                     │  └──────────┘  └──────────┘  └──────────────┘  │
                     └──────────────────────────────────────────────────┘
```

### Request Flow

```
APT Client → aptg:8080 → Client IP Resolution (X-Forwarded-For / socket peer)
                            │
                            ├── PolicyEngine::check_request(ip, path, method)
                            │     ├── Banlist check (persistent)
                            │     ├── Rate limiter (per-client burst + per-minute)
                            │     └── Suite / component / architecture whitelist
                            │
                            ├── CacheManager::get(path) → hit? return cached
                            │
                            ├── MirrorFetcher::fetch_with_hash_validation(path, suite)
                            │     ├── Packages.xz cache (1h TTL)
                            │     ├── Find SHA256 for .deb in Packages file
                            │     ├── Fetch .deb from upstream
                            │     └── Verify SHA256 hash
                            │
                            ├── GpgVerifier::verify (if enabled)
                            │     └── Parse --status-fd 2 machine output
                            │
                            └── AuditLogger::log_request (JSON lines, rotation)
```

## Features

- **Secure Reverse Proxy**: Fetches, verifies, and caches Debian packages
- **GPG Verification**: Verifies Debian package signatures using official keys
- **Hash Validation**: Validates package integrity using SHA256 hashes from `Packages.xz`
- **Smart Caching**: Different TTLs for different file types
- **Policy Engine**: Access control based on suites, components, architectures
- **Audit Logging**: Complete audit trail of all requests (JSON lines, rotation)
- **APT Compatible**: Works seamlessly with APT package manager
- **Banlist Persistence**: Banned IPs survive restarts via `banlist.json`
- **Hot Reload**: Config and policy reload without restart (5s poll)

## Quick Start

1. **Build and run**:
   ```bash
   cargo run -- --config config.toml
   ```

2. **Configure APT**:
   ```bash
   echo "deb https://localhost:8080/debian bookworm main" | sudo tee /etc/apt/sources.list.d/mirror.list
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
- Validates SHA256 hashes from `Packages.xz`
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

```bash
# View audit logs
tail -f /var/log/aptg.log

# Monitor cache hits
grep "Cache hit" /var/log/aptg.log

# Check policy violations
grep "Policy violation" /var/log/aptg.log
```

## Production Deployment

### Docker
```bash
docker build -t aptg .
docker run -p 8080:8080 -v $(pwd)/config.toml:/etc/aptg/config.toml aptg --config /etc/aptg/config.toml
```

### Systemd
```ini
[Unit]
Description=aptg - Debian Mirror Redirector
After=network.target

[Service]
Type=simple
User=aptg
WorkingDirectory=/var/lib/aptg
ExecStart=/usr/local/bin/aptg --config /etc/aptg/config.toml
Restart=always

[Install]
WantedBy=multi-user.target
```

## CI/CD

- **Rust CI**: Check, test, format, clippy on every push/PR
- **Docker Build**: Multi-platform (`linux/amd64`, `linux/arm64`) build and push to `ghcr.io` on `main` and version tags
- **Release**: Cross-platform binaries (Linux amd64/arm64, macOS Intel/ARM) attached to GitHub Releases

## Releases

```bash
git tag v0.1.0
git push origin v0.1.0
```

The release workflow builds cross-platform binaries and creates a GitHub Release automatically.

## License

Dual-licensed under MIT or Apache 2.0.

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

To report a vulnerability, see [Security Policy](SECURITY.md).

## Support

- [Bug Reports](https://github.com/mdselim606570-cloud/aptg/issues/new/choose)
- Check audit logs for troubleshooting
- Review configuration documentation
