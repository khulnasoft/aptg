# Contributing to aptg

Thank you for your interest in contributing to **aptg**! We welcome contributions from the community to help make this Debian mirror redirector even better.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct. We strive to maintain a welcoming and inclusive environment for everyone.

## How Can I Contribute?

### Reporting Bugs

If you find a bug, please create an issue on GitHub with:
- A clear, descriptive title.
- Steps to reproduce the bug.
- Your environment details (OS, Rust version).
- Expected vs. actual behavior.

### Suggesting Enhancements

We're always looking for ways to improve! Please open an issue to discuss your ideas before starting work on a major feature.

### Pull Requests

1. **Fork the Repo**: Create your own fork and clone it locally.
2. **Create a Branch**: Use a descriptive name like `fix/issue-123` or `feature/new-validation`.
3. **Make Changes**: Follow the project's coding style and ensure your code is well-documented.
4. **Run Tests**: Ensure all tests pass:
   ```bash
   cargo test
   ```
5. **Linting**: Run Clippy and Fmt:
   ```bash
   cargo fmt --all
   cargo clippy -- -D warnings
   ```
6. **Submit**: Push to your fork and open a Pull Request. Provide a clear description of the changes.

## Development Setup

1. **Prerequisites**: Rust (latest stable), GPG, and OpenSSL.
2. **Setup**:
   ```bash
   git clone https://github.com/khulnasoft/mirror.git
   cd mirror
   cargo build
   ```
3. **Generate Test Certs**:
   ```bash
   cargo run --bin gen_certs
   ```

## License

By contributing, you agree that your contributions will be licensed under the project's **MIT OR Apache-2.0** dual license.
