# AGENTS.md - ntrace Project Guide

## Project Overview

**ntrace** is an HTTP network request tracer for monitoring HTTP traffic from any process, similar to `strace` but specifically for network requests. 

- **Current target**: macOS (using dynamic library interposition)
- **Future target**: Linux (using eBPF)
- **Language**: Rust + C (for socket hooks)

## Quick Commands

```bash
# Build everything (library + Rust binary)
make build

# Clean build artifacts
make clean

# Test basic functionality
sudo ./target/release/ntrace -c "python3 test_http.py"

# Run type check (Rust)
cargo check

# Run with debug build
cargo build && sudo ./target/debug/ntrace -c "command"
```

## Project Structure

```
ntrace/
├── src/
│   ├── main.rs           # CLI entry point and process management
│   ├── http_parser.rs    # HTTP request/response parsing logic
│   └── hook.c            # C library for socket interception
├── Cargo.toml           # Rust dependencies and build config
├── build.rs             # Cargo build script (currently unused)
├── Makefile             # Build system for C shared library
├── test_http.py         # Test script for verification
└── README.md            # User documentation
```

## Architecture

### Current Implementation (macOS)
- **C Hook Library**: `hook.c` compiled to `libntrace_hook.dylib`
  - Hooks `send()`/`recv()` system calls via `DYLD_INSERT_LIBRARIES`
  - Filters and logs HTTP traffic to stderr in structured format
  - Format: `[NTRACE:DIRECTION:SOCKFD:LEN]data[/NTRACE]`

- **Rust Controller**: `main.rs`
  - Launches target process with injected library
  - Parses hook output from stderr
  - Uses `httparse` crate for HTTP parsing
  - Formats output for user

### Future Implementation (Linux)
- Replace C hooks with eBPF programs
- Use `libbpf-rs` or `aya` crate for eBPF integration
- Maintain same Rust interface for cross-platform compatibility

## Key Dependencies

- **clap**: CLI argument parsing
- **httparse**: HTTP request/response parsing  
- **tokio**: Async runtime (currently unused but planned)
- **libc**: C interop
- **serde/serde_json**: Serialization (for future JSON output)

## Current Limitations & Known Issues

### Security Restrictions
- **macOS SIP**: System Integrity Protection prevents injection into system binaries
- **Root required**: Library interposition requires sudo privileges
- **DYLD restrictions**: Modern macOS versions increasingly restrict library injection

### Functional Limitations  
- **HTTP only**: Cannot intercept HTTPS traffic (encrypted)
- **Launch only**: Cannot attach to already running processes
- **Basic parsing**: No request/response body parsing yet
- **No filtering**: Cannot filter by host, method, etc.

## Testing Strategy

### Manual Testing
- Use `test_http.py` for basic functionality verification
- Test with non-system binaries to avoid SIP issues
- Monitor stderr output for hook loading debug messages

### Future Testing
- Unit tests for HTTP parser module
- Integration tests with various HTTP clients
- Performance tests for overhead measurement

## Code Conventions

### Rust Code
- Use standard Rust formatting (`cargo fmt`)
- Follow existing error handling patterns with `Result<T, Box<dyn Error>>`
- Keep CLI interface simple and focused
- Use structured logging for debugging

### C Code  
- **Documentation**: Use Doxygen-style comments (`/** */`)
- **Naming**: Snake_case for functions, ALL_CAPS for macros
- **Comments**: Use `/* */` for inline comments, `/** */` for function docs
- **Integration**: Document how C functions integrate with Rust code
- **Error handling**: Use standard C error conventions

## Development Notes

### Why Library Interposition?
- Initially chosen for simplicity and direct socket access
- More targeted than packet capture (process-specific)
- Cross-platform concept (different implementation per OS)

### Why Not Working on macOS?
- Modern macOS security features block `DYLD_INSERT_LIBRARIES`
- SIP prevents modification of system process behavior
- Alternative approaches needed (packet capture, dtrace, etc.)

### Future Architecture Changes
- Move to packet capture for macOS reliability
- Maintain hook-based approach for Linux (eBPF)
- Abstract platform differences behind common interface

## Debugging Tips

1. **Library loading**: Check for `[NTRACE:INIT]` messages in stderr
2. **Permission issues**: Ensure running with sudo
3. **SIP conflicts**: Test with user-compiled binaries, not system ones
4. **HTTP detection**: Verify data matches patterns in `is_http_data()`

## Adding New Features

### Process Attachment (Future)
- Research `ptrace` alternatives for macOS
- Consider `dtrace` integration for system call monitoring
- Maintain compatibility with launch-based workflow

### HTTPS Support (Future)  
- Requires SSL/TLS key extraction
- Consider integration with system keychain
- May need separate implementation approach

### Enhanced Filtering
- Add host/method filtering in Rust parser
- Consider adding filtering at C hook level for performance
- Add configuration file support for complex rules

## Build System Notes

- **Makefile**: Handles C library compilation with proper flags
- **Cargo**: Handles Rust compilation and dependency management
- **build.rs**: Reserved for future integration of C compilation into Cargo
- Keep build process simple and reliable across different macOS versions
