# httptrace

A HTTP network request tracer. It is a simple tool to monitor HTTP requests made by any process, similar to `strace` but specifically for network traffic.

## How it works

`httptrace` uses **dynamic library interposition** via `DYLD_INSERT_LIBRARIES` to intercept HTTP traffic at the socket level.

### Technical Overview

**Function Interposition Process:**

1. **Library Injection**: `DYLD_INSERT_LIBRARIES=libhttptrace_hook.dylib` tells macOS's dynamic linker to load our library first
2. **Symbol Replacement**: Our `send()`/`recv()` functions replace the system ones in the target process
3. **Call Interception**: When target calls `send()`, it actually calls our hook function
4. **Data Logging**: We log HTTP data to stderr, then call the real `send()` via `dlsym(RTLD_NEXT)`
5. **Transparent Operation**: Target process continues normally, unaware of interception

**Symbol Resolution Chain:**
```
Target Process → calls send() → Our hook send() → Real libc send() → Kernel
                                     ↓
                              Logs to stderr → Rust parser → HTTP output
```

**Why This Works:**
- Dynamic linker loads libraries in order specified by `DYLD_INSERT_LIBRARIES`
- First definition of a symbol wins during runtime symbol resolution
- `dlsym(RTLD_NEXT)` lets us call the "next" (real) function in the search order

## Usage

```bash
# Build the project
cargo build --release

# Trace HTTP requests from curl
sudo ./target/release/httptrace -c "curl -v http://httpbin.org/get"

# Note: Some system binaries (like /usr/bin/curl) may be protected by SIP
# Try with homebrew curl instead:
sudo ./target/release/httptrace -c "/opt/homebrew/bin/curl http://httpbin.org/get"
```

## Limitations (current implementation)

- **macOS only**: Uses DYLD_INSERT_LIBRARIES (macOS-specific)
- **Root required**: Library interposition requires sudo privileges for security reasons
- **SIP restrictions**: Modern macOS System Integrity Protection blocks injection into system binaries (like `/usr/bin/curl`)
- **DYLD restrictions**: Recent macOS versions increasingly restrict `DYLD_INSERT_LIBRARIES` usage
- **HTTP only**: Only detects basic HTTP traffic, not HTTPS (encrypted data is opaque)
- **Library loading issues**: May fail silently if dyld refuses to load our library

## Future improvements

- Linux support using eBPF
- HTTPS/TLS traffic decryption
- Better process targeting (attach to running processes)
- JSON output format
- Request/response body parsing

## Technical Details

### Function Interposition Mechanism

**How DYLD_INSERT_LIBRARIES Works:**

1. **Library Load Order**: `DYLD_INSERT_LIBRARIES=hook.dylib` → dyld loads our library first
2. **Symbol Shadowing**: Our `send()/recv()` definitions take precedence over libc's
3. **Call Chain**: `Target → Our hook → Log data → Real libc function → Kernel`
4. **Symbol Resolution**: `dlsym(RTLD_NEXT, "send")` finds the real libc function

**Why Root Is Required:**
- Library injection modifies process memory layout
- macOS requires elevated privileges for security reasons
- Similar to `gdb` or `dtrace` requiring root access

### Debugging Library Loading

If no HTTP output appears, the library may not be loading:

```bash
# Check for initialization messages
sudo ./target/release/httptrace -c "python3 test_http.py" 2>&1 | grep NTRACE:INIT

# Test library injection manually
DYLD_INSERT_LIBRARIES=./libhttptrace_hook.dylib python3 test_http.py

# Verify library exists and is executable
ls -la libhttptrace_hook.dylib
```

## Architecture

```
┌─────────────────┐    ┌──────────────┐    ┌────────────────┐
│  httptrace CLI  │───▶│ Target App   │───▶│  HTTP Output   │
│ (Rust)          │    │ + hook.dylib │    │  (parsed)      │
└─────────────────┘    └──────────────┘    └────────────────┘
                              │
                              ▼
                       ┌───────────────┐
                       │ socket calls  │
                       │ send()/recv() │
                       └───────────────┘
```
