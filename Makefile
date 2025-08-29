# Build the hook library
libhttptrace_hook.dylib: src/hook.c
	clang -shared -fPIC -o libhttptrace_hook.dylib src/hook.c -ldl

# Build everything
build: libhttptrace_hook.dylib
	cargo build --release

# Clean build artifacts
clean:
	cargo clean
	rm -f libhttptrace_hook.dylib

.PHONY: build clean
