# Build the hook library
libntrace_hook.dylib: src/hook.c
	clang -shared -fPIC -o libntrace_hook.dylib src/hook.c -ldl

# Build everything
build: libntrace_hook.dylib
	cargo build --release

# Clean build artifacts
clean:
	cargo clean
	rm -f libntrace_hook.dylib

.PHONY: build clean
