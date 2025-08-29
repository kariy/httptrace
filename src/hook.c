/**
 * @file hook.c
 * @brief Socket interposition library for ntrace HTTP monitoring tool
 *
 * FUNCTION INTERPOSITION MECHANISM:
 * ================================
 * This library implements dynamic function interposition to intercept socket calls
 * in target processes without requiring process modification or recompilation.
 *
 * HOW DYLD_INSERT_LIBRARIES WORKS:
 * 1. Target process starts → macOS dynamic linker (dyld) loads shared libraries
 * 2. DYLD_INSERT_LIBRARIES causes dyld to load our hook.dylib BEFORE libc.dylib
 * 3. Symbol resolution: First definition wins → our send()/recv() shadow libc's
 * 4. Target calls send() → Actually calls OUR send() → We log → Call real send()
 *
 * SYMBOL RESOLUTION PROCESS:
 * - dlsym(RTLD_NEXT, "send") = "Find next send() symbol in library search order"
 * - This gives us the real libc send() while we provide the hooked version
 * - Target process remains completely unaware of the interception
 *
 * INTERCEPTION FLOW:
 * Target Process → send() call → Our hook send() → log to stderr → Real libc send() → Kernel
 *                                       ↓
 *                               Rust reads stderr → HTTP parser → User output
 *
 * OUTPUT FORMAT: [NTRACE:DIRECTION:SOCKFD:LEN]raw_http_data[/NTRACE]
 * - DIRECTION: "SEND" (outgoing requests) or "RECV" (incoming responses)
 * - SOCKFD: Socket file descriptor for connection tracking
 * - LEN: Data length in bytes
 *
 * CURRENT LIMITATIONS:
 * - macOS System Integrity Protection blocks injection into system binaries
 * - Recent macOS versions restrict DYLD_INSERT_LIBRARIES usage
 * - Only works with HTTP (plaintext), not HTTPS (encrypted)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>

/** @brief Function pointer to original send() system call */
static ssize_t (*original_send)(int sockfd, const void *buf, size_t len, int flags) = NULL;

/** @brief Function pointer to original recv() system call */
static ssize_t (*original_recv)(int sockfd, void *buf, size_t len, int flags) = NULL;

/**
 * @brief Initialize function pointers to original socket functions
 *
 * Uses dlsym(RTLD_NEXT, ...) to get addresses of the real send/recv functions
 * from libc, which we'll call after logging HTTP data. This is called lazily
 * from our hook functions to avoid initialization order issues.
 *
 * Debug output is sent to stderr to help diagnose library loading issues
 * during development and testing.
 */
static void init_hooks(void) {
    if (!original_send) {
        original_send = dlsym(RTLD_NEXT, "send");
        fprintf(stderr, "[NTRACE:INIT] Loaded send hook\n");
    }
    if (!original_recv) {
        original_recv = dlsym(RTLD_NEXT, "recv");
        fprintf(stderr, "[NTRACE:INIT] Loaded recv hook\n");
    }
}

/**
 * @brief Detect if socket data contains HTTP protocol traffic
 *
 * Performs lightweight inspection of socket data to determine if it contains
 * HTTP requests or responses. This filtering reduces noise by only logging
 * HTTP-related socket traffic to the Rust parser.
 *
 * Detection logic:
 * - HTTP requests: Looks for standard HTTP method verbs (GET, POST, etc.)
 * - HTTP responses: Looks for HTTP version prefix ("HTTP/")
 *
 * @param data Pointer to socket data buffer
 * @param len Length of data in buffer
 *
 * @return 1 if data appears to be HTTP, 0 otherwise
 */
static int is_http_data(const char* data, size_t len) {
    if (len < 4) return 0;

    /* Check for HTTP request methods */
    if (strncmp(data, "GET ", 4) == 0 ||
        strncmp(data, "POST ", 5) == 0 ||
        strncmp(data, "PUT ", 4) == 0 ||
        strncmp(data, "DELETE ", 7) == 0 ||
        strncmp(data, "HEAD ", 5) == 0 ||
        strncmp(data, "OPTIONS ", 8) == 0) {
        return 1;
    }

    /* Check for HTTP response status line */
    if (strncmp(data, "HTTP/", 5) == 0) {
        return 1;
    }

    return 0;
}

/**
 * @brief Log HTTP socket data to stderr in structured format for Rust parser
 *
 * Outputs HTTP data using a custom format that the Rust application can easily
 * parse from the target process's stderr stream. Only logs data that passes
 * the is_http_data() filter to reduce noise.
 *
 * Output format: [NTRACE:DIRECTION:SOCKFD:LEN]raw_http_data[/NTRACE]
 *
 * This format allows the Rust parse_hook_output() function to:
 * 1. Identify our log lines vs regular stderr output
 * 2. Extract metadata (direction, socket fd, data length)
 * 3. Parse the raw HTTP data with httparse crate
 *
 * @param direction "SEND" for outgoing data, "RECV" for incoming data
 * @param sockfd Socket file descriptor for connection tracking
 * @param data Pointer to HTTP data buffer
 * @param len Length of data in buffer
 */
static void log_http_data(const char* direction, int sockfd, const void* data, size_t len) {
    if (!is_http_data((const char*)data, len)) return;

    fprintf(stderr, "[NTRACE:%s:%d:%zu]", direction, sockfd, len);
    fwrite(data, 1, len, stderr);
    fprintf(stderr, "[/NTRACE]\n");
    fflush(stderr);  /* Ensure immediate output for real-time monitoring */
}

/**
 * @brief Hooked send() system call for intercepting outgoing HTTP requests
 *
 * This function replaces the system's send() call when our library is injected.
 * It logs any HTTP data being sent before calling the original send() function.
 *
 * The Rust application uses this to capture outgoing HTTP requests like:
 * - GET/POST request lines
 * - HTTP headers
 * - Request bodies (for POST/PUT requests)
 *
 * @param sockfd Socket file descriptor
 * @param buf Buffer containing data to send
 * @param len Length of data to send
 * @param flags Socket send flags (passed through to original)
 *
 * @return Number of bytes sent, or -1 on error (from original send())
 */
ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    init_hooks();

    /* Log outgoing HTTP data before sending */
    log_http_data("SEND", sockfd, buf, len);

    /* Call the real send() function */
    return original_send(sockfd, buf, len, flags);
}

/**
 * @brief Hooked recv() system call for intercepting incoming HTTP responses
 *
 * This function replaces the system's recv() call when our library is injected.
 * It calls the original recv() first to get the data, then logs any HTTP responses.
 *
 * The Rust application uses this to capture incoming HTTP responses like:
 * - HTTP status lines (HTTP/1.1 200 OK)
 * - Response headers (Content-Type, Content-Length, etc.)
 * - Response bodies (JSON, HTML, etc.)
 *
 * @param sockfd Socket file descriptor
 * @param buf Buffer to receive data into
 * @param len Maximum length of data to receive
 * @param flags Socket recv flags (passed through to original)
 *
 * @return Number of bytes received, or -1 on error (from original recv())
 */
ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    init_hooks();

    /* Call the real recv() function first to get the data */
    ssize_t result = original_recv(sockfd, buf, len, flags);

    /* Log incoming HTTP data only if we successfully received some */
    if (result > 0) {
        log_http_data("RECV", sockfd, buf, result);
    }

    return result;
}
