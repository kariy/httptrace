use clap::Parser;
use std::env;
use std::io::{BufRead, BufReader};
use std::process::{Command as StdCommand, Stdio};

mod http_parser;
use http_parser::HttpRequest;

#[derive(Parser)]
#[command(name = "ntrace", version)]
#[command(about = "Network tracer for HTTP requests on macOS")]
struct Args {
    /// Command to execute and trace
    #[arg(short, long, value_name = "COMMAND")]
    command: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Build the dynamic library path
    let hook_lib = build_hook_library()?;

    println!("🔍 Starting ntrace for: {}", args.command);
    println!("📡 Monitoring HTTP requests...\n");

    trace_command(&args.command, &hook_lib)?;

    Ok(())
}

fn build_hook_library() -> Result<String, Box<dyn std::error::Error>> {
    // Use the pre-built shared library
    let lib_path = "libntrace_hook.dylib";

    // Check if library exists
    if !std::path::Path::new(lib_path).exists() {
        return Err("Hook library not found. Run 'make build' first.".into());
    }

    // Return absolute path
    let current_dir = env::current_dir()?;
    Ok(format!("{}/{}", current_dir.display(), lib_path))
}

fn trace_command(command: &str, hook_lib: &str) -> Result<(), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = command.split_whitespace().collect();
    if parts.is_empty() {
        return Err("Empty command".into());
    }

    let mut cmd = StdCommand::new(parts[0]);
    if parts.len() > 1 {
        cmd.args(&parts[1..]);
    }

    // Set up environment to inject our hook library
    cmd.env("DYLD_INSERT_LIBRARIES", hook_lib);
    cmd.env("DYLD_FORCE_FLAT_NAMESPACE", "1");

    // Capture stderr to get our hook output
    cmd.stderr(Stdio::piped());
    cmd.stdout(Stdio::inherit());

    let mut child = cmd.spawn()?;

    // Read and parse the hook output
    if let Some(stderr) = child.stderr.take() {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            let line = line?;
            if let Some(request) = parse_hook_output(&line) {
                print_http_request(&request);
            }
        }
    }

    let status = child.wait()?;

    if !status.success() {
        eprintln!("Command exited with status: {}", status);
    }

    Ok(())
}

fn parse_hook_output(line: &str) -> Option<HttpRequest> {
    // Parse our special format: [NTRACE:SEND:sockfd:len]data[/NTRACE]
    if line.starts_with("[NTRACE:") && line.ends_with("[/NTRACE]") {
        let end_header = line.find(']')?;
        let start_data = end_header + 1;
        let end_data = line.len() - 9; // Remove "[/NTRACE]"

        let header = &line[8..end_header]; // Remove "[NTRACE:"
        let data = &line[start_data..end_data];

        let parts: Vec<&str> = header.split(':').collect();
        if parts.len() == 3 {
            let direction = parts[0];
            let _sockfd = parts[1];
            let _len = parts[2];

            return http_parser::parse_http_data(data, direction == "SEND");
        }
    }
    None
}

fn print_http_request(request: &HttpRequest) {
    match request {
        HttpRequest::Request {
            method,
            url,
            headers,
            ..
        } => {
            println!("🚀 {} {}", method, url);
            for (key, value) in headers {
                println!("   {}: {}", key, value);
            }
            println!();
        }
        HttpRequest::Response {
            status, headers, ..
        } => {
            println!("📥 HTTP/{}", status);
            for (key, value) in headers {
                println!("   {}: {}", key, value);
            }
            println!();
        }
    }
}
