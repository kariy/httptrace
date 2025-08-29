use clap::Parser;
use std::process::{Command as StdCommand, Stdio};
use std::time::{Duration, Instant};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::thread;
use log::{info, error, warn};

mod http_parser;
mod capture;

use http_parser::HttpRequest;
use capture::{PcapCapture, CaptureError, InterfaceDetector};

#[derive(Parser)]
#[command(version, about = "HTTP traffic tracer using packet capture")]
struct Args {
    /// Command to execute and trace (optional - if not provided, captures all HTTP traffic)
    #[arg(short, long, value_name = "COMMAND")]
    command: Option<String>,
    
    /// Network interface to capture on (auto-detect if not specified)
    #[arg(short, long, value_name = "INTERFACE")]
    interface: Option<String>,
    
    /// Duration to capture packets (in seconds, default: indefinite)
    #[arg(short, long, value_name = "SECONDS")]
    duration: Option<u64>,
    
    /// List available network interfaces and exit
    #[arg(short, long)]
    list: bool,
    
    /// Capture on all active interfaces simultaneously
    #[arg(short = 'A', long)]
    all_interfaces: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let args = Args::parse();

    // Handle list command
    if args.list {
        list_interfaces()?;
        return Ok(());
    }

    println!("🔍 Starting httptrace");
    
    if let Some(ref cmd) = args.command {
        println!("📡 Launching command: {}", cmd);
        capture_with_command(&args)?;
    } else {
        println!("📡 Monitoring all HTTP traffic...");
        capture_continuously(&args)?;
    }

    Ok(())
}

fn list_interfaces() -> Result<(), Box<dyn std::error::Error>> {
    println!("Available network interfaces:");
    let devices = PcapCapture::list_devices()?;
    
    // Get the default interface for highlighting
    let default_interface = InterfaceDetector::get_default_interface().ok();
    let active_interfaces = InterfaceDetector::get_active_interfaces().unwrap_or_default();
    
    for device in devices {
        let mut tags = Vec::new();
        
        if Some(&device.name) == default_interface.as_ref() {
            tags.push("default route");
        }
        if active_interfaces.contains(&device.name) {
            tags.push("active");
        }
        
        let tag_str = if tags.is_empty() {
            String::new()
        } else {
            format!(" [{}]", tags.join(", "))
        };
        
        println!("  {}{} - {}", 
                device.name,
                tag_str,
                device.desc.as_deref().unwrap_or("No description"));
    }
    
    // Show interface statistics
    println!("\nInterface activity (bytes transmitted):");
    let activity = InterfaceDetector::get_interface_activity();
    for (interface, bytes) in activity {
        if bytes > 0 {
            println!("  {}: {} bytes", interface, bytes);
        }
    }
    
    Ok(())
}

fn capture_with_command(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let command = args.command.as_ref().unwrap();
    
    // Start packet capture in background
    let mut capture = PcapCapture::new(args.interface.as_deref())?;
    println!("🔍 Starting capture on interface: {}", capture.interface_name());
    
    // Set up signal handling for graceful shutdown
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    
    ctrlc::set_handler(move || {
        println!("\n🛑 Received interrupt signal, stopping capture...");
        r.store(false, Ordering::SeqCst);
    })?;
    
    // Launch the command
    let mut child = launch_command(command)?;
    
    // Start packet capture
    let capture_running = running.clone();
    let capture_handle = thread::spawn(move || {
        let result = capture.start_capture(|packet_data| {
            if !capture_running.load(Ordering::SeqCst) {
                return false; // Stop capture
            }
            
            // Process the packet for HTTP content
            process_packet(packet_data);
            true // Continue capture
        });
        
        if let Err(e) = result {
            error!("Capture error: {}", e);
        }
    });
    
    // Wait for command to finish or timeout
    if let Some(duration) = args.duration {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(duration) && running.load(Ordering::SeqCst) {
            if let Ok(Some(_)) = child.try_wait() {
                break; // Command finished
            }
            thread::sleep(Duration::from_millis(100));
        }
    } else {
        // Wait for command to finish
        child.wait()?;
    }
    
    // Stop capture
    running.store(false, Ordering::SeqCst);
    
    // Clean up
    if capture_handle.join().is_err() {
        warn!("Capture thread did not shut down cleanly");
    }
    
    println!("✅ Capture completed");
    Ok(())
}

fn capture_continuously(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let mut capture = PcapCapture::new(args.interface.as_deref())?;
    println!("🔍 Starting capture on interface: {}", capture.interface_name());
    
    if let Some(duration) = args.duration {
        println!("⏰ Capture duration: {} seconds", duration);
    } else {
        println!("⏰ Press Ctrl+C to stop capture");
    }
    
    // Set up signal handling for graceful shutdown
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    
    ctrlc::set_handler(move || {
        println!("\n🛑 Received interrupt signal, stopping capture...");
        r.store(false, Ordering::SeqCst);
    })?;
    
    let start_time = Instant::now();
    let mut packet_count = 0;
    
    capture.start_capture(|packet_data| {
        if !running.load(Ordering::SeqCst) {
            return false; // Stop capture
        }
        
        // Check duration limit
        if let Some(duration) = args.duration {
            if start_time.elapsed() >= Duration::from_secs(duration) {
                println!("⏰ Duration limit reached, stopping capture");
                return false;
            }
        }
        
        // Process the packet for HTTP content
        process_packet(packet_data);
        packet_count += 1;
        
        true // Continue capture
    })?;
    
    println!("✅ Capture completed. Processed {} packets", packet_count);
    Ok(())
}

fn launch_command(command: &str) -> Result<std::process::Child, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = command.split_whitespace().collect();
    if parts.is_empty() {
        return Err("Empty command".into());
    }

    let mut cmd = StdCommand::new(parts[0]);
    if parts.len() > 1 {
        cmd.args(&parts[1..]);
    }

    // Let command use normal stdout/stderr
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    let child = cmd.spawn()?;
    info!("Launched command with PID: {}", child.id());
    
    Ok(child)
}

fn process_packet(packet_data: &[u8]) {
    // For now, we'll implement basic packet processing
    // This will be enhanced when we add the packet parsing logic
    
    // Try to extract HTTP data from the packet
    if let Some(http_data) = extract_http_from_packet(packet_data) {
        if let Some(request) = http_parser::parse_http_data(&http_data, true) {
            print_http_request(&request);
        }
    }
}

fn extract_http_from_packet(packet_data: &[u8]) -> Option<String> {
    // Basic implementation - look for HTTP patterns in the packet
    // This is a simplified version and will need to be enhanced with proper TCP/IP parsing
    
    if packet_data.len() < 20 {
        return None; // Too small to contain meaningful data
    }
    
    // Convert to string and look for HTTP patterns
    if let Ok(data_str) = std::str::from_utf8(packet_data) {
        if data_str.contains("HTTP/") || 
           data_str.starts_with("GET ") ||
           data_str.starts_with("POST ") ||
           data_str.starts_with("PUT ") ||
           data_str.starts_with("DELETE ") {
            return Some(data_str.to_string());
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
