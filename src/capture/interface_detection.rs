use std::process::Command;
use std::collections::HashMap;
use log::{debug, info, warn, error};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum InterfaceDetectionError {
    #[error("Failed to execute command: {0}")]
    CommandFailed(String),
    #[error("Failed to parse routing table")]
    RoutingTableParse,
    #[error("No default route found")]
    NoDefaultRoute,
    #[error("Interface not found: {0}")]
    InterfaceNotFound(String),
}

#[derive(Debug, Clone)]
pub struct RouteInfo {
    pub destination: String,
    pub gateway: String,
    pub interface: String,
    pub flags: String,
}

pub struct InterfaceDetector;

impl InterfaceDetector {
    /// Find the interface used by the default route (most traffic goes through this)
    pub fn get_default_interface() -> Result<String, InterfaceDetectionError> {
        let routes = Self::get_routing_table()?;
        
        // Look for default route (0.0.0.0/0 or default)
        for route in &routes {
            if route.destination == "default" || 
               route.destination == "0.0.0.0" || 
               route.destination.starts_with("0.0.0.0/0") {
                info!("Found default route via interface: {}", route.interface);
                return Ok(route.interface.clone());
            }
        }
        
        Err(InterfaceDetectionError::NoDefaultRoute)
    }
    
    /// Get all active network interfaces (excluding loopback)
    pub fn get_active_interfaces() -> Result<Vec<String>, InterfaceDetectionError> {
        let routes = Self::get_routing_table()?;
        let mut interfaces: std::collections::HashSet<String> = std::collections::HashSet::new();
        
        for route in routes {
            // Skip loopback and local routes
            if !route.interface.contains("lo") && 
               !route.interface.contains("loopback") &&
               !route.destination.starts_with("127.") &&
               !route.destination.starts_with("::1") {
                interfaces.insert(route.interface);
            }
        }
        
        let active_interfaces: Vec<String> = interfaces.into_iter().collect();
        info!("Active interfaces: {:?}", active_interfaces);
        
        Ok(active_interfaces)
    }
    
    /// Predict which interface a destination will use based on routing table
    pub fn predict_interface_for_destination(destination: &str) -> Result<String, InterfaceDetectionError> {
        let routes = Self::get_routing_table()?;
        
        // For HTTP traffic, we often don't know the exact destination
        // So we'll use some heuristics:
        
        // 1. If it's a specific IP, try to match routing table entries
        if Self::is_ip_address(destination) {
            for route in &routes {
                if Self::matches_route(destination, &route.destination) {
                    info!("Found matching route for {}: via {}", destination, route.interface);
                    return Ok(route.interface.clone());
                }
            }
        }
        
        // 2. Fall back to default route
        Self::get_default_interface()
    }
    
    /// Get the routing table from the system
    fn get_routing_table() -> Result<Vec<RouteInfo>, InterfaceDetectionError> {
        // On macOS, use 'netstat -rn' to get routing table
        let output = Command::new("netstat")
            .args(["-rn", "-f", "inet"])
            .output()
            .map_err(|e| InterfaceDetectionError::CommandFailed(format!("netstat failed: {}", e)))?;
        
        if !output.status.success() {
            return Err(InterfaceDetectionError::CommandFailed(
                "netstat command failed".to_string()
            ));
        }
        
        let output_str = String::from_utf8_lossy(&output.stdout);
        debug!("Routing table output:\n{}", output_str);
        
        Self::parse_macos_routing_table(&output_str)
    }
    
    /// Parse macOS routing table output
    fn parse_macos_routing_table(output: &str) -> Result<Vec<RouteInfo>, InterfaceDetectionError> {
        let mut routes = Vec::new();
        let mut parsing_routes = false;
        
        for line in output.lines() {
            let line = line.trim();
            
            // Skip until we reach the routing table section
            if line.starts_with("Destination") {
                parsing_routes = true;
                continue;
            }
            
            if !parsing_routes || line.is_empty() {
                continue;
            }
            
            // Parse routing table line: Destination Gateway Flags Interface
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let route = RouteInfo {
                    destination: parts[0].to_string(),
                    gateway: parts[1].to_string(),
                    flags: parts[2].to_string(),
                    interface: parts[3].to_string(),
                };
                routes.push(route);
            }
        }
        
        if routes.is_empty() {
            return Err(InterfaceDetectionError::RoutingTableParse);
        }
        
        debug!("Parsed {} routes", routes.len());
        Ok(routes)
    }
    
    /// Check if a string looks like an IP address
    fn is_ip_address(addr: &str) -> bool {
        addr.chars().any(|c| c.is_ascii_digit()) && addr.contains('.')
    }
    
    /// Check if a destination matches a routing table entry
    fn matches_route(destination: &str, route_dest: &str) -> bool {
        // Simple matching for now - could be enhanced with subnet matching
        if route_dest == "default" {
            return true;
        }
        
        // Direct match
        if destination == route_dest {
            return true;
        }
        
        // Subnet matching (simplified)
        if route_dest.contains('/') {
            // This is a simplified check - real implementation would need proper CIDR matching
            let network_part = route_dest.split('/').next().unwrap_or(route_dest);
            return destination.starts_with(&network_part[..network_part.len().saturating_sub(3)]);
        }
        
        false
    }
    
    /// Get network interface statistics to see which ones are active
    pub fn get_interface_activity() -> HashMap<String, u64> {
        let mut activity = HashMap::new();
        
        // On macOS, we can use 'netstat -i' to get interface statistics
        if let Ok(output) = Command::new("netstat").args(["-i", "-b"]).output() {
            if output.status.success() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                
                for line in output_str.lines() {
                    if let Some(stats) = Self::parse_interface_stats_line(line) {
                        activity.insert(stats.0, stats.1);
                    }
                }
            }
        }
        
        activity
    }
    
    fn parse_interface_stats_line(line: &str) -> Option<(String, u64)> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 8 {
            // Interface name is in first column, bytes in column 6 (out) or 7 (in)
            let interface = parts[0].to_string();
            if let Ok(bytes_out) = parts[6].parse::<u64>() {
                return Some((interface, bytes_out));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_get_default_interface() {
        // This test requires network connectivity
        match InterfaceDetector::get_default_interface() {
            Ok(interface) => {
                assert!(!interface.is_empty());
                println!("Default interface: {}", interface);
            },
            Err(e) => {
                println!("Could not detect default interface: {}", e);
                // This might fail in test environments without network
            }
        }
    }
    
    #[test]
    fn test_get_active_interfaces() {
        match InterfaceDetector::get_active_interfaces() {
            Ok(interfaces) => {
                println!("Active interfaces: {:?}", interfaces);
                // Should have at least one interface in most environments
            },
            Err(e) => {
                println!("Could not get active interfaces: {}", e);
            }
        }
    }
}
