use pcap::{Capture, Device};
use thiserror::Error;
use log::{info, debug, error, warn};

#[derive(Error, Debug)]
pub enum CaptureError {
    #[error("Failed to list network devices: {0}")]
    DeviceList(#[from] pcap::Error),
    #[error("No network devices available")]
    NoDevices,
    #[error("Device not found: {0}")]
    DeviceNotFound(String),
    #[error("Failed to open capture device: {0}")]
    CaptureOpen(pcap::Error),
    #[error("Failed to configure capture: {0}")]
    CaptureConfig(pcap::Error),
    #[error("Packet capture error: {0}")]
    PacketCapture(pcap::Error),
}

pub struct PcapCapture {
    capture: Capture<pcap::Active>,
    interface_name: String,
}

impl PcapCapture {
    /// List all available network interfaces
    pub fn list_devices() -> Result<Vec<Device>, CaptureError> {
        let devices = Device::list()?;
        if devices.is_empty() {
            return Err(CaptureError::NoDevices);
        }
        
        info!("Available network devices:");
        for device in &devices {
            info!("  {} - {}", device.name, device.desc.as_deref().unwrap_or("No description"));
        }
        
        Ok(devices)
    }
    
    /// Find the best network interface to capture on using intelligent detection
    pub fn find_best_device() -> Result<Device, CaptureError> {
        let devices = Self::list_devices()?;
        
        // Try to get the default route interface first
        if let Ok(default_interface) = crate::capture::InterfaceDetector::get_default_interface() {
            info!("Using default route interface: {}", default_interface);
            for device in &devices {
                if device.name == default_interface {
                    return Ok(device.clone());
                }
            }
            warn!("Default interface {} not found in pcap device list", default_interface);
        }
        
        // Fallback: get active interfaces from routing table
        if let Ok(active_interfaces) = crate::capture::InterfaceDetector::get_active_interfaces() {
            for active_interface in &active_interfaces {
                for device in &devices {
                    if device.name == *active_interface {
                        info!("Selected active interface: {}", device.name);
                        return Ok(device.clone());
                    }
                }
            }
        }
        
        // Final fallback: prefer non-loopback interfaces
        for device in &devices {
            if !device.name.contains("lo") && 
               !device.name.contains("loopback") {
                warn!("Using fallback non-loopback interface: {}", device.name);
                return Ok(device.clone());
            }
        }
        
        // Last resort: first available device
        if let Some(device) = devices.first() {
            warn!("Using last resort interface: {}", device.name);
            Ok(device.clone())
        } else {
            Err(CaptureError::NoDevices)
        }
    }
    
    /// Create a new packet capture instance on the specified interface
    pub fn new(interface_name: Option<&str>) -> Result<Self, CaptureError> {
        let device = if let Some(name) = interface_name {
            // Find specific interface by name
            let devices = Self::list_devices()?;
            devices.into_iter()
                .find(|d| d.name == name)
                .ok_or_else(|| CaptureError::DeviceNotFound(name.to_string()))?
        } else {
            // Find best available interface
            Self::find_best_device()?
        };
        
        info!("Opening capture on interface: {}", device.name);
        
        // Create capture session
        let mut capture = Capture::from_device(device.clone())
            .map_err(CaptureError::CaptureOpen)?
            .promisc(true)  // Enable promiscuous mode
            .snaplen(65535) // Capture full packets
            .timeout(100)   // 100ms timeout for packet reads
            .immediate_mode(true) // Reduce kernel buffering
            .open()
            .map_err(CaptureError::CaptureConfig)?;
        
        // Set BPF filter to capture only TCP traffic (HTTP runs over TCP)
        capture.filter("tcp", true)
            .map_err(CaptureError::CaptureConfig)?;
        
        info!("Packet capture initialized successfully");
        
        Ok(Self {
            capture,
            interface_name: device.name,
        })
    }
    
    /// Start capturing packets and process them with the provided callback
    pub fn start_capture<F>(&mut self, mut packet_handler: F) -> Result<(), CaptureError>
    where
        F: FnMut(&[u8]) -> bool, // Return false to stop capture
    {
        info!("Starting packet capture on interface: {}", self.interface_name);
        
        loop {
            match self.capture.next_packet() {
                Ok(packet) => {
                    debug!("Captured packet: {} bytes", packet.data.len());
                    
                    // Call the packet handler
                    if !packet_handler(packet.data) {
                        info!("Packet handler requested capture stop");
                        break;
                    }
                },
                Err(pcap::Error::TimeoutExpired) => {
                    // Timeout is normal - continue capturing
                    continue;
                },
                Err(e) => {
                    error!("Packet capture error: {}", e);
                    return Err(CaptureError::PacketCapture(e));
                }
            }
        }
        
        Ok(())
    }
    
    /// Get statistics about the capture session
    pub fn stats(&mut self) -> Result<pcap::Stat, CaptureError> {
        self.capture.stats()
            .map_err(CaptureError::PacketCapture)
    }
    
    /// Get the interface name being used for capture
    pub fn interface_name(&self) -> &str {
        &self.interface_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_list_devices() {
        // This test requires admin privileges and actual network interfaces
        // Run with: sudo cargo test
        let devices = PcapCapture::list_devices();
        match devices {
            Ok(devs) => {
                assert!(!devs.is_empty(), "Should have at least one network device");
            },
            Err(CaptureError::NoDevices) => {
                // This might happen in some test environments
                println!("No network devices available for testing");
            },
            Err(e) => {
                panic!("Unexpected error: {}", e);
            }
        }
    }
}
