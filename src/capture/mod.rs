pub mod pcap;
pub mod interface_detection;

pub use pcap::{PcapCapture, CaptureError};
pub use interface_detection::{InterfaceDetector, InterfaceDetectionError};
