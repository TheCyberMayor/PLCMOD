"""
Network monitoring and packet capture for ICS cybersecurity.
"""

import asyncio
import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, asdict
from pathlib import Path

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
from loguru import logger
import pandas as pd

# ICS Protocol definitions
ICS_PROTOCOLS = {
    'modbus': 502,
    'ethernet/ip': 44818,
    'dnp3': 20000,
    'bacnet': 47808,
    's7': 102,
    'opc_ua': 4840
}


@dataclass
class PacketData:
    """Data structure for captured packet information."""
    timestamp: float
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    packet_size: int
    payload: bytes
    flags: Dict[str, bool]
    ttl: int
    window_size: int
    sequence_number: int
    acknowledgment_number: int


@dataclass
class ThreatIndicator:
    """Data structure for threat indicators."""
    timestamp: float
    source_ip: str
    destination_ip: str
    threat_type: str
    confidence: float
    description: str
    mitre_technique: Optional[str] = None
    severity: str = "medium"


class NetworkMonitor:
    """Network monitoring and packet analysis for ICS systems."""
    
    def __init__(self, config: Dict):
        """Initialize network monitor."""
        self.config = config
        self.interface = config.get('interface', 'eth0')
        self.packet_count = config.get('packet_count', 1000)
        self.timeout = config.get('timeout', 30)
        self.protocols = config.get('protocols', ['modbus', 'ethernet/ip', 'dnp3'])
        
        # Data storage
        self.packets: List[PacketData] = []
        self.threats: List[ThreatIndicator] = []
        self.running = False
        
        # Callbacks
        self.packet_callbacks: List[Callable] = []
        self.threat_callbacks: List[Callable] = []
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'ics_packets': 0,
            'threats_detected': 0,
            'start_time': None
        }
        
        # Load MITRE ATT&CK data
        self.mitre_data = self._load_mitre_data()
        
        logger.info(f"Network monitor initialized for interface {self.interface}")
    
    def _load_mitre_data(self) -> Dict:
        """Load MITRE ATT&CK ICS data."""
        mitre_path = self.config.get('mitre_attack_db', 'data/mitre_attack_ics.json')
        
        if Path(mitre_path).exists():
            try:
                with open(mitre_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load MITRE data: {e}")
        
        # Return default structure if file doesn't exist
        return {
            'techniques': {},
            'tactics': {},
            'procedures': {}
        }
    
    def add_packet_callback(self, callback: Callable):
        """Add callback for packet processing."""
        self.packet_callbacks.append(callback)
    
    def add_threat_callback(self, callback: Callable):
        """Add callback for threat detection."""
        self.threat_callbacks.append(callback)
    
    def _is_ics_protocol(self, port: int) -> bool:
        """Check if port corresponds to ICS protocol."""
        return port in ICS_PROTOCOLS.values()
    
    def _get_protocol_name(self, port: int) -> Optional[str]:
        """Get protocol name from port number."""
        for name, port_num in ICS_PROTOCOLS.items():
            if port_num == port:
                return name
        return None
    
    def _extract_packet_data(self, packet) -> Optional[PacketData]:
        """Extract relevant data from captured packet."""
        try:
            if IP in packet:
                ip_layer = packet[IP]
                tcp_layer = packet[TCP] if TCP in packet else None
                udp_layer = packet[UDP] if UDP in packet else None
                
                # Determine transport layer
                if tcp_layer:
                    transport_layer = tcp_layer
                    protocol = "TCP"
                elif udp_layer:
                    transport_layer = udp_layer
                    protocol = "UDP"
                else:
                    return None
                
                # Extract packet data
                packet_data = PacketData(
                    timestamp=time.time(),
                    source_ip=ip_layer.src,
                    destination_ip=ip_layer.dst,
                    source_port=transport_layer.sport,
                    destination_port=transport_layer.dport,
                    protocol=protocol,
                    packet_size=len(packet),
                    payload=bytes(packet.payload) if packet.payload else b'',
                    flags={
                        'syn': bool(tcp_layer.flags & 0x02) if tcp_layer else False,
                        'ack': bool(tcp_layer.flags & 0x10) if tcp_layer else False,
                        'fin': bool(tcp_layer.flags & 0x01) if tcp_layer else False,
                        'rst': bool(tcp_layer.flags & 0x04) if tcp_layer else False,
                        'psh': bool(tcp_layer.flags & 0x08) if tcp_layer else False,
                        'urg': bool(tcp_layer.flags & 0x20) if tcp_layer else False
                    },
                    ttl=ip_layer.ttl,
                    window_size=tcp_layer.window if tcp_layer else 0,
                    sequence_number=tcp_layer.seq if tcp_layer else 0,
                    acknowledgment_number=tcp_layer.ack if tcp_layer else 0
                )
                
                return packet_data
                
        except Exception as e:
            logger.error(f"Error extracting packet data: {e}")
            return None
    
    def _analyze_packet(self, packet_data: PacketData) -> Optional[ThreatIndicator]:
        """Analyze packet for potential threats."""
        threats = []
        
        # Check for ICS protocol communication
        if self._is_ics_protocol(packet_data.destination_port):
            protocol_name = self._get_protocol_name(packet_data.destination_port)
            
            # Check for suspicious patterns
            if self._is_port_scan(packet_data):
                threats.append(ThreatIndicator(
                    timestamp=packet_data.timestamp,
                    source_ip=packet_data.source_ip,
                    destination_ip=packet_data.destination_ip,
                    threat_type="port_scan",
                    confidence=0.8,
                    description=f"Port scan detected on {protocol_name} port",
                    mitre_technique="T1595.001",  # Active Scanning: Scanning IP Blocks
                    severity="medium"
                ))
            
            if self._is_unauthorized_access(packet_data):
                threats.append(ThreatIndicator(
                    timestamp=packet_data.timestamp,
                    source_ip=packet_data.source_ip,
                    destination_ip=packet_data.destination_ip,
                    threat_type="unauthorized_access",
                    confidence=0.9,
                    description=f"Unauthorized access attempt to {protocol_name}",
                    mitre_technique="T1078",  # Valid Accounts
                    severity="high"
                ))
            
            if self._is_malicious_payload(packet_data):
                threats.append(ThreatIndicator(
                    timestamp=packet_data.timestamp,
                    source_ip=packet_data.source_ip,
                    destination_ip=packet_data.destination_ip,
                    threat_type="malicious_payload",
                    confidence=0.7,
                    description=f"Potential malicious payload in {protocol_name} communication",
                    mitre_technique="T1059",  # Command and Scripting Interpreter
                    severity="high"
                ))
        
        return threats[0] if threats else None
    
    def _is_port_scan(self, packet_data: PacketData) -> bool:
        """Detect port scanning activity."""
        # Simple heuristic: multiple SYN packets without ACK
        if packet_data.flags.get('syn') and not packet_data.flags.get('ack'):
            # Check if we've seen multiple similar packets from this source
            recent_packets = [p for p in self.packets[-100:] 
                            if p.source_ip == packet_data.source_ip 
                            and p.flags.get('syn') 
                            and not p.flags.get('ack')]
            
            return len(recent_packets) > 5
        
        return False
    
    def _is_unauthorized_access(self, packet_data: PacketData) -> bool:
        """Detect unauthorized access attempts."""
        # Check against whitelist of authorized IPs
        authorized_ips = self.config.get('authorized_ips', [])
        
        if authorized_ips and packet_data.source_ip not in authorized_ips:
            return True
        
        return False
    
    def _is_malicious_payload(self, packet_data: PacketData) -> bool:
        """Detect potentially malicious payloads."""
        if not packet_data.payload:
            return False
        
        # Check for common attack patterns
        payload_str = packet_data.payload.decode('utf-8', errors='ignore').lower()
        
        malicious_patterns = [
            'admin', 'root', 'password', 'exec', 'system',
            'cmd', 'shell', 'backdoor', 'exploit'
        ]
        
        return any(pattern in payload_str for pattern in malicious_patterns)
    
    def _packet_callback(self, packet):
        """Callback function for packet capture."""
        try:
            # Extract packet data
            packet_data = self._extract_packet_data(packet)
            if not packet_data:
                return
            
            # Store packet
            self.packets.append(packet_data)
            self.stats['total_packets'] += 1
            
            # Check if it's ICS protocol
            if self._is_ics_protocol(packet_data.destination_port):
                self.stats['ics_packets'] += 1
            
            # Analyze for threats
            threat = self._analyze_packet(packet_data)
            if threat:
                self.threats.append(threat)
                self.stats['threats_detected'] += 1
                
                # Notify threat callbacks
                for callback in self.threat_callbacks:
                    try:
                        callback(threat)
                    except Exception as e:
                        logger.error(f"Error in threat callback: {e}")
            
            # Notify packet callbacks
            for callback in self.packet_callbacks:
                try:
                    callback(packet_data)
                except Exception as e:
                    logger.error(f"Error in packet callback: {e}")
            
            # Limit packet storage
            if len(self.packets) > 10000:
                self.packets = self.packets[-5000:]
            
        except Exception as e:
            logger.error(f"Error in packet callback: {e}")
    
    async def start(self):
        """Start network monitoring."""
        if self.running:
            logger.warning("Network monitor is already running")
            return
        
        self.running = True
        self.stats['start_time'] = time.time()
        
        logger.info(f"Starting network monitoring on interface {self.interface}")
        
        # Start packet capture in background
        asyncio.create_task(self._capture_packets())
        
        # Start log collection
        asyncio.create_task(self._collect_logs())
    
    async def _capture_packets(self):
        """Capture network packets."""
        try:
            # Create filter for ICS protocols
            port_filter = " or ".join([f"port {ICS_PROTOCOLS[proto]}" 
                                     for proto in self.protocols])
            
            logger.info(f"Starting packet capture with filter: {port_filter}")
            
            # Start packet capture
            scapy.sniff(
                iface=self.interface,
                prn=self._packet_callback,
                filter=port_filter,
                store=False,
                timeout=self.timeout
            )
            
        except Exception as e:
            logger.error(f"Error in packet capture: {e}")
            self.running = False
    
    async def _collect_logs(self):
        """Collect system logs."""
        log_sources = self.config.get('log_sources', [])
        log_interval = self.config.get('log_interval', 60)
        
        while self.running:
            try:
                for log_source in log_sources:
                    if Path(log_source).exists():
                        # Read recent log entries
                        with open(log_source, 'r') as f:
                            lines = f.readlines()[-100:]  # Last 100 lines
                            
                            for line in lines:
                                # Analyze log for security events
                                if self._is_security_event(line):
                                    threat = ThreatIndicator(
                                        timestamp=time.time(),
                                        source_ip="system",
                                        destination_ip="system",
                                        threat_type="log_alert",
                                        confidence=0.6,
                                        description=f"Security event in {log_source}: {line.strip()}",
                                        severity="medium"
                                    )
                                    
                                    self.threats.append(threat)
                                    self.stats['threats_detected'] += 1
                
                await asyncio.sleep(log_interval)
                
            except Exception as e:
                logger.error(f"Error collecting logs: {e}")
                await asyncio.sleep(log_interval)
    
    def _is_security_event(self, log_line: str) -> bool:
        """Check if log line indicates a security event."""
        security_keywords = [
            'failed login', 'authentication failure', 'unauthorized access',
            'permission denied', 'security alert', 'intrusion detected'
        ]
        
        return any(keyword in log_line.lower() for keyword in security_keywords)
    
    async def stop(self):
        """Stop network monitoring."""
        self.running = False
        logger.info("Network monitoring stopped")
    
    def get_statistics(self) -> Dict:
        """Get monitoring statistics."""
        uptime = time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
        
        return {
            **self.stats,
            'uptime': uptime,
            'packets_per_second': self.stats['total_packets'] / uptime if uptime > 0 else 0,
            'threats_per_hour': (self.stats['threats_detected'] / uptime) * 3600 if uptime > 0 else 0
        }
    
    def get_recent_packets(self, limit: int = 100) -> List[Dict]:
        """Get recent packet data."""
        return [asdict(packet) for packet in self.packets[-limit:]]
    
    def get_recent_threats(self, limit: int = 50) -> List[Dict]:
        """Get recent threat indicators."""
        return [asdict(threat) for threat in self.threats[-limit:]]
    
    def export_data(self, filepath: str):
        """Export captured data to file."""
        try:
            data = {
                'packets': [asdict(packet) for packet in self.packets],
                'threats': [asdict(threat) for threat in self.threats],
                'statistics': self.get_statistics()
            }
            
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
            logger.info(f"Data exported to {filepath}")
            
        except Exception as e:
            logger.error(f"Error exporting data: {e}") 