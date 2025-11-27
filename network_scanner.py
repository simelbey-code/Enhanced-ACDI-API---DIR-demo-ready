"""
ACDI Network Scanner Module
Wraps Nmap for cryptographic service discovery

IFG Quantum Holdings - Confidential
"""

import subprocess
import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Any
from datetime import datetime
import ipaddress
import re


@dataclass
class DiscoveredService:
    """Represents a discovered network service with crypto potential"""
    ip_address: str
    hostname: str
    port: int
    protocol: str
    service_name: str
    service_version: str
    has_ssl: bool
    state: str
    discovery_time: str
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    """Complete scan result"""
    scan_id: str
    target: str
    start_time: str
    end_time: str
    status: str
    hosts_up: int
    hosts_total: int
    services: List[DiscoveredService]
    errors: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['services'] = [s.to_dict() for s in self.services]
        return result


class NetworkScanner:
    """
    Network scanner for cryptographic service discovery
    Uses Nmap for comprehensive network enumeration
    """
    
    # Ports commonly using cryptography
    CRYPTO_PORTS = {
        22: 'ssh',
        25: 'smtp',
        110: 'pop3',
        143: 'imap',
        443: 'https',
        465: 'smtps',
        587: 'submission',
        636: 'ldaps',
        853: 'dns-over-tls',
        989: 'ftps-data',
        990: 'ftps',
        993: 'imaps',
        995: 'pop3s',
        1194: 'openvpn',
        3389: 'rdp',
        5061: 'sips',
        5432: 'postgresql',
        5671: 'amqps',
        6379: 'redis',
        8080: 'http-proxy',
        8443: 'https-alt',
        9200: 'elasticsearch',
        27017: 'mongodb',
    }
    
    # Extended port list for deep scans
    EXTENDED_PORTS = list(range(1, 1024)) + [
        1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 
        8000, 8080, 8443, 8888, 9000, 9090, 9200, 9300,
        27017, 27018, 27019
    ]
    
    def __init__(self, nmap_path: str = "nmap"):
        self.nmap_path = nmap_path
        self.scan_count = 0
        
    def _generate_scan_id(self) -> str:
        """Generate unique scan ID"""
        self.scan_count += 1
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        return f"SCAN-{timestamp}-{self.scan_count:04d}"
    
    def _validate_target(self, target: str) -> bool:
        """Validate target is a valid IP, range, or hostname"""
        # Check if it's a valid IP address
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            pass
        
        # Check if it's a valid network range
        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            pass
        
        # Check if it's a valid hostname pattern
        hostname_pattern = re.compile(
            r'^(?=.{1,253}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)*(?!-)[A-Za-z0-9-]{1,63}(?<!-)$'
        )
        if hostname_pattern.match(target):
            return True
            
        # Check for IP range notation (e.g., 192.168.1.1-254)
        range_pattern = re.compile(
            r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$'
        )
        if range_pattern.match(target):
            return True
            
        return False
    
    def _parse_nmap_xml(self, xml_output: str) -> List[DiscoveredService]:
        """Parse Nmap XML output into DiscoveredService objects"""
        services = []
        
        try:
            root = ET.fromstring(xml_output)
            
            for host in root.findall('.//host'):
                # Get host status
                status = host.find('status')
                if status is None or status.get('state') != 'up':
                    continue
                
                # Get IP address
                address = host.find("address[@addrtype='ipv4']")
                if address is None:
                    address = host.find("address[@addrtype='ipv6']")
                ip = address.get('addr') if address is not None else 'unknown'
                
                # Get hostname
                hostname_elem = host.find('.//hostname')
                hostname = hostname_elem.get('name') if hostname_elem is not None else ip
                
                # Get ports/services
                for port in host.findall('.//port'):
                    port_id = int(port.get('portid', 0))
                    protocol = port.get('protocol', 'tcp')
                    
                    state_elem = port.find('state')
                    state = state_elem.get('state') if state_elem is not None else 'unknown'
                    
                    if state != 'open':
                        continue
                    
                    service_elem = port.find('service')
                    if service_elem is not None:
                        service_name = service_elem.get('name', 'unknown')
                        service_version = service_elem.get('version', '')
                        product = service_elem.get('product', '')
                        if product:
                            service_version = f"{product} {service_version}".strip()
                        
                        # Check for SSL/TLS
                        tunnel = service_elem.get('tunnel', '')
                        has_ssl = tunnel == 'ssl' or service_name in [
                            'https', 'ssl', 'imaps', 'pop3s', 'smtps', 
                            'ldaps', 'ftps', 'ssh'
                        ]
                    else:
                        service_name = self.CRYPTO_PORTS.get(port_id, 'unknown')
                        service_version = ''
                        has_ssl = port_id in [443, 465, 636, 993, 995, 990, 8443]
                    
                    services.append(DiscoveredService(
                        ip_address=ip,
                        hostname=hostname,
                        port=port_id,
                        protocol=protocol,
                        service_name=service_name,
                        service_version=service_version,
                        has_ssl=has_ssl,
                        state=state,
                        discovery_time=datetime.now().isoformat()
                    ))
                    
        except ET.ParseError as e:
            print(f"XML parsing error: {e}")
            
        return services
    
    def scan_surface(self, target: str) -> ScanResult:
        """
        Surface scan - common crypto ports only
        Faster, less intrusive
        """
        if not self._validate_target(target):
            return ScanResult(
                scan_id=self._generate_scan_id(),
                target=target,
                start_time=datetime.now().isoformat(),
                end_time=datetime.now().isoformat(),
                status='failed',
                hosts_up=0,
                hosts_total=0,
                services=[],
                errors=[f"Invalid target: {target}"]
            )
        
        scan_id = self._generate_scan_id()
        start_time = datetime.now().isoformat()
        
        # Build port list
        ports = ','.join(str(p) for p in self.CRYPTO_PORTS.keys())
        
        # Nmap command for surface scan
        cmd = [
            self.nmap_path,
            '-sV',                    # Version detection
            '-sS',                    # SYN scan (stealthy)
            '--version-intensity', '5',
            '-p', ports,
            '-oX', '-',               # XML output to stdout
            '--open',                 # Only show open ports
            '-T4',                    # Aggressive timing
            target
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout
            )
            
            if result.returncode != 0 and not result.stdout:
                return ScanResult(
                    scan_id=scan_id,
                    target=target,
                    start_time=start_time,
                    end_time=datetime.now().isoformat(),
                    status='failed',
                    hosts_up=0,
                    hosts_total=0,
                    services=[],
                    errors=[result.stderr]
                )
            
            services = self._parse_nmap_xml(result.stdout)
            
            # Count unique hosts
            unique_hosts = set(s.ip_address for s in services)
            
            return ScanResult(
                scan_id=scan_id,
                target=target,
                start_time=start_time,
                end_time=datetime.now().isoformat(),
                status='completed',
                hosts_up=len(unique_hosts),
                hosts_total=len(unique_hosts),
                services=services,
                errors=[]
            )
            
        except subprocess.TimeoutExpired:
            return ScanResult(
                scan_id=scan_id,
                target=target,
                start_time=start_time,
                end_time=datetime.now().isoformat(),
                status='timeout',
                hosts_up=0,
                hosts_total=0,
                services=[],
                errors=["Scan timed out after 10 minutes"]
            )
        except FileNotFoundError:
            return ScanResult(
                scan_id=scan_id,
                target=target,
                start_time=start_time,
                end_time=datetime.now().isoformat(),
                status='failed',
                hosts_up=0,
                hosts_total=0,
                services=[],
                errors=["Nmap not found. Please install nmap."]
            )
        except Exception as e:
            return ScanResult(
                scan_id=scan_id,
                target=target,
                start_time=start_time,
                end_time=datetime.now().isoformat(),
                status='failed',
                hosts_up=0,
                hosts_total=0,
                services=[],
                errors=[str(e)]
            )
    
    def scan_deep(self, target: str) -> ScanResult:
        """
        Deep scan - comprehensive port scanning with service detection
        Slower, more thorough
        """
        if not self._validate_target(target):
            return ScanResult(
                scan_id=self._generate_scan_id(),
                target=target,
                start_time=datetime.now().isoformat(),
                end_time=datetime.now().isoformat(),
                status='failed',
                hosts_up=0,
                hosts_total=0,
                services=[],
                errors=[f"Invalid target: {target}"]
            )
        
        scan_id = self._generate_scan_id()
        start_time = datetime.now().isoformat()
        
        # Build comprehensive port list
        ports = ','.join(str(p) for p in sorted(set(self.EXTENDED_PORTS)))
        
        # Nmap command for deep scan
        cmd = [
            self.nmap_path,
            '-sV',                    # Version detection
            '-sS',                    # SYN scan
            '-sC',                    # Default scripts
            '--version-intensity', '7',
            '-p', ports,
            '-oX', '-',               # XML output to stdout
            '--open',                 # Only show open ports
            '-T4',                    # Aggressive timing
            '--script', 'ssl-enum-ciphers,ssl-cert',  # SSL scripts
            target
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout for deep scan
            )
            
            if result.returncode != 0 and not result.stdout:
                return ScanResult(
                    scan_id=scan_id,
                    target=target,
                    start_time=start_time,
                    end_time=datetime.now().isoformat(),
                    status='failed',
                    hosts_up=0,
                    hosts_total=0,
                    services=[],
                    errors=[result.stderr]
                )
            
            services = self._parse_nmap_xml(result.stdout)
            unique_hosts = set(s.ip_address for s in services)
            
            return ScanResult(
                scan_id=scan_id,
                target=target,
                start_time=start_time,
                end_time=datetime.now().isoformat(),
                status='completed',
                hosts_up=len(unique_hosts),
                hosts_total=len(unique_hosts),
                services=services,
                errors=[]
            )
            
        except subprocess.TimeoutExpired:
            return ScanResult(
                scan_id=scan_id,
                target=target,
                start_time=start_time,
                end_time=datetime.now().isoformat(),
                status='timeout',
                hosts_up=0,
                hosts_total=0,
                services=[],
                errors=["Deep scan timed out after 1 hour"]
            )
        except FileNotFoundError:
            return ScanResult(
                scan_id=scan_id,
                target=target,
                start_time=start_time,
                end_time=datetime.now().isoformat(),
                status='failed',
                hosts_up=0,
                hosts_total=0,
                services=[],
                errors=["Nmap not found. Please install nmap."]
            )
        except Exception as e:
            return ScanResult(
                scan_id=scan_id,
                target=target,
                start_time=start_time,
                end_time=datetime.now().isoformat(),
                status='failed',
                hosts_up=0,
                hosts_total=0,
                services=[],
                errors=[str(e)]
            )


# Convenience function for quick scans
def quick_scan(target: str, deep: bool = False) -> Dict[str, Any]:
    """Quick scan function for API use"""
    scanner = NetworkScanner()
    if deep:
        result = scanner.scan_deep(target)
    else:
        result = scanner.scan_surface(target)
    return result.to_dict()


if __name__ == "__main__":
    # Test with localhost
    scanner = NetworkScanner()
    print("Testing surface scan on localhost...")
    result = scanner.scan_surface("127.0.0.1")
    print(json.dumps(result.to_dict(), indent=2))
