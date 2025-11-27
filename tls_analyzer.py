"""
ACDI TLS/Certificate Analyzer Module
Analyzes SSL/TLS configurations and certificates for quantum vulnerability

IFG Quantum Holdings - Confidential
"""

import ssl
import socket
import subprocess
import json
from dataclasses import dataclass, asdict, field
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime
import re
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
import OpenSSL


@dataclass
class CertificateInfo:
    """Parsed certificate information"""
    subject: str
    issuer: str
    serial_number: str
    not_before: str
    not_after: str
    days_until_expiry: int
    is_expired: bool
    is_self_signed: bool
    signature_algorithm: str
    public_key_algorithm: str
    public_key_size: int
    san_domains: List[str]
    fingerprint_sha256: str
    chain_length: int
    chain_valid: bool
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass 
class CipherSuite:
    """Individual cipher suite information"""
    name: str
    protocol: str
    key_exchange: str
    authentication: str
    encryption: str
    mac: str
    key_size: int
    is_weak: bool
    is_quantum_vulnerable: bool
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TLSAnalysis:
    """Complete TLS analysis result"""
    target: str
    port: int
    analysis_time: str
    status: str
    
    # Protocol support
    supports_sslv2: bool = False
    supports_sslv3: bool = False
    supports_tls10: bool = False
    supports_tls11: bool = False
    supports_tls12: bool = False
    supports_tls13: bool = False
    
    # Certificate info
    certificate: Optional[CertificateInfo] = None
    
    # Cipher suites
    cipher_suites: List[CipherSuite] = field(default_factory=list)
    
    # Vulnerabilities
    vulnerable_to_heartbleed: bool = False
    vulnerable_to_poodle: bool = False
    vulnerable_to_beast: bool = False
    vulnerable_to_crime: bool = False
    vulnerable_to_robot: bool = False
    
    # Quantum assessment
    quantum_vulnerable: bool = True  # Default true until proven otherwise
    quantum_risk_score: int = 100  # 0-100, higher is worse
    quantum_risk_factors: List[str] = field(default_factory=list)
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    
    # Errors
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        if self.certificate:
            result['certificate'] = self.certificate.to_dict()
        result['cipher_suites'] = [c.to_dict() for c in self.cipher_suites]
        return result


class TLSAnalyzer:
    """
    TLS/SSL Certificate and Configuration Analyzer
    Identifies quantum-vulnerable cryptographic implementations
    """
    
    # Quantum-vulnerable key exchange algorithms
    QUANTUM_VULNERABLE_KEX = {
        'RSA', 'DH', 'DHE', 'ECDH', 'ECDHE', 'DSS', 'ECDSA'
    }
    
    # Quantum-resistant algorithms (NIST approved)
    QUANTUM_RESISTANT = {
        'ML-KEM', 'ML-DSA', 'SLH-DSA', 'KYBER', 'DILITHIUM', 'SPHINCS+'
    }
    
    # Weak cipher patterns
    WEAK_CIPHERS = {
        'NULL', 'EXPORT', 'DES', '3DES', 'RC4', 'RC2', 'MD5', 'ANON'
    }
    
    # Minimum acceptable key sizes
    MIN_RSA_KEY_SIZE = 2048
    MIN_EC_KEY_SIZE = 256
    MIN_DH_KEY_SIZE = 2048
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    def _get_certificate_chain(self, host: str, port: int) -> Tuple[List[x509.Certificate], List[str]]:
        """Get certificate chain from server"""
        errors = []
        certificates = []
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Get certificate in DER format
                    der_cert = ssock.getpeercert(binary_form=True)
                    if der_cert:
                        cert = x509.load_der_x509_certificate(der_cert, default_backend())
                        certificates.append(cert)
                        
        except ssl.SSLError as e:
            errors.append(f"SSL Error: {str(e)}")
        except socket.timeout:
            errors.append(f"Connection timeout to {host}:{port}")
        except socket.error as e:
            errors.append(f"Socket error: {str(e)}")
        except Exception as e:
            errors.append(f"Error getting certificate: {str(e)}")
            
        return certificates, errors
    
    def _analyze_certificate(self, cert: x509.Certificate) -> CertificateInfo:
        """Analyze a single certificate"""
        # Get subject and issuer
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        
        # Check if self-signed
        is_self_signed = subject == issuer
        
        # Get validity dates
        not_before = cert.not_valid_before_utc.isoformat()
        not_after = cert.not_valid_after_utc.isoformat()
        
        # Calculate days until expiry
        now = datetime.utcnow()
        expiry = cert.not_valid_after_utc.replace(tzinfo=None)
        days_until_expiry = (expiry - now).days
        is_expired = days_until_expiry < 0
        
        # Get signature algorithm
        sig_algo = cert.signature_algorithm_oid._name
        
        # Get public key info
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            pk_algo = "RSA"
            pk_size = public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            pk_algo = f"ECDSA ({public_key.curve.name})"
            pk_size = public_key.key_size
        elif isinstance(public_key, dsa.DSAPublicKey):
            pk_algo = "DSA"
            pk_size = public_key.key_size
        else:
            pk_algo = "Unknown"
            pk_size = 0
        
        # Get SANs
        san_domains = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            for name in san_ext.value:
                if isinstance(name, x509.DNSName):
                    san_domains.append(name.value)
        except x509.ExtensionNotFound:
            pass
        
        # Get fingerprint
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        
        return CertificateInfo(
            subject=subject,
            issuer=issuer,
            serial_number=str(cert.serial_number),
            not_before=not_before,
            not_after=not_after,
            days_until_expiry=days_until_expiry,
            is_expired=is_expired,
            is_self_signed=is_self_signed,
            signature_algorithm=sig_algo,
            public_key_algorithm=pk_algo,
            public_key_size=pk_size,
            san_domains=san_domains,
            fingerprint_sha256=fingerprint,
            chain_length=1,  # Will be updated if chain is available
            chain_valid=not is_self_signed
        )
    
    def _parse_cipher_suite(self, cipher_name: str, protocol: str) -> CipherSuite:
        """Parse cipher suite name into components"""
        # Default values
        kex = "Unknown"
        auth = "Unknown"
        enc = "Unknown"
        mac = "Unknown"
        key_size = 0
        
        # Parse common cipher formats
        # e.g., TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        parts = cipher_name.replace('-', '_').upper().split('_')
        
        # Key exchange
        for p in parts:
            if p in ['ECDHE', 'DHE', 'RSA', 'DH', 'ECDH', 'PSK']:
                kex = p
                break
        
        # Authentication
        for p in parts:
            if p in ['RSA', 'DSS', 'ECDSA', 'ANON']:
                auth = p
                break
        
        # Encryption
        for p in parts:
            if p in ['AES', '3DES', 'DES', 'RC4', 'CHACHA20', 'CAMELLIA', 'ARIA']:
                enc = p
                # Try to get key size
                idx = parts.index(p)
                if idx + 1 < len(parts) and parts[idx + 1].isdigit():
                    key_size = int(parts[idx + 1])
                break
        
        # MAC
        for p in parts:
            if p in ['SHA', 'SHA256', 'SHA384', 'MD5', 'POLY1305']:
                mac = p
                break
        
        # Determine if weak
        is_weak = any(w in cipher_name.upper() for w in self.WEAK_CIPHERS)
        
        # Determine quantum vulnerability (all current TLS is quantum vulnerable)
        is_quantum_vulnerable = kex in self.QUANTUM_VULNERABLE_KEX
        
        return CipherSuite(
            name=cipher_name,
            protocol=protocol,
            key_exchange=kex,
            authentication=auth,
            encryption=enc,
            mac=mac,
            key_size=key_size,
            is_weak=is_weak,
            is_quantum_vulnerable=is_quantum_vulnerable
        )
    
    def _test_protocol_support(self, host: str, port: int) -> Dict[str, bool]:
        """Test which TLS/SSL protocols are supported"""
        protocols = {
            'sslv2': False,
            'sslv3': False,
            'tls10': False,
            'tls11': False,
            'tls12': False,
            'tls13': False
        }
        
        # Map protocol versions to SSL context options
        protocol_tests = [
            ('tls13', ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, 'TLSv1_3') else None),
            ('tls12', ssl.TLSVersion.TLSv1_2),
            ('tls11', ssl.TLSVersion.TLSv1_1),
            ('tls10', ssl.TLSVersion.TLSv1),
        ]
        
        for proto_name, version in protocol_tests:
            if version is None:
                continue
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = version
                context.maximum_version = version
                
                with socket.create_connection((host, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        protocols[proto_name] = True
            except:
                pass
        
        return protocols
    
    def _get_cipher_suites(self, host: str, port: int) -> List[CipherSuite]:
        """Get supported cipher suites"""
        suites = []
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        name, protocol, bits = cipher
                        suite = self._parse_cipher_suite(name, protocol)
                        suite.key_size = bits
                        suites.append(suite)
                        
        except Exception:
            pass
        
        return suites
    
    def _calculate_quantum_risk(self, analysis: TLSAnalysis) -> Tuple[int, List[str]]:
        """Calculate quantum risk score and identify risk factors"""
        risk_score = 0
        risk_factors = []
        
        # Certificate-based risks
        if analysis.certificate:
            cert = analysis.certificate
            
            # RSA keys (Shor's algorithm threat)
            if 'RSA' in cert.public_key_algorithm:
                risk_score += 40
                risk_factors.append(f"RSA-{cert.public_key_size} vulnerable to Shor's algorithm")
                
            # ECDSA/ECDH (also Shor's algorithm threat)
            if 'ECD' in cert.public_key_algorithm:
                risk_score += 35
                risk_factors.append(f"{cert.public_key_algorithm} vulnerable to quantum attack")
                
            # DSA
            if 'DSA' in cert.public_key_algorithm and 'ECD' not in cert.public_key_algorithm:
                risk_score += 40
                risk_factors.append("DSA vulnerable to Shor's algorithm")
                
            # Small key sizes increase risk
            if cert.public_key_size < self.MIN_RSA_KEY_SIZE:
                risk_score += 20
                risk_factors.append(f"Key size {cert.public_key_size} below minimum {self.MIN_RSA_KEY_SIZE}")
        
        # Cipher suite risks
        for suite in analysis.cipher_suites:
            if suite.is_quantum_vulnerable and suite.key_exchange in ['RSA', 'DH', 'ECDH']:
                if 'Key exchange vulnerable' not in str(risk_factors):
                    risk_score += 20
                    risk_factors.append(f"Key exchange ({suite.key_exchange}) quantum vulnerable")
            
            if suite.is_weak:
                risk_score += 10
                risk_factors.append(f"Weak cipher: {suite.name}")
        
        # Protocol risks
        if analysis.supports_sslv2 or analysis.supports_sslv3:
            risk_score += 15
            risk_factors.append("Legacy SSL protocols supported")
            
        if analysis.supports_tls10 or analysis.supports_tls11:
            risk_score += 5
            risk_factors.append("Deprecated TLS versions supported")
        
        # Cap at 100
        risk_score = min(100, risk_score)
        
        # If no quantum-resistant crypto detected
        if risk_score > 0:
            risk_factors.append("No post-quantum cryptography detected")
        
        return risk_score, risk_factors
    
    def _generate_recommendations(self, analysis: TLSAnalysis) -> List[str]:
        """Generate remediation recommendations"""
        recommendations = []
        
        if analysis.certificate:
            cert = analysis.certificate
            
            if cert.is_expired:
                recommendations.append("CRITICAL: Certificate is expired. Renew immediately.")
            elif cert.days_until_expiry < 30:
                recommendations.append(f"WARNING: Certificate expires in {cert.days_until_expiry} days.")
                
            if cert.is_self_signed:
                recommendations.append("Replace self-signed certificate with CA-issued certificate.")
                
            if cert.public_key_size < self.MIN_RSA_KEY_SIZE:
                recommendations.append(f"Increase RSA key size to at least {self.MIN_RSA_KEY_SIZE} bits.")
        
        if analysis.supports_sslv2 or analysis.supports_sslv3:
            recommendations.append("Disable SSLv2 and SSLv3 protocols immediately.")
            
        if analysis.supports_tls10:
            recommendations.append("Disable TLS 1.0 per PCI DSS requirements.")
            
        if analysis.supports_tls11:
            recommendations.append("Disable TLS 1.1 (deprecated).")
            
        if not analysis.supports_tls13:
            recommendations.append("Enable TLS 1.3 for improved security and performance.")
        
        # Quantum recommendations
        recommendations.append("QUANTUM: Begin planning migration to post-quantum cryptography (NIST FIPS 203/204/205).")
        recommendations.append("QUANTUM: Implement hybrid key exchange (classical + PQC) as interim measure.")
        recommendations.append("QUANTUM: Inventory all cryptographic dependencies for PQC migration roadmap.")
        
        return recommendations
    
    def analyze(self, host: str, port: int = 443) -> TLSAnalysis:
        """
        Perform complete TLS analysis on a target
        """
        analysis = TLSAnalysis(
            target=host,
            port=port,
            analysis_time=datetime.now().isoformat(),
            status='analyzing'
        )
        
        # Get certificate
        certs, cert_errors = self._get_certificate_chain(host, port)
        analysis.errors.extend(cert_errors)
        
        if certs:
            analysis.certificate = self._analyze_certificate(certs[0])
        
        # Test protocols
        try:
            protocols = self._test_protocol_support(host, port)
            analysis.supports_sslv2 = protocols.get('sslv2', False)
            analysis.supports_sslv3 = protocols.get('sslv3', False)
            analysis.supports_tls10 = protocols.get('tls10', False)
            analysis.supports_tls11 = protocols.get('tls11', False)
            analysis.supports_tls12 = protocols.get('tls12', False)
            analysis.supports_tls13 = protocols.get('tls13', False)
        except Exception as e:
            analysis.errors.append(f"Protocol test error: {str(e)}")
        
        # Get cipher suites
        analysis.cipher_suites = self._get_cipher_suites(host, port)
        
        # Calculate quantum risk
        risk_score, risk_factors = self._calculate_quantum_risk(analysis)
        analysis.quantum_risk_score = risk_score
        analysis.quantum_risk_factors = risk_factors
        analysis.quantum_vulnerable = risk_score > 0
        
        # Generate recommendations
        analysis.recommendations = self._generate_recommendations(analysis)
        
        analysis.status = 'completed' if not analysis.errors else 'completed_with_errors'
        
        return analysis


def analyze_tls(host: str, port: int = 443) -> Dict[str, Any]:
    """Convenience function for API use"""
    analyzer = TLSAnalyzer()
    result = analyzer.analyze(host, port)
    return result.to_dict()


if __name__ == "__main__":
    # Test analysis
    analyzer = TLSAnalyzer()
    print("Testing TLS analysis on google.com:443...")
    result = analyzer.analyze("google.com", 443)
    print(json.dumps(result.to_dict(), indent=2, default=str))
