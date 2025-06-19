import * as tls from 'tls';
import * as net from 'net';
import * as dns from 'dns';
import * as crypto from 'crypto';
import { promisify } from 'util';
import { Scanner, ScannerInput, TLSConfigResult } from '../types';
import { extractDomain, createScannerInput } from '../core/request';

// Promisify DNS lookup
const dnsLookup = promisify(dns.lookup);

// Standard cipher suite ratings
const CIPHER_RATINGS: Record<string, 'strong' | 'recommended' | 'adequate' | 'weak' | 'insecure'> = {
  // Strong modern ciphers
  'TLS_AES_256_GCM_SHA384': 'strong',
  'TLS_AES_128_GCM_SHA256': 'strong',
  'TLS_CHACHA20_POLY1305_SHA256': 'strong',
  
  // Recommended ciphers
  'ECDHE-ECDSA-AES256-GCM-SHA384': 'recommended',
  'ECDHE-RSA-AES256-GCM-SHA384': 'recommended',
  'ECDHE-ECDSA-AES128-GCM-SHA256': 'recommended',
  'ECDHE-RSA-AES128-GCM-SHA256': 'recommended',
  'ECDHE-ECDSA-CHACHA20-POLY1305': 'recommended',
  'ECDHE-RSA-CHACHA20-POLY1305': 'recommended',
  
  // Adequate ciphers
  'DHE-RSA-AES256-GCM-SHA384': 'adequate',
  'DHE-RSA-AES128-GCM-SHA256': 'adequate',
  'ECDHE-ECDSA-AES256-SHA384': 'adequate',
  'ECDHE-RSA-AES256-SHA384': 'adequate',
  'ECDHE-ECDSA-AES128-SHA256': 'adequate',
  'ECDHE-RSA-AES128-SHA256': 'adequate',
  
  // Weak ciphers - should be avoided
  'ECDHE-RSA-AES256-SHA': 'weak',
  'ECDHE-ECDSA-AES256-SHA': 'weak',
  'DHE-RSA-AES256-SHA': 'weak',
  'ECDHE-RSA-AES128-SHA': 'weak',
  'ECDHE-ECDSA-AES128-SHA': 'weak',
  'DHE-RSA-AES128-SHA': 'weak',
  'RSA-AES256-GCM-SHA384': 'weak',
  'RSA-AES128-GCM-SHA256': 'weak',
  'RSA-AES256-SHA256': 'weak',
  'RSA-AES128-SHA256': 'weak',
  'RSA-AES256-SHA': 'weak',
  'RSA-AES128-SHA': 'weak',
  
  // Insecure ciphers - should never be used
  'DES-CBC3-SHA': 'insecure',
  'ECDHE-RSA-DES-CBC3-SHA': 'insecure',
  'EDH-RSA-DES-CBC3-SHA': 'insecure',
  'RC4-SHA': 'insecure',
  'RC4-MD5': 'insecure',
  'NULL-SHA': 'insecure',
  'NULL-MD5': 'insecure',
  'EXP-RC4-MD5': 'insecure',
  'EXP-DES-CBC-SHA': 'insecure'
};

// TLS/SSL protocol versions with their security ratings
const PROTOCOL_RATINGS: Record<string, {
  rating: 'secure' | 'recommended' | 'adequate' | 'weak' | 'insecure',
  description: string
}> = {
  'TLSv1.3': {
    rating: 'secure',
    description: 'Modern, secure protocol with perfect forward secrecy and improved handshake encryption'
  },
  'TLSv1.2': {
    rating: 'recommended',
    description: 'Secure protocol when configured properly, widely supported'
  },
  'TLSv1.1': {
    rating: 'weak',
    description: 'Outdated protocol with known vulnerabilities, should be disabled'
  },
  'TLSv1': {
    rating: 'insecure',
    description: 'Outdated protocol with known vulnerabilities, should be disabled'
  },
  'SSLv3': {
    rating: 'insecure',
    description: 'Insecure protocol affected by POODLE vulnerability, must be disabled'
  },
  'SSLv2': {
    rating: 'insecure',
    description: 'Critically insecure legacy protocol, must be disabled'
  }
};

// Known vulnerabilities in SSL/TLS
const KNOWN_VULNERABILITIES = [
  {
    name: 'BEAST',
    affects: ['TLSv1'],
    description: 'Browser Exploit Against SSL/TLS. Affects CBC ciphers in TLS 1.0 and earlier.',
    severity: 'high'
  },
  {
    name: 'POODLE',
    affects: ['SSLv3'],
    description: 'Padding Oracle On Downgraded Legacy Encryption. Affects all SSLv3 connections.',
    severity: 'high'
  },
  {
    name: 'FREAK',
    affects: ['TLSv1', 'TLSv1.1', 'TLSv1.2'],
    description: 'Forcing RSA Export Keys. Server supports export-grade cipher suites.',
    severity: 'high',
    testFor: (cipher: string) => cipher.includes('EXP')
  },
  {
    name: 'LOGJAM',
    affects: ['TLSv1', 'TLSv1.1', 'TLSv1.2'],
    description: 'Weak Diffie-Hellman key exchange. Server may use weak DH parameters.',
    severity: 'high',
    testFor: (cipher: string) => cipher.includes('DHE') && cipher.includes('EXPORT')
  },
  {
    name: 'ROBOT',
    affects: ['TLSv1', 'TLSv1.1', 'TLSv1.2'],
    description: 'Return Of Bleichenbacher\'s Oracle Threat. RSA padding oracle vulnerability.',
    severity: 'high',
    testFor: (cipher: string) => cipher.startsWith('RSA')
  },
  {
    name: 'LUCKY13',
    affects: ['TLSv1', 'TLSv1.1', 'TLSv1.2'],
    description: 'Timing attack against CBC ciphers.',
    severity: 'medium',
    testFor: (cipher: string) => cipher.includes('CBC')
  },
  {
    name: 'HEARTBLEED',
    affects: ['TLSv1', 'TLSv1.1', 'TLSv1.2'],
    description: 'OpenSSL heartbeat information disclosure. Can\'t be detected from connection alone.',
    severity: 'critical'
  },
  {
    name: 'Sweet32',
    affects: ['TLSv1', 'TLSv1.1', 'TLSv1.2'],
    description: 'Birthday attacks on 64-bit block ciphers (3DES/DES)',
    severity: 'medium',
    testFor: (cipher: string) => cipher.includes('3DES') || cipher.includes('DES-CBC')
  }
];

/**
 * Tests if a port is open on a given host
 */
async function isPortOpen(host: string, port: number, timeout: number): Promise<boolean> {
  return new Promise(resolve => {
    const socket = new net.Socket();
    let isOpen = false;
    
    // Set timeout
    socket.setTimeout(timeout);
    
    socket.on('connect', () => {
      isOpen = true;
      socket.end();
    });
    
    socket.on('timeout', () => {
      socket.destroy();
      resolve(false);
    });
    
    socket.on('error', () => {
      resolve(false);
    });
    
    socket.on('close', () => {
      resolve(isOpen);
    });
    
    socket.connect(port, host);
  });
}

/**
 * Test for specific SSL/TLS vulnerabilities by configuration
 */
function testForVulnerabilities(protocol: string, cipher: tls.CipherNameAndProtocol): Array<{
  name: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}> {
  const vulnerabilities: Array<{
    name: string;
    description: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
  }> = [];

  for (const vuln of KNOWN_VULNERABILITIES) {
    if (vuln.affects.includes(protocol)) {
      // If there's a specific test for this vulnerability
      if (!vuln.testFor || vuln.testFor(cipher.name)) {
        vulnerabilities.push({
          name: vuln.name,
          description: vuln.description,
          severity: vuln.severity as 'critical' | 'high' | 'medium' | 'low'
        });
      }
    }
  }

  return vulnerabilities;
}

/**
 * Calculate the key strength from certificate information
 */
function calculateKeyStrength(cert: any): { 
  strength: number; 
  algorithm: string;
  rating: 'strong' | 'adequate' | 'weak' | 'insecure';
} {
  let strength = 0;
  let algorithm = 'unknown';
  let rating: 'strong' | 'adequate' | 'weak' | 'insecure' = 'weak';

  if (cert.pubkey) {
    // Extract key algorithm and size
    if (cert.pubkey.algo === 'rsa') {
      strength = cert.pubkey.bits || 0;
      algorithm = 'RSA';
      
      if (strength >= 4096) {
        rating = 'strong';
      } else if (strength >= 2048) {
        rating = 'adequate';
      } else if (strength >= 1024) {
        rating = 'weak';
      } else {
        rating = 'insecure';
      }
    } else if (cert.pubkey.algo === 'ec') {
      strength = cert.pubkey.bits || 0;
      algorithm = 'ECDSA';
      
      if (strength >= 384) {
        rating = 'strong';
      } else if (strength >= 256) {
        rating = 'adequate';
      } else {
        rating = 'weak';
      }
    }
  }

  return { strength, algorithm, rating };
}

/**
 * Check for specific certificate features
 */
function checkCertificateFeatures(cert: any): Array<{
  feature: string;
  supported: boolean;
  description: string;
}> {
  const features: Array<{
    feature: string;
    supported: boolean;
    description: string;
  }> = [];
  
  // Check for CT (Certificate Transparency)
  const hasSCT = cert.ext && (cert.ext.includes('CT Precertificate SCTs') || cert.ext.includes('signed certificate timestamp'));
  features.push({
    feature: 'Certificate Transparency',
    supported: !!hasSCT,
    description: hasSCT ? 
      'Certificate includes embedded SCTs, complying with Certificate Transparency' : 
      'Certificate does not include Certificate Transparency information'
  });
  
  // Check for OCSP Must-Staple
  const hasOCSPMustStaple = cert.ext && cert.ext.includes('OCSP Must-Staple');
  features.push({
    feature: 'OCSP Must-Staple',
    supported: !!hasOCSPMustStaple,
    description: hasOCSPMustStaple ?
      'Certificate requires the server to provide OCSP stapling' :
      'Certificate does not enforce OCSP stapling'
  });
  
  // Check for key usage restrictions
  const hasKeyUsage = cert.ext && cert.ext.includes('X509v3 Key Usage');
  features.push({
    feature: 'Key Usage Restrictions',
    supported: !!hasKeyUsage,
    description: hasKeyUsage ?
      'Certificate specifies permitted key usages' :
      'Certificate does not restrict key usages'
  });
  
  return features;
}

/**
 * Get elliptic curve name from the TLS connection if available
 */
function getECDHCurve(socket: tls.TLSSocket): string | undefined {
  try {
    // Get cipher information from the TLS socket
    const cipher = socket.getCipher();
    // In newer Node versions, we might have more details but we'll use what's available
    return cipher.name.includes('ECDHE') ? 'ECDHE' : undefined;
  } catch (e) {
    return undefined;
  }
}

/**
 * Perform TLS connection with specific options
 */
async function tryTLSConnection(
  host: string, 
  port: number, 
  timeout: number, 
  options: Partial<tls.ConnectionOptions> = {}
): Promise<{success: boolean, socket?: tls.TLSSocket, error?: Error, details?: any}> {
  return new Promise(resolve => {
    try {
      // Allow customizing cipher list if it's provided in options
      const socketOptions: tls.ConnectionOptions = {
        host,
        port,
        timeout,
        rejectUnauthorized: false,
        secureContext: options.secureContext,
        secureProtocol: options.secureProtocol,
        ALPNProtocols: ['h2', 'http/1.1'], // Test for HTTP/2 support
        requestCert: true,
        ...options
      };
      
      // Create socket with options
      const socket = tls.connect(socketOptions);
      
      // Set timeout
      socket.setTimeout(timeout);
        socket.on('secureConnect', () => {
        const details: any = {};

        // Try to get ALPN protocol (HTTP/2 support)
        try {
          details.alpnProtocol = socket.alpnProtocol;
        } catch (e) {
          // Ignore errors
        }
        
        // Try to get server name indication (SNI)
        try {
          // The requested hostname (not actually the server name from the certificate)
          details.hostname = host;
        } catch (e) {
          // Ignore errors
        }

        // Try to get the negotiated protocol
        try {
          details.negotiatedProtocol = socket.getProtocol();
        } catch (e) {
          // Ignore errors
        }

        resolve({ success: true, socket, details });
      });
      
      socket.on('error', (error) => {
        socket.destroy();
        resolve({ success: false, error });
      });
      
      socket.on('timeout', () => {
        socket.destroy();
        resolve({ success: false, error: new Error('Connection timeout') });
      });
    } catch (error) {
      resolve({ success: false, error: error as Error });
    }
  });
}

/**
 * Try to establish a connection with various cipher suite restrictions to test what the server supports
 */
async function testCipherSupport(host: string, port: number, timeout: number, protocol: string): Promise<string[]> {
  const supportedCiphers: string[] = [];
  
  // Get all available ciphers that Node.js supports
  const allCiphers = crypto.getCiphers()
    .filter(c => 
      // Filter to just TLS/SSL ciphers
      c.includes('-') && 
      !c.startsWith('id-') && 
      !c.includes('NULL')
    );
  
  // Group ciphers into categories for prioritized testing
  const cipherGroups = {
    modern: allCiphers.filter(c => 
      c.includes('ECDHE') && 
      (c.includes('GCM') || c.includes('CHACHA20'))
    ),
    recommended: allCiphers.filter(c =>
      c.includes('DHE') &&
      (c.includes('GCM') || c.includes('CHACHA20'))
    ),
    legacy: allCiphers.filter(c => 
      c.includes('AES') && 
      !c.includes('GCM')
    ),
    weak: allCiphers.filter(c => 
      c.includes('RC4') || 
      c.includes('DES') || 
      c.includes('3DES') ||
      c.includes('MD5')
    )
  };
  
  // Test modern ciphers first, then try others if needed
  const cipherList = [
    ...cipherGroups.modern,
    ...cipherGroups.recommended,
    ...cipherGroups.legacy,
    ...cipherGroups.weak
  ];
  
  // Limit how many ciphers we test to avoid excessive time consumption
  const maxCiphersToTest = 30;
  const selectedCiphers = cipherList.slice(0, maxCiphersToTest);
  
  // Try a subset of representative ciphers
  for (const cipher of selectedCiphers) {
    try {
      const options: tls.ConnectionOptions = {
        minVersion: protocol as any,
        maxVersion: protocol as any,
        ciphers: cipher
      };
      
      const result = await tryTLSConnection(host, port, timeout / 2, options);
      if (result.success && result.socket) {
        supportedCiphers.push(result.socket.getCipher().name);
        result.socket.destroy();
      }
    } catch (e) {
      // Ignore errors for individual cipher tests
    }
  }
  
  return [...new Set(supportedCiphers)]; // Remove duplicates
}

/**
 * Extract certificate information from TLS socket
 */
function extractCertificateInfo(socket: tls.TLSSocket, host: string): {
  protocol: string;
  cipher: tls.CipherNameAndProtocol;
  certInfo: any;
  issues: TLSConfigResult['issues'];
  certificateChain?: any[];
  securityRating: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  features?: Array<{feature: string; supported: boolean; description: string}>;
  vulnerabilities?: Array<{name: string; description: string; severity: string}>;
} {
  const protocol = socket.getProtocol() || '';
  const cipher = socket.getCipher();
  const cert = socket.getPeerCertificate(true); // true gets the whole certificate chain
  
  // Extract certificate chain
  const chain: any[] = [];
  let currentCert = cert;
  
  while (currentCert && !(currentCert.issuerCertificate?.fingerprint === currentCert.fingerprint)) {
    // Add certificate to chain if it's not already there (avoid infinite loops from self-signed certs)
    if (chain.findIndex(c => c.fingerprint === currentCert.fingerprint) === -1) {
      chain.push({
        subject: currentCert.subject,
        issuer: currentCert.issuer,
        validFrom: currentCert.valid_from,
        validTo: currentCert.valid_to,
        fingerprint: currentCert.fingerprint
      });
      
      // Move to the next certificate in the chain
      if (currentCert.issuerCertificate && 
          currentCert.fingerprint !== currentCert.issuerCertificate.fingerprint) {
        currentCert = currentCert.issuerCertificate;
      } else {
        break;
      }
    } else {
      break; // End if we've seen this certificate before (prevent infinite loop)
    }
  }
  
  // Get current date for certificate validation
  const now = new Date();
  const validFrom = new Date(cert.valid_from);
  const validTo = new Date(cert.valid_to);
  const expiresIn = Math.round((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)); // days
  const isExpired = now > validTo;
  const isNotYetValid = now < validFrom;
  
  // Create issues list
  const issues: TLSConfigResult['issues'] = [];
  
  // Certificate validity issues
  if (isExpired) {
    issues.push({
      severity: 'high',
      description: 'SSL certificate has expired.'
    });
  }
  
  if (isNotYetValid) {
    issues.push({
      severity: 'high',
      description: 'SSL certificate is not yet valid.'
    });
  }
  
  if (expiresIn <= 30 && !isExpired) {
    issues.push({
      severity: 'medium',
      description: `SSL certificate expires soon (${expiresIn} days).`
    });
  }
  
  // Certificate hostname validation
  const hostnames = [host];
  if (host.startsWith('www.')) {
    hostnames.push(host.substring(4)); // Add non-www version
  } else {
    hostnames.push(`www.${host}`); // Add www version
  }

  // Check if any of the hostnames are covered by the certificate
  const altNames = cert.subjectaltname?.split(', ').map((name: string) => {
    if (name.startsWith('DNS:')) {
      return name.substring(4);
    }
    return name;
  }) || [];

  const validNames = [
    cert.subject?.CN,
    ...altNames
  ].filter(Boolean);

  const hostnameMatch = hostnames.some(hostname => 
    validNames.some(name => {
      // Check for wildcard match e.g. *.example.com matches sub.example.com
      if (name.startsWith('*.')) {
        const domainPart = name.substring(2);
        return hostname.endsWith(domainPart) && 
               hostname.split('.').length === domainPart.split('.').length + 1;
      }
      return name === hostname;
    })
  );

  if (!hostnameMatch) {
    issues.push({
      severity: 'high',
      description: `Certificate hostname mismatch. Certificate is not valid for: ${host}`
    });
  }
  
  // Protocol version checks
  const protocolRating = PROTOCOL_RATINGS[protocol] || {
    rating: 'unknown',
    description: 'Unknown protocol version'
  };
  
  if (protocolRating.rating === 'insecure' || protocolRating.rating === 'weak') {
    issues.push({
      severity: 'high',
      description: `Server uses ${protocolRating.rating} protocol: ${protocol}. ${protocolRating.description}`
    });
  } else if (protocolRating.rating === 'adequate') {
    issues.push({
      severity: 'medium',
      description: `Server uses ${protocolRating.rating} protocol: ${protocol}. ${protocolRating.description}`
    });
  }
  
  // Cipher suite checks
  const cipherRating = CIPHER_RATINGS[cipher.name] || 'weak';
  if (cipherRating === 'insecure') {
    issues.push({
      severity: 'high',
      description: `Server uses insecure cipher: ${cipher.name}.`
    });
  } else if (cipherRating === 'weak') {
    issues.push({
      severity: 'high',
      description: `Server uses weak cipher: ${cipher.name}.`
    });
  } else if (cipherRating === 'adequate') {
    issues.push({
      severity: 'medium',
      description: `Server uses adequate but not ideal cipher: ${cipher.name}.`
    });
  }
  
  // Key strength checks
  const keyInfo = calculateKeyStrength(cert);
  if (keyInfo.rating === 'insecure') {
    issues.push({
      severity: 'high',
      description: `Certificate uses insecure ${keyInfo.algorithm} key (${keyInfo.strength} bits).`
    });
  } else if (keyInfo.rating === 'weak') {
    issues.push({
      severity: 'medium',
      description: `Certificate uses weak ${keyInfo.algorithm} key (${keyInfo.strength} bits).`
    });
  }

  // Self-signed certificate check
  const isSelfSigned = chain.length === 1 || 
      (cert.issuer.CN === cert.subject.CN && 
       cert.issuer.O === cert.subject.O);
  
  if (isSelfSigned) {
    issues.push({
      severity: 'high',
      description: 'Certificate is self-signed and not from a trusted authority.'
    });
  }
    // Check certificate signature algorithm
  // Node.js types don't include sigalg but it's actually available
  const sigAlgo = (cert as any).sigalg?.toLowerCase() || '';
  if (sigAlgo.includes('sha1') || sigAlgo.includes('md5')) {
    issues.push({
      severity: 'high',
      description: `Certificate uses weak signature algorithm: ${(cert as any).sigalg}`
    });
  }

  // Test for known vulnerabilities
  const vulnerabilities = testForVulnerabilities(protocol, cipher);
  
  // Add vulnerabilities to issues
  for (const vuln of vulnerabilities) {
    issues.push({
      severity: vuln.severity as 'high' | 'medium' | 'low' | 'info',
      description: `${vuln.name}: ${vuln.description}`
    });
  }
  
  // Certificate features
  const features = checkCertificateFeatures(cert);
  
  // Calculate overall security rating
  let securityScore = 100;
  
  // Deduct points based on issues
  for (const issue of issues) {
    if (issue.severity === 'high') {
      securityScore -= 25;
    } else if (issue.severity === 'medium') {
      securityScore -= 10;
    } else if (issue.severity === 'low') {
      securityScore -= 5;
    }
  }
  
  // Add points for good security features
  for (const feature of features) {
    if (feature.supported) {
      securityScore += 5;
    }
  }
  
  // Cap the score between 0 and 100
  securityScore = Math.max(0, Math.min(100, securityScore));
  
  // Convert score to letter grade
  let securityRating: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  if (securityScore >= 95) {
    securityRating = 'A+';
  } else if (securityScore >= 85) {
    securityRating = 'A';
  } else if (securityScore >= 70) {
    securityRating = 'B';
  } else if (securityScore >= 60) {
    securityRating = 'C';
  } else if (securityScore >= 50) {
    securityRating = 'D';
  } else {
    securityRating = 'F';
  }
  
  return {
    protocol,
    cipher,
    certInfo: {
      issuer: cert.issuer.CN || cert.issuer.O || 'Unknown',
      subject: cert.subject.CN || cert.subject.O || 'Unknown',
      validFrom: validFrom.toISOString(),
      validTo: validTo.toISOString(),
      expiresIn: expiresIn,
      subjectAltNames: altNames,
      serialNumber: cert.serialNumber,
      signatureAlgorithm: (cert as any).sigalg,
      keyStrength: keyInfo.strength,
      keyAlgorithm: keyInfo.algorithm
    },
    certificateChain: chain,
    issues,
    securityRating,
    features,
    vulnerabilities
  };
}

/**
 * Scan the TLS configuration of a domain
 * Note: This can only be used in a Node.js environment
 */
export const scanTLS: Scanner<TLSConfigResult> = async (
  input: ScannerInput
) => {
  const startTime = Date.now();
  const normalizedInput = createScannerInput(input);
  const domain = extractDomain(normalizedInput.target);
  const timeout = normalizedInput.timeout || 10000;
  
  const diagnosticInfo: string[] = [];
  
  try {
    // First, perform a DNS lookup to check if domain resolves
    try {
      const dnsResult = await dnsLookup(domain);
      diagnosticInfo.push(`Domain ${domain} resolves to IP: ${dnsResult.address}`);
    } catch (error) {
      diagnosticInfo.push(`DNS lookup error: ${(error as Error).message}`);
      return {
        status: 'failure',
        scanner: 'tlsConfig',
        error: `Failed to resolve domain: ${(error as Error).message}`,
        data: {
          version: '',
          ciphers: [],
          certificate: {
            issuer: '',
            subject: '',
            validFrom: '',
            validTo: '',
            expiresIn: 0
          },
          isValid: false,
          issues: [{
            severity: 'high',
            description: `Failed to resolve domain: ${(error as Error).message}`
          }],
          diagnosticInfo
        },
        timeTaken: Date.now() - startTime
      };
    }
    
    // Define ports to try
    const portsToTry = [443, 8443]; 
    let portOpen = false;
    let openPort = 0;
    
    // Check if ports are open first
    for (const port of portsToTry) {
      diagnosticInfo.push(`Checking if port ${port} is open...`);
      const isOpen = await isPortOpen(domain, port, timeout);
      if (isOpen) {
        diagnosticInfo.push(`Port ${port} is open.`);
        portOpen = true;
        openPort = port;
        break;
      } else {
        diagnosticInfo.push(`Port ${port} is closed or filtered.`);
      }
    }
    
    if (!portOpen) {
      return {
        status: 'failure',
        scanner: 'tlsConfig',
        error: 'No open TLS ports found',
        data: {
          version: '',
          ciphers: [],
          certificate: {
            issuer: '',
            subject: '',
            validFrom: '',
            validTo: '',
            expiresIn: 0
          },
          isValid: false,
          issues: [{
            severity: 'high',
            description: 'No open TLS ports found (tried: 443, 8443)'
          }],
          diagnosticInfo
        },
        timeTaken: Date.now() - startTime
      };
    }
    
    // Now try different TLS protocols on the open port
    const tlsVersions: {version: string, options: tls.ConnectionOptions}[] = [
      { version: 'TLSv1.3', options: { minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' } },
      { version: 'TLSv1.2', options: { minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2' } },
      { version: 'Default', options: {} } // Try with defaults as fallback
    ];
    
    for (const { version, options } of tlsVersions) {
      diagnosticInfo.push(`Attempting TLS connection on port ${openPort} with ${version} protocol...`);
      
      const connectionResult = await tryTLSConnection(domain, openPort, timeout, options);
      
      if (connectionResult.success && connectionResult.socket) {
        diagnosticInfo.push(`Successfully established TLS connection using ${version}.`);
          // Extract certificate and protocol info
        const { 
          protocol, 
          cipher, 
          certInfo, 
          issues,
          securityRating,
          features,
          vulnerabilities,
          certificateChain
        } = extractCertificateInfo(connectionResult.socket, domain);
        
        // Test supported ciphers for this protocol version
        const supportedCiphers = await testCipherSupport(domain, openPort, timeout / 2, protocol);
        
        // Close the connection
        connectionResult.socket.end();
        
        // Categorize ciphers by strength
        const cipherStrengths = supportedCiphers.map(cipherName => {
          const rating = CIPHER_RATINGS[cipherName] || 'unknown';
          return {
            name: cipherName,
            strength: rating
          };
        });
        
        return {
          status: 'success',
          scanner: 'tlsConfig',
          data: {
            version: protocol,
            ciphers: supportedCiphers,
            cipherDetails: cipherStrengths,
            certificate: certInfo,
            certificateChain,
            isValid: !issues.some(issue => issue.severity === 'high'),
            issues,
            securityRating,
            supportedFeatures: features?.filter(f => f.supported).map(f => f.feature) || [],
            missingFeatures: features?.filter(f => !f.supported).map(f => f.feature) || [],
            vulnerabilities: vulnerabilities || [],
            diagnosticInfo
          },
          timeTaken: Date.now() - startTime
        };
      } else {
        const errorMsg = connectionResult.error?.message || 'Unknown error';
        diagnosticInfo.push(`Failed with ${version}: ${errorMsg}`);
      }
    }
    
    // If we reached here, all connection attempts failed
    return {
      status: 'failure',
      scanner: 'tlsConfig',
      error: 'All TLS connection attempts failed',
      data: {
        version: '',
        ciphers: [],
        certificate: {
          issuer: '',
          subject: '',
          validFrom: '',
          validTo: '',
          expiresIn: 0
        },
        isValid: false,
        issues: [{
          severity: 'high',
          description: 'Failed to establish TLS connection after multiple attempts'
        }],
        diagnosticInfo
      },
      timeTaken: Date.now() - startTime
    };
  } catch (error) {
    return {
      status: 'failure',
      scanner: 'tlsConfig',
      error: (error as Error).message || 'Unknown error',
      data: {
        version: '',
        ciphers: [],
        certificate: {
          issuer: '',
          subject: '',
          validFrom: '',
          validTo: '',
          expiresIn: 0
        },
        isValid: false,
        issues: [{
          severity: 'high',
          description: `Error scanning TLS configuration: ${(error as Error).message}`
        }],
        diagnosticInfo
      },
      timeTaken: Date.now() - startTime
    };
  }
};
