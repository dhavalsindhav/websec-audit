import * as tls from 'tls';
import * as net from 'net';
import * as dns2 from 'dns';
import * as crypto from 'crypto';
import { promisify } from 'util';
import axios from 'axios';

// src/backend/TLS_SSL_Scanner.ts
var makeRequest = async (url, options) => {
  try {
    const config = {
      url,
      method: options?.method || "GET",
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
        ...options?.headers
      },
      timeout: options?.timeout || 1e4,
      // Default 10s timeout
      data: options?.data,
      validateStatus: () => true
      // Don't throw on any HTTP status code
    };
    const response = await axios(config);
    return {
      status: response.status,
      headers: response.headers,
      data: response.data,
      error: null
    };
  } catch (error) {
    return {
      status: 0,
      headers: {},
      data: null,
      error: error.message || "Request failed"
    };
  }
};
var normalizeUrl = (input) => {
  if (!input)
    return "";
  let url = input;
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "https://" + url;
  }
  try {
    const parsed = new URL(url);
    return parsed.origin;
  } catch (e) {
    return url;
  }
};
var extractDomain = (url) => {
  try {
    const parsed = new URL(normalizeUrl(url));
    let domain = parsed.hostname;
    if (domain.startsWith("www.")) {
      domain = domain.substring(4);
    }
    return domain;
  } catch (e) {
    return url.replace(/^(https?:\/\/)?(www\.)?/, "").split("/")[0];
  }
};
var createScannerInput = (target) => {
  if (typeof target === "string") {
    return {
      target: normalizeUrl(target),
      timeout: 1e4
    };
  }
  return {
    ...target,
    target: normalizeUrl(target.target)
  };
};

// src/backend/TLS_SSL_Scanner.ts
var dnsLookup = promisify(dns2.lookup);
var CIPHER_RATINGS = {
  // Strong modern ciphers
  "TLS_AES_256_GCM_SHA384": "strong",
  "TLS_AES_128_GCM_SHA256": "strong",
  "TLS_CHACHA20_POLY1305_SHA256": "strong",
  // Recommended ciphers
  "ECDHE-ECDSA-AES256-GCM-SHA384": "recommended",
  "ECDHE-RSA-AES256-GCM-SHA384": "recommended",
  "ECDHE-ECDSA-AES128-GCM-SHA256": "recommended",
  "ECDHE-RSA-AES128-GCM-SHA256": "recommended",
  "ECDHE-ECDSA-CHACHA20-POLY1305": "recommended",
  "ECDHE-RSA-CHACHA20-POLY1305": "recommended",
  // Adequate ciphers
  "DHE-RSA-AES256-GCM-SHA384": "adequate",
  "DHE-RSA-AES128-GCM-SHA256": "adequate",
  "ECDHE-ECDSA-AES256-SHA384": "adequate",
  "ECDHE-RSA-AES256-SHA384": "adequate",
  "ECDHE-ECDSA-AES128-SHA256": "adequate",
  "ECDHE-RSA-AES128-SHA256": "adequate",
  // Weak ciphers - should be avoided
  "ECDHE-RSA-AES256-SHA": "weak",
  "ECDHE-ECDSA-AES256-SHA": "weak",
  "DHE-RSA-AES256-SHA": "weak",
  "ECDHE-RSA-AES128-SHA": "weak",
  "ECDHE-ECDSA-AES128-SHA": "weak",
  "DHE-RSA-AES128-SHA": "weak",
  "RSA-AES256-GCM-SHA384": "weak",
  "RSA-AES128-GCM-SHA256": "weak",
  "RSA-AES256-SHA256": "weak",
  "RSA-AES128-SHA256": "weak",
  "RSA-AES256-SHA": "weak",
  "RSA-AES128-SHA": "weak",
  // Insecure ciphers - should never be used
  "DES-CBC3-SHA": "insecure",
  "ECDHE-RSA-DES-CBC3-SHA": "insecure",
  "EDH-RSA-DES-CBC3-SHA": "insecure",
  "RC4-SHA": "insecure",
  "RC4-MD5": "insecure",
  "NULL-SHA": "insecure",
  "NULL-MD5": "insecure",
  "EXP-RC4-MD5": "insecure",
  "EXP-DES-CBC-SHA": "insecure"
};
var PROTOCOL_RATINGS = {
  "TLSv1.3": {
    rating: "secure",
    description: "Modern, secure protocol with perfect forward secrecy and improved handshake encryption"
  },
  "TLSv1.2": {
    rating: "recommended",
    description: "Secure protocol when configured properly, widely supported"
  },
  "TLSv1.1": {
    rating: "weak",
    description: "Outdated protocol with known vulnerabilities, should be disabled"
  },
  "TLSv1": {
    rating: "insecure",
    description: "Outdated protocol with known vulnerabilities, should be disabled"
  },
  "SSLv3": {
    rating: "insecure",
    description: "Insecure protocol affected by POODLE vulnerability, must be disabled"
  },
  "SSLv2": {
    rating: "insecure",
    description: "Critically insecure legacy protocol, must be disabled"
  }
};
var KNOWN_VULNERABILITIES = [
  {
    name: "BEAST",
    affects: ["TLSv1"],
    description: "Browser Exploit Against SSL/TLS. Affects CBC ciphers in TLS 1.0 and earlier.",
    severity: "high"
  },
  {
    name: "POODLE",
    affects: ["SSLv3"],
    description: "Padding Oracle On Downgraded Legacy Encryption. Affects all SSLv3 connections.",
    severity: "high"
  },
  {
    name: "FREAK",
    affects: ["TLSv1", "TLSv1.1", "TLSv1.2"],
    description: "Forcing RSA Export Keys. Server supports export-grade cipher suites.",
    severity: "high",
    testFor: (cipher) => cipher.includes("EXP")
  },
  {
    name: "LOGJAM",
    affects: ["TLSv1", "TLSv1.1", "TLSv1.2"],
    description: "Weak Diffie-Hellman key exchange. Server may use weak DH parameters.",
    severity: "high",
    testFor: (cipher) => cipher.includes("DHE") && cipher.includes("EXPORT")
  },
  {
    name: "ROBOT",
    affects: ["TLSv1", "TLSv1.1", "TLSv1.2"],
    description: "Return Of Bleichenbacher's Oracle Threat. RSA padding oracle vulnerability.",
    severity: "high",
    testFor: (cipher) => cipher.startsWith("RSA")
  },
  {
    name: "LUCKY13",
    affects: ["TLSv1", "TLSv1.1", "TLSv1.2"],
    description: "Timing attack against CBC ciphers.",
    severity: "medium",
    testFor: (cipher) => cipher.includes("CBC")
  },
  {
    name: "HEARTBLEED",
    affects: ["TLSv1", "TLSv1.1", "TLSv1.2"],
    description: "OpenSSL heartbeat information disclosure. Can't be detected from connection alone.",
    severity: "critical"
  },
  {
    name: "Sweet32",
    affects: ["TLSv1", "TLSv1.1", "TLSv1.2"],
    description: "Birthday attacks on 64-bit block ciphers (3DES/DES)",
    severity: "medium",
    testFor: (cipher) => cipher.includes("3DES") || cipher.includes("DES-CBC")
  }
];
async function isPortOpen(host, port, timeout) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let isOpen = false;
    socket.setTimeout(timeout);
    socket.on("connect", () => {
      isOpen = true;
      socket.end();
    });
    socket.on("timeout", () => {
      socket.destroy();
      resolve(false);
    });
    socket.on("error", () => {
      resolve(false);
    });
    socket.on("close", () => {
      resolve(isOpen);
    });
    socket.connect(port, host);
  });
}
function testForVulnerabilities(protocol, cipher) {
  const vulnerabilities = [];
  for (const vuln of KNOWN_VULNERABILITIES) {
    if (vuln.affects.includes(protocol)) {
      if (!vuln.testFor || vuln.testFor(cipher.name)) {
        vulnerabilities.push({
          name: vuln.name,
          description: vuln.description,
          severity: vuln.severity
        });
      }
    }
  }
  return vulnerabilities;
}
function calculateKeyStrength(cert) {
  let strength = 0;
  let algorithm = "unknown";
  let rating = "weak";
  if (cert.pubkey) {
    if (cert.pubkey.algo === "rsa") {
      strength = cert.pubkey.bits || 0;
      algorithm = "RSA";
      if (strength >= 4096) {
        rating = "strong";
      } else if (strength >= 2048) {
        rating = "adequate";
      } else if (strength >= 1024) {
        rating = "weak";
      } else {
        rating = "insecure";
      }
    } else if (cert.pubkey.algo === "ec") {
      strength = cert.pubkey.bits || 0;
      algorithm = "ECDSA";
      if (strength >= 384) {
        rating = "strong";
      } else if (strength >= 256) {
        rating = "adequate";
      } else {
        rating = "weak";
      }
    }
  }
  return { strength, algorithm, rating };
}
function checkCertificateFeatures(cert) {
  const features = [];
  const hasSCT = cert.ext && (cert.ext.includes("CT Precertificate SCTs") || cert.ext.includes("signed certificate timestamp"));
  features.push({
    feature: "Certificate Transparency",
    supported: !!hasSCT,
    description: hasSCT ? "Certificate includes embedded SCTs, complying with Certificate Transparency" : "Certificate does not include Certificate Transparency information"
  });
  const hasOCSPMustStaple = cert.ext && cert.ext.includes("OCSP Must-Staple");
  features.push({
    feature: "OCSP Must-Staple",
    supported: !!hasOCSPMustStaple,
    description: hasOCSPMustStaple ? "Certificate requires the server to provide OCSP stapling" : "Certificate does not enforce OCSP stapling"
  });
  const hasKeyUsage = cert.ext && cert.ext.includes("X509v3 Key Usage");
  features.push({
    feature: "Key Usage Restrictions",
    supported: !!hasKeyUsage,
    description: hasKeyUsage ? "Certificate specifies permitted key usages" : "Certificate does not restrict key usages"
  });
  return features;
}
async function tryTLSConnection(host, port, timeout, options = {}) {
  return new Promise((resolve) => {
    try {
      const socketOptions = {
        host,
        port,
        timeout,
        rejectUnauthorized: false,
        secureContext: options.secureContext,
        secureProtocol: options.secureProtocol,
        ALPNProtocols: ["h2", "http/1.1"],
        // Test for HTTP/2 support
        requestCert: true,
        ...options
      };
      const socket = tls.connect(socketOptions);
      socket.setTimeout(timeout);
      socket.on("secureConnect", () => {
        const details = {};
        try {
          details.alpnProtocol = socket.alpnProtocol;
        } catch (e) {
        }
        try {
          details.hostname = host;
        } catch (e) {
        }
        try {
          details.negotiatedProtocol = socket.getProtocol();
        } catch (e) {
        }
        resolve({ success: true, socket, details });
      });
      socket.on("error", (error) => {
        socket.destroy();
        resolve({ success: false, error });
      });
      socket.on("timeout", () => {
        socket.destroy();
        resolve({ success: false, error: new Error("Connection timeout") });
      });
    } catch (error) {
      resolve({ success: false, error });
    }
  });
}
async function testCipherSupport(host, port, timeout, protocol) {
  const supportedCiphers = [];
  const allCiphers = crypto.getCiphers().filter(
    (c) => (
      // Filter to just TLS/SSL ciphers
      c.includes("-") && !c.startsWith("id-") && !c.includes("NULL")
    )
  );
  const cipherGroups = {
    modern: allCiphers.filter(
      (c) => c.includes("ECDHE") && (c.includes("GCM") || c.includes("CHACHA20"))
    ),
    recommended: allCiphers.filter(
      (c) => c.includes("DHE") && (c.includes("GCM") || c.includes("CHACHA20"))
    ),
    legacy: allCiphers.filter(
      (c) => c.includes("AES") && !c.includes("GCM")
    ),
    weak: allCiphers.filter(
      (c) => c.includes("RC4") || c.includes("DES") || c.includes("3DES") || c.includes("MD5")
    )
  };
  const cipherList = [
    ...cipherGroups.modern,
    ...cipherGroups.recommended,
    ...cipherGroups.legacy,
    ...cipherGroups.weak
  ];
  const maxCiphersToTest = 30;
  const selectedCiphers = cipherList.slice(0, maxCiphersToTest);
  for (const cipher of selectedCiphers) {
    try {
      const options = {
        minVersion: protocol,
        maxVersion: protocol,
        ciphers: cipher
      };
      const result = await tryTLSConnection(host, port, timeout / 2, options);
      if (result.success && result.socket) {
        supportedCiphers.push(result.socket.getCipher().name);
        result.socket.destroy();
      }
    } catch (e) {
    }
  }
  return [...new Set(supportedCiphers)];
}
function extractCertificateInfo(socket, host) {
  const protocol = socket.getProtocol() || "";
  const cipher = socket.getCipher();
  const cert = socket.getPeerCertificate(true);
  const chain = [];
  let currentCert = cert;
  while (currentCert && !(currentCert.issuerCertificate?.fingerprint === currentCert.fingerprint)) {
    if (chain.findIndex((c) => c.fingerprint === currentCert.fingerprint) === -1) {
      chain.push({
        subject: currentCert.subject,
        issuer: currentCert.issuer,
        validFrom: currentCert.valid_from,
        validTo: currentCert.valid_to,
        fingerprint: currentCert.fingerprint
      });
      if (currentCert.issuerCertificate && currentCert.fingerprint !== currentCert.issuerCertificate.fingerprint) {
        currentCert = currentCert.issuerCertificate;
      } else {
        break;
      }
    } else {
      break;
    }
  }
  const now = /* @__PURE__ */ new Date();
  const validFrom = new Date(cert.valid_from);
  const validTo = new Date(cert.valid_to);
  const expiresIn = Math.round((validTo.getTime() - now.getTime()) / (1e3 * 60 * 60 * 24));
  const isExpired = now > validTo;
  const isNotYetValid = now < validFrom;
  const issues = [];
  if (isExpired) {
    issues.push({
      severity: "high",
      description: "SSL certificate has expired."
    });
  }
  if (isNotYetValid) {
    issues.push({
      severity: "high",
      description: "SSL certificate is not yet valid."
    });
  }
  if (expiresIn <= 30 && !isExpired) {
    issues.push({
      severity: "medium",
      description: `SSL certificate expires soon (${expiresIn} days).`
    });
  }
  const hostnames = [host];
  if (host.startsWith("www.")) {
    hostnames.push(host.substring(4));
  } else {
    hostnames.push(`www.${host}`);
  }
  const altNames = cert.subjectaltname?.split(", ").map((name) => {
    if (name.startsWith("DNS:")) {
      return name.substring(4);
    }
    return name;
  }) || [];
  const validNames = [
    cert.subject?.CN,
    ...altNames
  ].filter(Boolean);
  const hostnameMatch = hostnames.some(
    (hostname) => validNames.some((name) => {
      if (name.startsWith("*.")) {
        const domainPart = name.substring(2);
        return hostname.endsWith(domainPart) && hostname.split(".").length === domainPart.split(".").length + 1;
      }
      return name === hostname;
    })
  );
  if (!hostnameMatch) {
    issues.push({
      severity: "high",
      description: `Certificate hostname mismatch. Certificate is not valid for: ${host}`
    });
  }
  const protocolRating = PROTOCOL_RATINGS[protocol] || {
    rating: "unknown",
    description: "Unknown protocol version"
  };
  if (protocolRating.rating === "insecure" || protocolRating.rating === "weak") {
    issues.push({
      severity: "high",
      description: `Server uses ${protocolRating.rating} protocol: ${protocol}. ${protocolRating.description}`
    });
  } else if (protocolRating.rating === "adequate") {
    issues.push({
      severity: "medium",
      description: `Server uses ${protocolRating.rating} protocol: ${protocol}. ${protocolRating.description}`
    });
  }
  const cipherRating = CIPHER_RATINGS[cipher.name] || "weak";
  if (cipherRating === "insecure") {
    issues.push({
      severity: "high",
      description: `Server uses insecure cipher: ${cipher.name}.`
    });
  } else if (cipherRating === "weak") {
    issues.push({
      severity: "high",
      description: `Server uses weak cipher: ${cipher.name}.`
    });
  } else if (cipherRating === "adequate") {
    issues.push({
      severity: "medium",
      description: `Server uses adequate but not ideal cipher: ${cipher.name}.`
    });
  }
  const keyInfo = calculateKeyStrength(cert);
  if (keyInfo.rating === "insecure") {
    issues.push({
      severity: "high",
      description: `Certificate uses insecure ${keyInfo.algorithm} key (${keyInfo.strength} bits).`
    });
  } else if (keyInfo.rating === "weak") {
    issues.push({
      severity: "medium",
      description: `Certificate uses weak ${keyInfo.algorithm} key (${keyInfo.strength} bits).`
    });
  }
  const isSelfSigned = chain.length === 1 || cert.issuer.CN === cert.subject.CN && cert.issuer.O === cert.subject.O;
  if (isSelfSigned) {
    issues.push({
      severity: "high",
      description: "Certificate is self-signed and not from a trusted authority."
    });
  }
  const sigAlgo = cert.sigalg?.toLowerCase() || "";
  if (sigAlgo.includes("sha1") || sigAlgo.includes("md5")) {
    issues.push({
      severity: "high",
      description: `Certificate uses weak signature algorithm: ${cert.sigalg}`
    });
  }
  const vulnerabilities = testForVulnerabilities(protocol, cipher);
  for (const vuln of vulnerabilities) {
    issues.push({
      severity: vuln.severity,
      description: `${vuln.name}: ${vuln.description}`
    });
  }
  const features = checkCertificateFeatures(cert);
  let securityScore = 100;
  for (const issue of issues) {
    if (issue.severity === "high") {
      securityScore -= 25;
    } else if (issue.severity === "medium") {
      securityScore -= 10;
    } else if (issue.severity === "low") {
      securityScore -= 5;
    }
  }
  for (const feature of features) {
    if (feature.supported) {
      securityScore += 5;
    }
  }
  securityScore = Math.max(0, Math.min(100, securityScore));
  let securityRating;
  if (securityScore >= 95) {
    securityRating = "A+";
  } else if (securityScore >= 85) {
    securityRating = "A";
  } else if (securityScore >= 70) {
    securityRating = "B";
  } else if (securityScore >= 60) {
    securityRating = "C";
  } else if (securityScore >= 50) {
    securityRating = "D";
  } else {
    securityRating = "F";
  }
  return {
    protocol,
    cipher,
    certInfo: {
      issuer: cert.issuer.CN || cert.issuer.O || "Unknown",
      subject: cert.subject.CN || cert.subject.O || "Unknown",
      validFrom: validFrom.toISOString(),
      validTo: validTo.toISOString(),
      expiresIn,
      subjectAltNames: altNames,
      serialNumber: cert.serialNumber,
      signatureAlgorithm: cert.sigalg,
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
var scanTLS = async (input) => {
  const startTime = Date.now();
  const normalizedInput = createScannerInput(input);
  const domain = extractDomain(normalizedInput.target);
  const timeout = normalizedInput.timeout || 1e4;
  const diagnosticInfo = [];
  try {
    try {
      const dnsResult = await dnsLookup(domain);
      diagnosticInfo.push(`Domain ${domain} resolves to IP: ${dnsResult.address}`);
    } catch (error) {
      diagnosticInfo.push(`DNS lookup error: ${error.message}`);
      return {
        status: "failure",
        scanner: "tlsConfig",
        error: `Failed to resolve domain: ${error.message}`,
        data: {
          version: "",
          ciphers: [],
          certificate: {
            issuer: "",
            subject: "",
            validFrom: "",
            validTo: "",
            expiresIn: 0
          },
          isValid: false,
          issues: [{
            severity: "high",
            description: `Failed to resolve domain: ${error.message}`
          }],
          diagnosticInfo
        },
        timeTaken: Date.now() - startTime
      };
    }
    const portsToTry = [443, 8443];
    let portOpen = false;
    let openPort = 0;
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
        status: "failure",
        scanner: "tlsConfig",
        error: "No open TLS ports found",
        data: {
          version: "",
          ciphers: [],
          certificate: {
            issuer: "",
            subject: "",
            validFrom: "",
            validTo: "",
            expiresIn: 0
          },
          isValid: false,
          issues: [{
            severity: "high",
            description: "No open TLS ports found (tried: 443, 8443)"
          }],
          diagnosticInfo
        },
        timeTaken: Date.now() - startTime
      };
    }
    const tlsVersions = [
      { version: "TLSv1.3", options: { minVersion: "TLSv1.3", maxVersion: "TLSv1.3" } },
      { version: "TLSv1.2", options: { minVersion: "TLSv1.2", maxVersion: "TLSv1.2" } },
      { version: "Default", options: {} }
      // Try with defaults as fallback
    ];
    for (const { version, options } of tlsVersions) {
      diagnosticInfo.push(`Attempting TLS connection on port ${openPort} with ${version} protocol...`);
      const connectionResult = await tryTLSConnection(domain, openPort, timeout, options);
      if (connectionResult.success && connectionResult.socket) {
        diagnosticInfo.push(`Successfully established TLS connection using ${version}.`);
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
        const supportedCiphers = await testCipherSupport(domain, openPort, timeout / 2, protocol);
        connectionResult.socket.end();
        const cipherStrengths = supportedCiphers.map((cipherName) => {
          const rating = CIPHER_RATINGS[cipherName] || "unknown";
          return {
            name: cipherName,
            strength: rating
          };
        });
        return {
          status: "success",
          scanner: "tlsConfig",
          data: {
            version: protocol,
            ciphers: supportedCiphers,
            cipherDetails: cipherStrengths,
            certificate: certInfo,
            certificateChain,
            isValid: !issues.some((issue) => issue.severity === "high"),
            issues,
            securityRating,
            supportedFeatures: features?.filter((f) => f.supported).map((f) => f.feature) || [],
            missingFeatures: features?.filter((f) => !f.supported).map((f) => f.feature) || [],
            vulnerabilities: vulnerabilities || [],
            diagnosticInfo
          },
          timeTaken: Date.now() - startTime
        };
      } else {
        const errorMsg = connectionResult.error?.message || "Unknown error";
        diagnosticInfo.push(`Failed with ${version}: ${errorMsg}`);
      }
    }
    return {
      status: "failure",
      scanner: "tlsConfig",
      error: "All TLS connection attempts failed",
      data: {
        version: "",
        ciphers: [],
        certificate: {
          issuer: "",
          subject: "",
          validFrom: "",
          validTo: "",
          expiresIn: 0
        },
        isValid: false,
        issues: [{
          severity: "high",
          description: "Failed to establish TLS connection after multiple attempts"
        }],
        diagnosticInfo
      },
      timeTaken: Date.now() - startTime
    };
  } catch (error) {
    return {
      status: "failure",
      scanner: "tlsConfig",
      error: error.message || "Unknown error",
      data: {
        version: "",
        ciphers: [],
        certificate: {
          issuer: "",
          subject: "",
          validFrom: "",
          validTo: "",
          expiresIn: 0
        },
        isValid: false,
        issues: [{
          severity: "high",
          description: `Error scanning TLS configuration: ${error.message}`
        }],
        diagnosticInfo
      },
      timeTaken: Date.now() - startTime
    };
  }
};
var resolveTxt2 = promisify(dns2.resolveTxt);
promisify(dns2.resolveMx);
var resolveNs2 = promisify(dns2.resolveNs);
var scanDNSRecords = async (input) => {
  const startTime = Date.now();
  const normalizedInput = createScannerInput(input);
  const domain = extractDomain(normalizedInput.target);
  const result = {
    spf: {
      exists: false,
      valid: false
    },
    dmarc: {
      exists: false,
      valid: false
    },
    dkim: {
      exists: false,
      valid: false
    },
    dnssec: {
      enabled: false,
      valid: false
    }
  };
  try {
    try {
      const txtRecords = await resolveTxt2(domain);
      const spfRecord = txtRecords.find((record) => {
        const recordStr = record.join("");
        return recordStr.startsWith("v=spf1");
      });
      if (spfRecord) {
        const recordStr = spfRecord.join("");
        result.spf = {
          exists: true,
          valid: true,
          record: recordStr,
          issues: []
        };
        if (!recordStr.includes("~all") && !recordStr.includes("-all")) {
          result.spf.issues = ["SPF record does not end with ~all or -all"];
          result.spf.valid = false;
        }
      }
    } catch (error) {
      result.spf.exists = false;
      result.spf.issues = ["Failed to retrieve SPF record"];
    }
    try {
      const dmarcRecords = await resolveTxt2("_dmarc." + domain);
      const dmarcRecord = dmarcRecords.find((record) => {
        const recordStr = record.join("");
        return recordStr.startsWith("v=DMARC1");
      });
      if (dmarcRecord) {
        const recordStr = dmarcRecord.join("");
        result.dmarc = {
          exists: true,
          valid: true,
          record: recordStr,
          issues: []
        };
        const policyMatch = recordStr.match(/p=([^;]+)/);
        if (policyMatch) {
          result.dmarc.policy = policyMatch[1];
        }
        if (!recordStr.includes("p=")) {
          result.dmarc.issues = ["DMARC record does not include a policy (p=)"];
          result.dmarc.valid = false;
        } else if (result.dmarc.policy === "none") {
          result.dmarc.issues = ['DMARC policy is set to "none" which only monitors but takes no action'];
        }
      }
    } catch (error) {
      result.dmarc.exists = false;
      result.dmarc.issues = ["Failed to retrieve DMARC record"];
    }
    const commonSelectors = ["default", "google", "selector1", "selector2", "k1"];
    const dkimResults = [];
    for (const selector of commonSelectors) {
      try {
        const dkimRecords = await resolveTxt2(`${selector}._domainkey.${domain}`);
        if (dkimRecords && dkimRecords.length > 0) {
          dkimResults.push(selector);
        }
      } catch (error) {
      }
    }
    if (dkimResults.length > 0) {
      result.dkim = {
        exists: true,
        valid: true,
        selectors: dkimResults
      };
    } else {
      result.dkim.issues = ["No DKIM records found for common selectors"];
    }
    try {
      const nsRecords = await resolveNs2(domain);
      if (nsRecords && nsRecords.length > 0) {
        result.dnssec = {
          enabled: true,
          valid: true,
          issues: ["Basic DNSSEC detection only. Full validation requires specialized tools."]
        };
      }
    } catch (error) {
      result.dnssec.issues = ["Failed to check nameservers for DNSSEC"];
    }
    return {
      status: "success",
      scanner: "dnsRecords",
      data: result,
      timeTaken: Date.now() - startTime
    };
  } catch (error) {
    return {
      status: "failure",
      scanner: "dnsRecords",
      error: error.message || "Unknown error",
      data: result,
      timeTaken: Date.now() - startTime
    };
  }
};
var DEFAULT_PORTS = [
  21,
  // FTP
  22,
  // SSH
  23,
  // Telnet
  25,
  // SMTP
  53,
  // DNS
  80,
  // HTTP
  110,
  // POP3
  143,
  // IMAP
  443,
  // HTTPS
  465,
  // SMTPS
  587,
  // SMTP Submission
  993,
  // IMAPS
  995,
  // POP3S
  3306,
  // MySQL
  5432,
  // PostgreSQL
  8080,
  // HTTP Alternate
  8443
  // HTTPS Alternate
];
var SERVICE_NAMES = {
  21: "FTP",
  22: "SSH",
  23: "Telnet",
  25: "SMTP",
  53: "DNS",
  80: "HTTP",
  110: "POP3",
  143: "IMAP",
  443: "HTTPS",
  465: "SMTPS",
  587: "SMTP Submission",
  993: "IMAPS",
  995: "POP3S",
  3306: "MySQL",
  5432: "PostgreSQL",
  8080: "HTTP Alternate",
  8443: "HTTPS Alternate"
};
var scanPorts = async (input) => {
  const startTime = Date.now();
  const normalizedInput = createScannerInput(input);
  const domain = extractDomain(normalizedInput.target);
  const timeout = normalizedInput.timeout || 3e3;
  const portsToScan = normalizedInput.options?.ports || DEFAULT_PORTS;
  const result = {
    openPorts: [],
    total: 0
  };
  try {
    const portPromises = portsToScan.map((port) => {
      return new Promise((resolve) => {
        const socket = new net.Socket();
        let resolved = false;
        socket.setTimeout(timeout);
        socket.on("connect", () => {
          if (resolved)
            return;
          resolved = true;
          let banner = "";
          const bannerTimeout = setTimeout(() => {
            socket.destroy();
            result.openPorts.push({
              port,
              service: SERVICE_NAMES[port] || void 0,
              banner: banner || void 0
            });
            resolve();
          }, 1e3);
          socket.once("data", (data) => {
            banner = data.toString().trim();
            clearTimeout(bannerTimeout);
            socket.destroy();
            result.openPorts.push({
              port,
              service: SERVICE_NAMES[port] || void 0,
              banner: banner || void 0
            });
            resolve();
          });
          if (port === 80) {
            socket.write("HEAD / HTTP/1.1\r\nHost: " + domain + "\r\n\r\n");
          } else if (port === 443) {
            socket.destroy();
            result.openPorts.push({
              port,
              service: "HTTPS"
            });
            resolve();
          } else if (port === 25 || port === 587) {
          } else if (port === 22) {
          } else {
            socket.destroy();
            result.openPorts.push({
              port,
              service: SERVICE_NAMES[port] || void 0
            });
            resolve();
          }
        });
        socket.on("error", () => {
          if (resolved)
            return;
          resolved = true;
          socket.destroy();
          resolve();
        });
        socket.on("timeout", () => {
          if (resolved)
            return;
          resolved = true;
          socket.destroy();
          resolve();
        });
        socket.connect(port, domain);
      });
    });
    await Promise.all(portPromises);
    result.total = result.openPorts.length;
    return {
      status: "success",
      scanner: "portScan",
      data: result,
      timeTaken: Date.now() - startTime
    };
  } catch (error) {
    return {
      status: "failure",
      scanner: "portScan",
      error: error.message || "Unknown error",
      data: result,
      timeTaken: Date.now() - startTime
    };
  }
};

export { makeRequest, scanDNSRecords, scanPorts, scanTLS };
//# sourceMappingURL=out.js.map
//# sourceMappingURL=index.mjs.map