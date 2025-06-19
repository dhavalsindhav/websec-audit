/**
 * Common types for the websec-audit package
 */

export interface ScannerInput {
  /** The target URL or domain to scan */
  target: string;
  /** Optional timeout in milliseconds */
  timeout?: number;
  /** Optional custom headers for HTTP requests */
  headers?: Record<string, string>;
  /** Optional custom options for specific scanners */
  options?: Record<string, any>;
}

export interface ScannerOutput<T = any> {
  /** Scanner result status */
  status: 'success' | 'failure' | 'partial';
  /** Scanner result data */
  data: T;
  /** Error message if status is failure */
  error?: string;
  /** Time taken in milliseconds */
  timeTaken?: number;
  /** Scanner name */
  scanner: string;
}

export type Scanner<T = any> = (input: ScannerInput) => Promise<ScannerOutput<T>>;

/**
 * Security Headers
 */
export interface SecurityHeadersResult {
  headers: {
    [key: string]: string | null;
  };
  missing: string[];
  issues: {
    severity: 'high' | 'medium' | 'low' | 'info';
    header: string;
    description: string;
  }[];
  score: number;
}

/**
 * TLS Configuration Result
 */
export interface TLSConfigResult {
  version: string;
  ciphers: string[];
  /** Optional detailed information about cipher strengths */
  cipherDetails?: Array<{
    name: string;
    strength: 'strong' | 'recommended' | 'adequate' | 'weak' | 'insecure' | 'unknown';
  }>;
  certificate: {
    issuer: string;
    subject: string;
    validFrom: string;
    validTo: string;
    expiresIn: number; // days
    /** Optional additional fields */
    subjectAltNames?: string[];
    serialNumber?: string;
    signatureAlgorithm?: string;
    keyStrength?: number;
    keyAlgorithm?: string;
  };
  /** Optional certificate chain information */
  certificateChain?: Array<{
    subject: any;
    issuer: any;
    validFrom: string;
    validTo: string;
    fingerprint: string;
  }>;
  isValid: boolean;
  issues: {
    severity: 'high' | 'medium' | 'low' | 'info';
    description: string;
  }[];
  /** Optional overall security rating */
  securityRating?: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  /** Optional list of supported security features */
  supportedFeatures?: string[];
  /** Optional list of missing security features */
  missingFeatures?: string[];
  /** Optional list of detected vulnerabilities */
  vulnerabilities?: Array<{
    name: string;
    description: string;
    severity: string;
  }>;
  /** Optional diagnostic information about the connection process */
  diagnosticInfo?: string[];
}

/**
 * Firewall Detection Result
 */
export interface FirewallResult {
  detected: boolean;
  name?: string;
  confidence: number;
  evidence?: string[];
}

/**
 * DNS Record Results
 */
export interface DNSRecordResult {
  spf: {
    exists: boolean;
    valid: boolean;
    record?: string;
    issues?: string[];
  };
  dmarc: {
    exists: boolean;
    valid: boolean;
    record?: string;
    policy?: string;
    issues?: string[];
  };
  dkim: {
    exists: boolean;
    valid: boolean;
    selectors?: string[];
    issues?: string[];
  };
  dnssec: {
    enabled: boolean;
    valid: boolean;
    issues?: string[];
  };
}

/**
 * Library Vulnerability Result
 */
export interface LibraryVulnerabilityResult {
  vulnerableLibs: {
    name: string;
    version: string;
    vulnerabilities: {
      id: string;
      severity: 'high' | 'medium' | 'low';
      info: string;
    }[];
  }[];
  totalVulnerabilities: number;
  detectedLibraries?: {
    name: string;
    version: string;
  }[];
}

/**
 * Sensitive File Exposure Result
 */
export interface SensitiveFileResult {
  exposedFiles: {
    path: string;
    status: number;
    contentType?: string;
    size?: number;
  }[];
  issues: {
    severity: 'high' | 'medium' | 'low';
    path: string;
    description: string;
  }[];
}

/**
 * Subdomain Result
 */
export interface SubdomainResult {
  subdomains: string[];
  total: number;
  live?: {
    domain: string;
    ip?: string;
    status?: number;
  }[];
}

/**
 * Tech Stack Detection Result
 */
export interface TechStackResult {
  technologies: {
    name: string;
    version?: string;
    categories: string[];
    confidence: number;
  }[];
  frameworks: string[];
  languages: string[];
  servers: string[];
}

/**
 * Form Detection Result
 */
export interface FormDetectionResult {
  forms: {
    action?: string;
    method?: string;
    inputs: {
      name?: string;
      type: string;
      id?: string;
      required: boolean;
      autocomplete?: string;
    }[];
    hasPassword: boolean;
    hasCSRF: boolean;
    issues: {
      severity: 'high' | 'medium' | 'low' | 'info';
      description: string;
    }[];
  }[];
  total: number;
}

/**
 * OSINT Result
 */
export interface OSINTResult {
  whois?: {
    registrar?: string;
    creationDate?: string;
    expirationDate?: string;
    nameServers?: string[];
  };
  wayback?: {
    firstSeen?: string;
    lastSeen?: string;
    totalSnapshots: number;
    snapshots?: {
      url: string;
      timestamp: string;
    }[];
  };
}

/**
 * Port Scan Result
 */
export interface PortScanResult {
  openPorts: {
    port: number;
    service?: string;
    banner?: string;
  }[];
  total: number;
}
