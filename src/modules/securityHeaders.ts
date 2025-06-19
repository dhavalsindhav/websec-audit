import { SecurityHeadersResult, Scanner, ScannerInput } from '../types.js';
import { makeRequest, createScannerInput } from '../core/request.js';

// Define required security headers and their descriptions
const SECURITY_HEADERS = {
  'strict-transport-security': {
    description: 'HTTP Strict Transport Security (HSTS) enforces secure (HTTPS) connections',
    severity: 'high',
  },
  'content-security-policy': {
    description: 'Content Security Policy prevents XSS and data injection attacks',
    severity: 'high',
  },
  'x-content-type-options': {
    description: 'X-Content-Type-Options prevents MIME-sniffing',
    severity: 'medium',
  },
  'x-frame-options': {
    description: 'X-Frame-Options protects against clickjacking',
    severity: 'medium',
  },
  'x-xss-protection': {
    description: 'X-XSS-Protection enables the cross-site scripting filter',
    severity: 'medium',
  },
  'referrer-policy': {
    description: 'Referrer Policy controls how much information is sent in the Referer header',
    severity: 'low',
  },
  'permissions-policy': {
    description: 'Permissions Policy controls which browser features can be used',
    severity: 'low',
  },
  'cross-origin-embedder-policy': {
    description: 'Cross-Origin Embedder Policy prevents loading cross-origin resources',
    severity: 'low',
  },
  'cross-origin-opener-policy': {
    description: 'Cross-Origin Opener Policy prevents opening cross-origin windows',
    severity: 'low',
  },
  'cross-origin-resource-policy': {
    description: 'Cross-Origin Resource Policy prevents cross-origin loading',
    severity: 'low',
  }
} as const;

/**
 * Scan security headers of a website
 */
export const scanSecurityHeaders: Scanner<SecurityHeadersResult> = async (
  input: ScannerInput
) => {
  const startTime = Date.now();
  const normalizedInput = createScannerInput(input);
  
  try {
    // Make a HEAD request to get headers with minimal data transfer
    const response = await makeRequest(normalizedInput.target, {
      method: 'HEAD',
      timeout: normalizedInput.timeout,
      headers: normalizedInput.headers
    });
    
    if (response.error || !response.headers) {
      return {
        status: 'failure',
        scanner: 'securityHeaders',
        error: response.error || 'Failed to retrieve headers',
        data: {
          headers: {},
          missing: Object.keys(SECURITY_HEADERS),
          issues: [],
          score: 0
        },
        timeTaken: Date.now() - startTime
      };
    }
    
    // Convert all header names to lowercase for case-insensitive matching
    const headers: Record<string, string> = {};
    const headerNames = Object.keys(response.headers);
    
    headerNames.forEach(name => {
      headers[name.toLowerCase()] = response.headers[name] as string;
    });
    
    // Check which headers are missing
    const missing: string[] = [];
    const issues: {
      severity: 'high' | 'medium' | 'low' | 'info';
      header: string;
      description: string;
    }[] = [];
    
    Object.keys(SECURITY_HEADERS).forEach(header => {
      if (!headers[header]) {
        missing.push(header);
        issues.push({
          severity: SECURITY_HEADERS[header as keyof typeof SECURITY_HEADERS].severity as any,
          header,
          description: `Missing ${header} header. ${SECURITY_HEADERS[header as keyof typeof SECURITY_HEADERS].description}`
        });
      }
    });
    
    // Calculate a simple score (100 - deductions)
    const totalHeaders = Object.keys(SECURITY_HEADERS).length;
    const presentHeaders = totalHeaders - missing.length;
    const score = Math.round((presentHeaders / totalHeaders) * 100);
    
    // Check content of headers for common issues
    if (headers['strict-transport-security'] && 
        !headers['strict-transport-security'].includes('max-age=')) {
      issues.push({
        severity: 'medium',
        header: 'strict-transport-security',
        description: 'HSTS header does not include max-age directive'
      });
    }
    
    if (headers['x-frame-options'] && 
        !['DENY', 'SAMEORIGIN'].includes(headers['x-frame-options'].toUpperCase())) {
      issues.push({
        severity: 'medium',
        header: 'x-frame-options',
        description: 'X-Frame-Options should be set to DENY or SAMEORIGIN'
      });
    }
    
    return {
      status: 'success',
      scanner: 'securityHeaders',
      data: {
        headers,
        missing,
        issues,
        score
      },
      timeTaken: Date.now() - startTime
    };
  } catch (error) {
    return {
      status: 'failure',
      scanner: 'securityHeaders',
      error: (error as Error).message || 'Unknown error',
      data: {
        headers: {},
        missing: Object.keys(SECURITY_HEADERS),
        issues: [],
        score: 0
      },
      timeTaken: Date.now() - startTime
    };
  }
};
