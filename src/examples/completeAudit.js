/**
 * Complete Website Security Audit Example
 * 
 * This file demonstrates how to use the websec-audit package to conduct
 * a comprehensive security audit of a website.
 */

import * as websecAudit from '../index.js';

/**
 * Run a complete security audit on a website
 * @param {string} url - The URL to audit
 * @param {Object} options - Optional configuration
 * @returns {Promise<Object>} The audit results
 */
export async function runCompleteAudit(url, options = {}) {
  console.log(`Starting comprehensive security audit of ${url}`);
  const startTime = Date.now();
  const results = {
    url,
    timestamp: new Date().toISOString(),
    scanners: {},
    summary: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      total: 0
    }
  };
  
  // Common scanner options
  const scannerOptions = {
    target: url,
    timeout: options.timeout || 30000,
    headers: options.headers || {
      'User-Agent': 'Mozilla/5.0 (compatible; SecurityAudit/1.0)'
    }
  };
  
  try {
    // Basic TLS/SSL Security Check
    console.log('Scanning TLS/SSL configuration...');
    const tlsResult = await websecAudit.simplifiedScanTLS(scannerOptions);
    results.scanners.tls = tlsResult;
    
    // Security Headers Check
    console.log('Scanning security headers...');
    const headersResult = await websecAudit.scanSecurityHeaders(scannerOptions);
    results.scanners.headers = headersResult;
    
    // Cookie Security Check
    console.log('Analyzing cookies...');
    const cookieResult = await websecAudit.scanCookieSecurity(scannerOptions);
    results.scanners.cookies = cookieResult;
    
    // Form Detection
    console.log('Detecting forms...');
    const formsResult = await websecAudit.detectForms(scannerOptions);
    results.scanners.forms = formsResult;
    
    // Sensitive Files Exposure
    console.log('Checking for sensitive file exposure...');
    const filesResult = await websecAudit.scanSensitiveFiles(scannerOptions);
    results.scanners.sensitiveFiles = filesResult;
    
    // Technology Stack Detection
    console.log('Detecting technology stack...');
    const techResult = await websecAudit.detectTechStack(scannerOptions);
    results.scanners.technologies = techResult;
    
    // Firewall Detection
    console.log('Detecting web application firewall...');
    const firewallResult = await websecAudit.detectFirewall(scannerOptions);
    results.scanners.firewall = firewallResult;
    
    // Library Vulnerability Scan (if it's a frontend scan)
    console.log('Scanning for vulnerable libraries...');
    const libResult = await websecAudit.scanLibraryVulnerabilities(scannerOptions);
    results.scanners.libraries = libResult;
    
    // Blacklist Status Check
    console.log('Checking blacklist status...');
    const blacklistResult = await websecAudit.checkBlacklistStatus(scannerOptions);
    results.scanners.blacklist = blacklistResult;
    
    // If options include email scanning
    if (options.checkEmail) {
      // Extract domain for email checks
      const emailDomain = url.replace(/^https?:\/\//, '').split('/')[0];
      const emailOptions = { ...scannerOptions, target: emailDomain };
      
      console.log('Verifying email security...');
      try {
        // This will only work in Node.js environment
        const emailSecResult = await websecAudit.checkEmailSecurity(emailOptions);
        results.scanners.emailSecurity = emailSecResult;
      } catch (e) {
        console.log('Email security check not available in this environment');
      }
    }
    
    // If Node.js environment specific scanners are available
    try {
      // DNS Records Scan
      console.log('Scanning DNS records...');
      const dnsResult = await websecAudit.scanDNSRecords(scannerOptions);
      results.scanners.dns = dnsResult;
      
      // Full TLS Scan (more comprehensive than simplified version)
      console.log('Performing detailed TLS/SSL scan...');
      const detailedTlsResult = await websecAudit.scanTLS(scannerOptions);
      results.scanners.detailedTls = detailedTlsResult;
      
      // Port Scan
      if (options.scanPorts) {
        console.log('Scanning ports...');
        const portResult = await websecAudit.scanPorts(scannerOptions);
        results.scanners.ports = portResult;
      }
    } catch (e) {
      console.log('Some Node.js-specific scans are not available in this environment');
    }
    
    // Calculate summary metrics
    for (const scannerName in results.scanners) {
      const scanner = results.scanners[scannerName];
      if (scanner.data && scanner.data.issues) {
        for (const issue of scanner.data.issues) {
          results.summary.total++;
          results.summary[issue.severity]++;
        }
      }
    }
    
    results.totalTime = Date.now() - startTime;
    console.log(`Audit completed in ${results.totalTime}ms`);
    return results;
  } catch (error) {
    console.error('Error during audit:', error);
    results.error = error.message;
    return results;
  }
}

/**
 * Usage example:
 * 
 * import { runCompleteAudit } from 'websec-audit/examples/completeAudit.js';
 * 
 * (async () => {
 *   const results = await runCompleteAudit('https://example.com', {
 *     timeout: 60000,
 *     checkEmail: true,
 *     scanPorts: false
 *   });
 *   
 *   console.log(JSON.stringify(results, null, 2));
 * })();
 */
