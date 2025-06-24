# WebSec-Audit

- 📧 **Email Security** - Verify SPF, DMARC and DKIM records for email security
- ✉️ **Email Verification** - Validate email format and check for MX records
- 🔒 **Blacklist Status** - Check if a domain is blacklisted by security services
- 📝 **Form Detection** - Identify forms and validate their security postureiversal security scanning and audit tool for websites that works in both browser and Node.js environments.

[![npm version](https://img.shields.io/npm/v/websec-audit.svg)](https://www.npmjs.com/package/websec-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js CI](https://github.com/dhavalsindhav/websec-audit/actions/workflows/node.js.yml/badge.svg)](https://github.com/dhavalsindhav/websec-audit/actions/workflows/node.js.yml)

## Overview

WebSec-Audit is a comprehensive security scanning library designed for both client-side and server-side applications. It provides tools for scanning web applications for common security vulnerabilities, misconfigured headers, and helps identify potential security risks. With its universal design, it can be used in browser-based applications as well as Node.js server environments.

## Features

- 🛡️ **Security Headers Analysis** - Check for proper implementation of crucial security headers
- 🍪 **Cookie Security Analysis** - Verify cookie attributes for security best practices
- 📧 **Email Security** - Verify SPF, DMARC and DKIM records for email security
- � **Email Verification** - Validate email format and check for MX records
- 🔒 **Blacklist Status** - Check if a domain is blacklisted by security services
- �📝 **Form Detection** - Identify forms and validate their security posture
- 🔎 **Sensitive File Detection** - Scan for exposed sensitive files and directories
- 🌐 **Subdomain Enumeration** - Discover subdomains associated with the target
- 🧩 **Technology Detection** - Identify the tech stack, frameworks, and libraries in use
- 📜 **Library Vulnerability Scanning** - Detect vulnerable frontend libraries
- 🧱 **Web Application Firewall Detection** - Identify if WAF protection is in place
- 🔐 **TLS/SSL Configuration Analysis** - Verify proper TLS implementation
- 🔍 **Port Scanning** - Discover open ports on the target (Node.js only)
- 🔖 **DNS Record Analysis** - Examine DNS configuration (Node.js only)
- ⏱️ **Historical Content Analysis** - Check archived content via Wayback Machine API

## Installation

```bash
# npm
npm install websec-audit

# yarn
yarn add websec-audit

# pnpm
pnpm add websec-audit
```

## Basic Usage

### Browser Environment

```javascript
import { scanSecurityHeaders, detectForms, detectTechStack, scanCookieSecurity } from 'websec-audit';

async function auditWebsite(url) {
  // Check security headers
  const headers = await scanSecurityHeaders({ target: url });
  console.log(`Security Header Score: ${headers.data.score}/100`);
  
  // Check cookie security
  const cookies = await scanCookieSecurity({ target: url });
  console.log(`Cookie security: ${cookies.data.overallSecurity}`);
  
  // Detect forms and potential security issues
  const forms = await detectForms({ target: url });
  console.log(`Found ${forms.data.total} forms`);
  
  // Identify technologies in use
  const tech = await detectTechStack({ target: url });
  console.log('Technologies:', tech.data.technologies);
}

auditWebsite('https://example.com');
```

### Node.js Environment (All Features)

```javascript
import * as websecAudit from 'websec-audit';

async function fullSecurityAudit(domain) {
  // Basic URL scanning
  const headers = await websecAudit.scanSecurityHeaders({ target: domain });
  const cookies = await websecAudit.scanCookieSecurity({ target: domain });
  
  // Email security checks
  const emailSecurity = await websecAudit.checkEmailSecurity({ target: domain });
  console.log(`Email security score: ${emailSecurity.data.overall.securityScore}/100`);
  
  // Email validation check
  const email = `info@${domain}`;
  const emailVerification = await websecAudit.verifyEmail({ target: email });
  console.log(`Email valid: ${emailVerification.data.isValid}`);
  
  // Check if domain is blacklisted
  const blacklistStatus = await websecAudit.checkBlacklistStatus({ target: domain });
  console.log(`Blacklisted: ${blacklistStatus.data.overallStatus.blacklisted}`);
  
  // TLS/SSL scanning (simple version works in browsers too)
  const tlsScan = await websecAudit.simplifiedScanTLS({ target: domain });
  console.log(`TLS valid: ${tlsScan.data.isValid}`);
  
  // Enhanced TLS scanning (Node.js only)
  const detailedTlsScan = await websecAudit.scanTLS({ target: domain });
  console.log(`TLS version: ${detailedTlsScan.data.version}`);
  
  // DNS records scanning (Node.js only)
  const dnsRecords = await websecAudit.scanDNSRecords({ target: domain });
  console.log(`SPF record: ${dnsRecords.data.spf.record || 'Not found'}`);
  
  // Port scanning (Node.js only)
  const portScan = await websecAudit.scanPorts({ target: domain });
  console.log(`Open ports: ${portScan.data.openPorts.map(p => p.port).join(', ')}`);
  
  return {
    headerScore: headers.data.score,
    emailSecurity: emailSecurity.data.overall.securityScore,
    dnsRecords: dnsRecords.data.records,
    tlsGrade: detailedTlsScan.data.grade
  };
}

fullSecurityAudit('example.com').then(console.log);
```

## API Documentation

### Universal Modules (Browser + Node.js)

All modules follow a consistent API pattern and return results in a standardized format:

```typescript
interface ScannerOutput<T> {
  status: 'success' | 'failure' | 'partial';
  scanner: string;
  message: string;
  data: T;
  errors?: Error[];
  meta?: Record<string, any>;
}
```

#### Security Headers Scanner

```javascript
import { scanSecurityHeaders } from 'websec-audit';

const result = await scanSecurityHeaders({ 
  target: 'https://example.com',
  timeout: 5000 // optional
});
```

Returns information about security headers implementation and provides a security score.

#### Form Detection

```javascript
import { detectForms } from 'websec-audit';

const result = await detectForms({ target: 'https://example.com' });
```

Identifies forms on a page and evaluates their security configuration (HTTPS, CSRF protections, etc).

#### Technology Detection

```javascript
import { detectTechStack } from 'websec-audit';

const result = await detectTechStack({ target: 'https://example.com' });
```

Identifies technologies, frameworks, and libraries used by the target website.

#### Library Vulnerability Scanner

```javascript
import { scanLibraryVulnerabilities } from 'websec-audit';

const result = await scanLibraryVulnerabilities({ 
  target: 'https://example.com'
});
```

Detects vulnerable frontend libraries and provides information about the vulnerabilities.

### Node.js-Only Modules

These modules are available only in Node.js environments and can be imported from `websec-audit/backend`.

#### TLS/SSL Configuration Scanner

```javascript
import { scanTLS } from 'websec-audit/backend';

const result = await scanTLS({ 
  target: 'example.com',
  options: {
    ports: [443, 8443],
    checkVulnerabilities: true
  }
});
```

Evaluates the TLS/SSL configuration of a target server, providing information about protocol versions, cipher suites, certificate validity, and vulnerabilities detection.

#### DNS Records Scanner

```javascript
import { scanDNSRecords } from 'websec-audit/backend';

const result = await scanDNSRecords({ target: 'example.com' });
```

Analyzes DNS records for a domain, providing information about A, AAAA, MX, TXT, NS, CNAME, and other record types.

#### Port Scanner

```javascript
import { scanPorts } from 'websec-audit/backend';

const result = await scanPorts({ 
  target: 'example.com',
  options: {
    ports: [80, 443, 8080, 8443],
    timeout: 2000
  } 
});
```

Performs port scanning on a target host to identify open ports and services.

## Detailed Examples

### Universal Security Check

```javascript
import { scanSecurityHeaders, detectTechStack, detectFirewall } from 'websec-audit';

async function checkSecurityBasics(url) {
  try {
    // Check security headers
    const headers = await scanSecurityHeaders({ target: url });
    if (headers.status === 'success') {
      console.log(`Security Header Score: ${headers.data.score}/100`);
      
      if (headers.data.score < 70) {
        console.log('⚠️ Your security headers need improvement');
        console.log('Missing headers:', headers.data.missing);
      }
    }
    
    // Detect technologies in use
    const tech = await detectTechStack({ target: url });
    console.log('Technologies detected:', tech.data.technologies);
    
    // Check for Web Application Firewall
    const waf = await detectFirewall({ target: url });
    console.log('WAF detected:', waf.data.detected ? 'Yes' : 'No');
    if (waf.data.detected) {
      console.log('WAF type:', waf.data.type);
    }
  } catch (error) {
    console.error('Error during security check:', error);
  }
}
```

### Node.js Advanced Security Audit

```javascript
import { scanSecurityHeaders } from 'websec-audit';
import { scanPorts, scanDNSRecords, scanTLS } from 'websec-audit/backend';

async function advancedSecurityAudit(domain) {
  const results = {};
  
  // Run scans in parallel for efficiency
  const [headers, ports, dns, tls] = await Promise.all([
    scanSecurityHeaders({ target: `https://${domain}` }),
    scanPorts({ target: domain }),
    scanDNSRecords({ target: domain }),
    scanTLS({ target: domain })
  ]);
  
  // Compile results
  const report = {
    domain,
    timestamp: new Date().toISOString(),
    securityScore: headers.data.score,
    openPorts: ports.data.open,
    tlsGrade: tls.data.grade,
    vulnerabilities: {
      missingHeaders: headers.data.missing || [],
      tlsIssues: tls.data.issues || [],
      exposedPorts: ports.data.open.length > 3 ? 'High' : 'Low'
    },
    recommendations: []
  };
  
  // Generate recommendations
  if (headers.data.score < 70) {
    report.recommendations.push('Implement missing security headers');
  }
  if (tls.data.grade && tls.data.grade.match(/[CD]/)) {
    report.recommendations.push('Update TLS configuration');
  }
  
  return report;
}
```

Check the `/examples` directory for more usage examples:
- `basic-scan.js` - Simple security scan
- `comprehensive-scan.js` - Full-featured security audit
- `node-scan.js` - Node.js specific scanning capabilities
- `tls-ssl-scan.js` - TLS/SSL configuration analysis

## Browser Compatibility

WebSec-Audit is designed to work with modern browsers:

- Chrome/Edge (latest 2 versions)
- Firefox (latest 2 versions)
- Safari (latest 2 versions)

Note that backend-specific modules (`websec-audit/backend`) will not work in browser environments due to platform limitations.

## Troubleshooting

### CORS Issues in Browser

When running browser-based scans, you might encounter CORS-related issues. Consider:

- Using a CORS proxy for development purposes
- Implementing proper CORS headers on your server
- Using the backend modules in a Node.js server that makes requests on behalf of the browser

### Node.js Version Requirements

This package requires Node.js version 14.0.0 or higher due to its use of modern JavaScript features.

## Additional Resources

- [Documentation](https://github.com/dhavalsindhav/websec-audit/tree/main/docs)
- [Changelog](https://github.com/dhavalsindhav/websec-audit/blob/main/CHANGELOG.md)
- [Security Best Practices](https://github.com/dhavalsindhav/websec-audit/blob/main/docs/SECURITY_BEST_PRACTICES.md)

## Contributing

We welcome contributions to WebSec-Audit! Here's how you can help:

1. **Report bugs** by opening an issue
2. **Suggest features** that would make the library more useful
3. **Submit pull requests** with bug fixes or new features

Please make sure to:
- Follow the coding style of the project
- Add tests for new features
- Update documentation for any changes

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Security

If you discover any security issues, please email security@example.com instead of using the issue tracker.
