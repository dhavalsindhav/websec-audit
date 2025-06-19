/**
 * Backend-specific exports for Node.js environments only
 */

// Export backend-specific scanners
export { scanTLS } from './TLS_SSL_Scanner.js';
export { scanDNSRecords } from './dnsScanner.js';
export { scanPorts } from './portScanner.js';

// Re-export core utilities needed by backend
export { makeRequest } from '../core/request';
