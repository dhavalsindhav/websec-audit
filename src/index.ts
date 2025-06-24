/**
 * Main index.ts file for websec-audit
 * Exports all universal scanners and types
 */

// Export types
export * from './types';

// Core utilities
export * from './core/request.js';

// Export modules that work in both frontend and backend
export { scanSecurityHeaders } from './modules/securityHeaders.js';
export { detectForms } from './modules/formDetection.js';
export { scanSensitiveFiles } from './modules/sensitiveFiles.js';
export { scanSubdomains } from './modules/subdomains.js';
export { detectTechStack } from './modules/techStack.js';
export { scanLibraryVulnerabilities } from './modules/libraryVulnerabilities.js';
export { scanWaybackMachine } from './modules/waybackMachine.js';
export { detectFirewall } from './modules/firewall.js';
export { simplifiedScanTLS } from './modules/tlsScanner.js';
export { checkBlacklistStatus } from './modules/blacklistChecker.js';
export { verifyEmail } from './modules/emailVerifier.js';
export { scanCookieSecurity } from './modules/cookieSecurity.js';

// Re-export browser-only modules
export * from './frontend/index.js';

// Re-export Node.js only modules
export * from './backend/index.js';
