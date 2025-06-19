/**
 * Main index.ts file for websec-audit
 * Exports all universal scanners and types
 */
export * from './types';
export * from './core/request.js';
export { scanSecurityHeaders } from './modules/securityHeaders.js';
export { detectForms } from './modules/formDetection.js';
export { scanSensitiveFiles } from './modules/sensitiveFiles.js';
export { scanSubdomains } from './modules/subdomains.js';
export { detectTechStack } from './modules/techStack.js';
export { scanLibraryVulnerabilities } from './modules/libraryVulnerabilities.js';
export { scanWaybackMachine } from './modules/waybackMachine.js';
export { detectFirewall } from './modules/firewall.js';
export * from './frontend/index.js';
export * from './backend/index.js';
