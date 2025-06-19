/**
 * Frontend-specific exports for browser environments
 */
import { detectForms } from '../modules/formDetection.js';
import { scanSecurityHeaders } from '../modules/securityHeaders.js';
export { detectForms, scanSecurityHeaders };
/**
 * Browser-based DOM form detection that works directly with DOM
 */
export declare const detectFormsInDOM: () => Promise<import("../types.js").ScannerOutput<import("../types.js").FormDetectionResult>>;
