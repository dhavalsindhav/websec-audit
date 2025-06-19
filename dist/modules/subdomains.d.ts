import { Scanner, SubdomainResult } from '../types';
/**
 * Scan for subdomains using passive techniques (Certificate Transparency logs)
 */
export declare const scanSubdomains: Scanner<SubdomainResult>;
