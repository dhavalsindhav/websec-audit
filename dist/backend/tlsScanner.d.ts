import { Scanner, TLSConfigResult } from '../types';
/**
 * Scan the TLS configuration of a domain
 * Note: This can only be used in a Node.js environment
 */
export declare const scanTLS: Scanner<TLSConfigResult>;
