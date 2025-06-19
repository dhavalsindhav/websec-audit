import { DNSRecordResult, Scanner } from '../types';
/**
 * Scan DNS records (SPF, DMARC, DKIM)
 * Note: This can only be used in a Node.js environment
 */
export declare const scanDNSRecords: Scanner<DNSRecordResult>;
