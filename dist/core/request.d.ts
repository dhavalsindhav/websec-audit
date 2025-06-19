import { ScannerInput } from '../types';
/**
 * Makes HTTP requests with appropriate timeouts and error handling
 */
export interface MakeRequestResult {
    status: number;
    headers: Record<string, string | string[]>;
    data: any;
    error: string | null;
}
export declare const makeRequest: (url: string, options?: {
    headers?: Record<string, string>;
    timeout?: number;
    method?: "GET" | "POST" | "HEAD";
    data?: any;
}) => Promise<MakeRequestResult>;
/**
 * Gets the normalized base URL from an input
 */
export declare const normalizeUrl: (input: string) => string;
/**
 * Extracts domain from URL
 */
export declare const extractDomain: (url: string) => string;
/**
 * Helper to safely parse JSON
 */
export declare const safeJsonParse: (text: string) => any;
/**
 * Creates common scanner input from various formats
 */
export declare const createScannerInput: (target: string | ScannerInput) => ScannerInput;
