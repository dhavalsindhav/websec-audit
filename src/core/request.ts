import { default as axios, AxiosRequestConfig } from 'axios';
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

export const makeRequest = async (
  url: string,
  options?: {
    headers?: Record<string, string>;
    timeout?: number;
    method?: 'GET' | 'POST' | 'HEAD';
    data?: any;
  }
): Promise<MakeRequestResult> => {
  try {
    const config: AxiosRequestConfig = {
      url,
      method: options?.method || 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
        ...options?.headers
      },
      timeout: options?.timeout || 10000, // Default 10s timeout
      data: options?.data,
      validateStatus: () => true // Don't throw on any HTTP status code
    };
    
    const response = await axios(config);
    return {
      status: response.status,
      headers: response.headers as Record<string, string | string[]>,
      data: response.data,
      error: null
    };
  } catch (error: any) {
    // This will only catch network errors, timeouts, etc.
    // HTTP errors like 404, 500 are handled by validateStatus above
    return {
      status: 0,
      headers: {},
      data: null,
      error: error.message || 'Request failed'
    };
  }
};

/**
 * Gets the normalized base URL from an input
 */
export const normalizeUrl = (input: string): string => {
  if (!input) return '';
  
  // Add protocol if missing
  let url = input;
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }
  
  try {
    const parsed = new URL(url);
    return parsed.origin;
  } catch (e) {
    return url;
  }
};

/**
 * Extracts domain from URL
 */
export const extractDomain = (url: string): string => {
  try {
    // Remove protocol and www if present
    const parsed = new URL(normalizeUrl(url));
    let domain = parsed.hostname;
    
    if (domain.startsWith('www.')) {
      domain = domain.substring(4);
    }
    
    return domain;
  } catch (e) {
    return url.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0];
  }
};

/**
 * Helper to safely parse JSON
 */
export const safeJsonParse = (text: string): any => {
  try {
    return JSON.parse(text);
  } catch (e) {
    return null;
  }
};

/**
 * Creates common scanner input from various formats
 */
export const createScannerInput = (target: string | ScannerInput): ScannerInput => {
  if (typeof target === 'string') {
    return {
      target: normalizeUrl(target),
      timeout: 10000
    };
  }
  
  return {
    ...target,
    target: normalizeUrl(target.target)
  };
};
