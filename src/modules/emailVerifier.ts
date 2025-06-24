import { Scanner, ScannerInput } from '../types';
import { createScannerInput } from '../core/request';
import * as emailValidator from 'email-validator';
import * as dns from 'dns';
import { promisify } from 'util';

// Convert DNS methods to promise-based
const resolveMx = promisify(dns.resolveMx);
const resolve4 = promisify(dns.resolve4);

// Define the result interface
export interface EmailVerificationResult {
  email: string;
  isValid: boolean;
  formatValid: boolean;
  mxRecords: {
    exchange: string;
    priority: number;
  }[];
  hasMx: boolean;
  hasDomain: boolean;
  issues: {
    severity: 'high' | 'medium' | 'low' | 'info';
    description: string;
  }[];
}

/**
 * Verify if an email address is valid by checking format and DNS records
 */
export const verifyEmail: Scanner<EmailVerificationResult> = async (input: ScannerInput) => {
  const startTime = Date.now();
  const normalizedInput = createScannerInput(input);
  
  // Extract email from input if it's a URL or path
  let email = normalizedInput.target;
  if (email.includes('@')) {
    // Already an email
  } else if (email.includes('/')) {
    // Extract email from path if it's a form submission endpoint
    try {
      const url = new URL(email);
      email = url.searchParams.get('email') || 'example@example.com';
    } catch (e) {
      email = 'example@example.com';
    }
  } else {
    // Use domain as email
    email = `info@${email.replace(/^https?:\/\//, '').split('/')[0]}`;
  }

  try {
    // Basic format validation
    const formatValid = emailValidator.validate(email);
    
    // Extract domain for DNS checks
    const domain = email.split('@')[1];
    let mxRecords: dns.MxRecord[] = [];
    let hasMx = false;
    let hasDomain = false;
    
    const issues: {
      severity: 'high' | 'medium' | 'low' | 'info';
      description: string;
    }[] = [];
    
    // Only check MX and A records if format is valid
    if (formatValid && domain) {
      try {
        mxRecords = await resolveMx(domain);
        hasMx = mxRecords.length > 0;
        
        if (!hasMx) {
          // If no MX records, try A records as fallback
          const aRecords = await resolve4(domain);
          hasDomain = aRecords.length > 0;
        } else {
          hasDomain = true;
        }
      } catch (e) {
        hasMx = false;
        hasDomain = false;
      }
    }
    
    // Overall validity - requires both format and either MX or A record
    const isValid = formatValid && hasDomain;
    
    // Identify issues
    if (!formatValid) {
      issues.push({
        severity: 'high',
        description: `Email address ${email} has invalid format`
      });
    }
    
    if (formatValid && !hasDomain) {
      issues.push({
        severity: 'high',
        description: `Domain ${domain} does not exist or has no valid mail servers`
      });
    }
    
    if (formatValid && !hasMx && hasDomain) {
      issues.push({
        severity: 'medium',
        description: `Domain ${domain} has no MX records but has A records, email might work but is not properly configured`
      });
    }
    
    return {
      status: 'success',
      scanner: 'emailVerifier',
      data: {
        email,
        isValid,
        formatValid,
        mxRecords: mxRecords || [],
        hasMx,
        hasDomain,
        issues
      },
      timeTaken: Date.now() - startTime
    };
  } catch (error) {
    return {
      status: 'failure',
      scanner: 'emailVerifier',
      error: (error as Error).message || 'Unknown error',
      data: {
        email,
        isValid: false,
        formatValid: false,
        mxRecords: [],
        hasMx: false,
        hasDomain: false,
        issues: [{
          severity: 'info',
          description: 'Email verification failed due to an error'
        }]
      },
      timeTaken: Date.now() - startTime
    };
  }
};
