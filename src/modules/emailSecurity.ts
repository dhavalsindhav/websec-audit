import { Scanner, ScannerInput } from '../types';
import { createScannerInput, extractDomain } from '../core/request';
import * as dns from 'dns';
import { promisify } from 'util';

// Promisify DNS methods
const resolveTxt = promisify(dns.resolveTxt);

// Define the result interface
export interface EmailSecurityResult {
  domain: string;
  spf: {
    exists: boolean;
    valid: boolean;
    record?: string;
    issues?: string[];
  };
  dmarc: {
    exists: boolean;
    valid: boolean;
    record?: string;
    policy?: string;
    issues?: string[];
  };
  mta_sts: {
    exists: boolean;
    valid: boolean;
    record?: string;
    issues?: string[];
  };
  bimi: {
    exists: boolean;
    valid: boolean;
    record?: string;
    issues?: string[];
  };
  overall: {
    securityScore: number;
    recommendations: string[];
  };
}

/**
 * Check email security configuration for a domain
 */
export const checkEmailSecurity: Scanner<EmailSecurityResult> = async (input: ScannerInput) => {
  const startTime = Date.now();
  const normalizedInput = createScannerInput(input);
  const domain = extractDomain(normalizedInput.target);
  
  // Initialize result
  const result: EmailSecurityResult = {
    domain,
    spf: {
      exists: false,
      valid: false
    },
    dmarc: {
      exists: false,
      valid: false
    },
    mta_sts: {
      exists: false,
      valid: false
    },
    bimi: {
      exists: false,
      valid: false
    },
    overall: {
      securityScore: 0,
      recommendations: []
    }
  };
  
  try {
    // Check SPF record
    try {
      const txtRecords = await resolveTxt(domain);
      const spfRecord = txtRecords.find((record: string[]) => {
        const recordStr = record.join('');
        return recordStr.startsWith('v=spf1');
      });
      
      if (spfRecord) {
        const recordStr = spfRecord.join('');
        result.spf = {
          exists: true,
          valid: true,
          record: recordStr,
          issues: []
        };
        
        // SPF validation
        if (!recordStr.includes('~all') && !recordStr.includes('-all')) {
          result.spf.issues?.push('SPF record does not end with ~all or -all');
          result.spf.valid = false;
        }
      } else {
        result.overall.recommendations.push('Implement an SPF record to prevent email spoofing');
      }
    } catch (error) {
      result.spf.exists = false;
      result.spf.issues = ['Failed to retrieve SPF record'];
      result.overall.recommendations.push('Implement an SPF record to prevent email spoofing');
    }
    
    // Check DMARC record
    try {
      const dmarcRecords = await resolveTxt('_dmarc.' + domain);
      const dmarcRecord = dmarcRecords.find((record: string[]) => {
        const recordStr = record.join('');
        return recordStr.startsWith('v=DMARC1');
      });
      
      if (dmarcRecord) {
        const recordStr = dmarcRecord.join('');
        result.dmarc = {
          exists: true,
          valid: true,
          record: recordStr,
          issues: []
        };
        
        // Extract policy
        const policyMatch = recordStr.match(/p=([^;]+)/);
        if (policyMatch) {
          result.dmarc.policy = policyMatch[1];
          
          // Check policy strength
          if (result.dmarc.policy === 'none') {
            result.dmarc.issues?.push('DMARC policy is set to "none" which only monitors but takes no action');
            result.overall.recommendations.push('Consider strengthening DMARC policy from "none" to "quarantine" or "reject"');
          } else if (result.dmarc.policy === 'quarantine') {
            result.overall.recommendations.push('Consider strengthening DMARC policy from "quarantine" to "reject" for maximum protection');
          }
        } else {
          result.dmarc.valid = false;
          result.dmarc.issues?.push('DMARC record does not include a policy (p=)');
        }
      } else {
        result.overall.recommendations.push('Implement a DMARC record to enhance email authentication');
      }
    } catch (error) {
      result.dmarc.exists = false;
      result.dmarc.issues = ['Failed to retrieve DMARC record'];
      result.overall.recommendations.push('Implement a DMARC record to enhance email authentication');
    }
    
    // Check MTA-STS (Mail Transfer Agent Strict Transport Security)
    try {
      const mtaStsRecords = await resolveTxt('_mta-sts.' + domain);
      const mtaStsRecord = mtaStsRecords.find((record: string[]) => {
        const recordStr = record.join('');
        return recordStr.startsWith('v=STSv1');
      });
      
      if (mtaStsRecord) {
        const recordStr = mtaStsRecord.join('');
        result.mta_sts = {
          exists: true,
          valid: true,
          record: recordStr,
          issues: []
        };
      } else {
        result.overall.recommendations.push('Implement MTA-STS for secure email transit and protection against downgrade attacks');
      }
    } catch (error) {
      result.mta_sts.exists = false;
      result.mta_sts.issues = ['Failed to retrieve MTA-STS record'];
    }
    
    // Check BIMI (Brand Indicators for Message Identification)
    try {
      const bimiRecords = await resolveTxt('default._bimi.' + domain);
      const bimiRecord = bimiRecords.find((record: string[]) => {
        const recordStr = record.join('');
        return recordStr.startsWith('v=BIMI1');
      });
      
      if (bimiRecord) {
        const recordStr = bimiRecord.join('');
        result.bimi = {
          exists: true,
          valid: true,
          record: recordStr,
          issues: []
        };
      }
    } catch (error) {
      result.bimi.exists = false;
      result.bimi.issues = ['Failed to retrieve BIMI record'];
    }
    
    // Calculate overall security score
    let score = 0;
    
    // SPF contributes 25% to score
    if (result.spf.exists) score += 15;
    if (result.spf.valid) score += 10;
    
    // DMARC contributes 40% to score
    if (result.dmarc.exists) score += 20;
    if (result.dmarc.valid) score += 10;
    if (result.dmarc.policy === 'reject') score += 10;
    else if (result.dmarc.policy === 'quarantine') score += 5;
    
    // MTA-STS contributes 25% to score
    if (result.mta_sts.exists) score += 15;
    if (result.mta_sts.valid) score += 10;
    
    // BIMI contributes 10% to score
    if (result.bimi.exists) score += 10;
    
    result.overall.securityScore = score;
    
    return {
      status: 'success',
      scanner: 'emailSecurity',
      data: result,
      timeTaken: Date.now() - startTime
    };
  } catch (error) {
    return {
      status: 'failure',
      scanner: 'emailSecurity',
      error: (error as Error).message || 'Unknown error',
      data: result,
      timeTaken: Date.now() - startTime
    };
  }
};
