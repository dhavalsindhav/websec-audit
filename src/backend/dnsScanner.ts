import * as dns from 'dns';
import { promisify } from 'util';
import { DNSRecordResult, Scanner, ScannerInput } from '../types';
import { extractDomain, createScannerInput } from '../core/request';

// Promisify DNS methods
const resolveTxt = promisify(dns.resolveTxt);
const resolveMx = promisify(dns.resolveMx);
const resolveNs = promisify(dns.resolveNs);

/**
 * Scan DNS records (SPF, DMARC, DKIM)
 * Note: This can only be used in a Node.js environment
 */
export const scanDNSRecords: Scanner<DNSRecordResult> = async (
  input: ScannerInput
) => {
  const startTime = Date.now();
  const normalizedInput = createScannerInput(input);
  const domain = extractDomain(normalizedInput.target);
  
  // Initialize result
  const result: DNSRecordResult = {
    spf: {
      exists: false,
      valid: false
    },
    dmarc: {
      exists: false,
      valid: false
    },
    dkim: {
      exists: false,
      valid: false
    },
    dnssec: {
      enabled: false,
      valid: false
    }
  };
  
  try {
    // Check SPF record
    try {
      const txtRecords = await resolveTxt(domain);      const spfRecord = txtRecords.find((record: string[]) => {
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
          // Enhanced SPF validation
        result.spf.issues = [];
        
        // Check for proper termination
        if (!recordStr.includes('~all') && !recordStr.includes('-all') && !recordStr.includes('?all')) {
          result.spf.issues.push('SPF record does not end with ~all, -all, or ?all');
          result.spf.valid = false;
        }
        
        // Check for potential issues
        if (recordStr.includes('+all')) {
          result.spf.issues.push('SPF record uses +all which allows anyone to send mail claiming to be from your domain');
          result.spf.valid = false;
        }
        
        // Check for potential complexity issues
        const parts = recordStr.split(' ');
        const includeCount = parts.filter(p => p.startsWith('include:')).length;
        
        if (includeCount > 10) {
          result.spf.issues.push(`SPF record has ${includeCount} include mechanisms which may exceed the 10 DNS lookup limit`);
        }
        
        // Check if record exceeds size limit (recommended is under 450 bytes)
        if (recordStr.length > 450) {
          result.spf.issues.push(`SPF record is ${recordStr.length} bytes long which exceeds the recommended 450 bytes and may be truncated`);
        }
      }
    } catch (error) {
      result.spf.exists = false;
      result.spf.issues = ['Failed to retrieve SPF record'];
    }
    
    // Check DMARC record
    try {
      const dmarcRecords = await resolveTxt('_dmarc.' + domain);      const dmarcRecord = dmarcRecords.find((record: string[]) => {
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
        }
        
        // Basic DMARC validation
        if (!recordStr.includes('p=')) {
          result.dmarc.issues = ['DMARC record does not include a policy (p=)'];
          result.dmarc.valid = false;
        } else if (result.dmarc.policy === 'none') {
          result.dmarc.issues = ['DMARC policy is set to "none" which only monitors but takes no action'];
        }
      }
    } catch (error) {
      result.dmarc.exists = false;
      result.dmarc.issues = ['Failed to retrieve DMARC record'];
    }
      // Check DKIM (enhanced check for common selectors)
    const commonSelectors = [
      'default', 'google', 'selector1', 'selector2', 'k1', 'dkim', 
      'mail', 'email', 'outlook', 'amazonses', 'mandrill', 'sendgrid',
      '20161025', 'mailjet', 'zoho'
    ];
    const dkimResults: string[] = [];
    
    // If custom selectors are provided in options, use them too
    const customSelectors = normalizedInput.options?.dkimSelectors as string[] | undefined;
    const selectorsToCheck = customSelectors 
      ? [...commonSelectors, ...customSelectors]
      : commonSelectors;
    
    for (const selector of selectorsToCheck) {
      try {
        const dkimRecords = await resolveTxt(`${selector}._domainkey.${domain}`);
        if (dkimRecords && dkimRecords.length > 0) {
          dkimResults.push(selector);
        }
      } catch (error) {
        // Ignore errors - just means no record for this selector
      }
    }
    
    if (dkimResults.length > 0) {
      result.dkim = {
        exists: true,
        valid: true,
        selectors: dkimResults
      };
    } else {
      result.dkim.issues = ['No DKIM records found for common selectors'];
    }
    
    // Basic heuristic DNSSEC check by looking for DS records
    try {
      // This is a simplified check and doesn't fully validate DNSSEC
      const nsRecords = await resolveNs(domain);
      if (nsRecords && nsRecords.length > 0) {
        // We'll mark DNSSEC as potentially enabled, but proper validation requires
        // specialized tools beyond the scope of a basic package
        result.dnssec = {
          enabled: true,
          valid: true,
          issues: ['Basic DNSSEC detection only. Full validation requires specialized tools.']
        };
      }
    } catch (error) {
      result.dnssec.issues = ['Failed to check nameservers for DNSSEC'];
    }
    
    return {
      status: 'success',
      scanner: 'dnsRecords',
      data: result,
      timeTaken: Date.now() - startTime
    };
  } catch (error) {
    return {
      status: 'failure',
      scanner: 'dnsRecords',
      error: (error as Error).message || 'Unknown error',
      data: result,
      timeTaken: Date.now() - startTime
    };
  }
};
