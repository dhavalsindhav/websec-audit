import { ScannerInput, Scanner, SubdomainResult } from '../types';
import { makeRequest, extractDomain, createScannerInput, safeJsonParse } from '../core/request';

/**
 * Scan for subdomains using passive techniques (Certificate Transparency logs)
 */
export const scanSubdomains: Scanner<SubdomainResult> = async (
  input: ScannerInput
) => {
  const startTime = Date.now();
  const normalizedInput = createScannerInput(input);
  const domain = extractDomain(normalizedInput.target);
  
  try {
    // Use crt.sh Certificate Transparency search
    const crtShUrl = `https://crt.sh/?q=%.${domain}&output=json`;
    
    const response = await makeRequest(crtShUrl, {
      method: 'GET',
      timeout: normalizedInput.timeout || 15000, // Increase default timeout for crt.sh
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)'
      }
    });
    
    if (response.error) {
      return {
        status: 'failure',
        scanner: 'subdomains',
        error: `Failed to retrieve certificate data: ${response.error}`,
        data: {
          subdomains: [],
          total: 0
        },
        timeTaken: Date.now() - startTime
      };
    }
    
    // Parse the response data
    let crtData: any[] = [];
    
    if (typeof response.data === 'string') {
      try {
        // Handle potential JSON formatting issues
        const cleanJson = response.data.trim().replace(/\n/g, '');
        crtData = JSON.parse(cleanJson);
      } catch (e) {
        // Try alternate approach - sometimes crt.sh returns HTML instead of JSON
        if (response.data.includes('<HTML>') || response.data.includes('<html>')) {
          return {
            status: 'failure',
            scanner: 'subdomains',
            error: 'crt.sh returned HTML instead of JSON. Try again later.',
            data: {
              subdomains: [],
              total: 0
            },
            timeTaken: Date.now() - startTime
          };
        }
        
        // Log detailed error information
        console.error('JSON Parse Error:', e);
        console.error('Response data sample:', response.data.substring(0, 200));
        
        return {
          status: 'failure',
          scanner: 'subdomains',
          error: `Failed to parse certificate data: ${(e as Error).message}`,
          data: {
            subdomains: [],
            total: 0
          },
          timeTaken: Date.now() - startTime
        };
      }
    } else if (Array.isArray(response.data)) {
      crtData = response.data;
    } else if (response.data && typeof response.data === 'object') {
      // Handle case where data is already parsed as an object but not an array
      crtData = [response.data];
    }
    
    // Check if we actually got data
    if (!crtData || crtData.length === 0) {
      return {
        status: 'failure',
        scanner: 'subdomains',
        error: 'No certificate data found for this domain',
        data: {
          subdomains: [],
          total: 0
        },
        timeTaken: Date.now() - startTime
      };
    }
    
    // Extract domain names from certificates
    const allDomains = new Set<string>();
    
    crtData.forEach((cert: any) => {
      if (cert && cert.name_value) {
        const name = cert.name_value.toLowerCase();
        
        // Handle multiple domains in one certificate (comma separated)
        const domains = name.split(/[,\s]+/);
        
        domains.forEach((d: string) => {
          // Clean up the domain name
          const cleanDomain = d.trim();
          
          // Only add if it's a subdomain and not the main domain
          if (cleanDomain.endsWith('.' + domain) && cleanDomain !== domain) {
            allDomains.add(cleanDomain);
          }
        });
      }
    });
    
    // Convert to array and sort
    const subdomains = Array.from(allDomains).sort();
    
    // Check if we should do live validation of found subdomains
    if (normalizedInput.options?.checkLive === true) {
      const liveSubdomains: SubdomainResult['live'] = [];
      
      // Test each subdomain with HEAD request (limit concurrent requests)
      const concurrentLimit = normalizedInput.options?.concurrentLimit || 5;
      const chunks: string[][] = [];
      
      // Split subdomains into chunks for concurrent processing
      for (let i = 0; i < subdomains.length; i += concurrentLimit) {
        chunks.push(subdomains.slice(i, i + concurrentLimit));
      }
      
      // Process each chunk of subdomains
      for (const chunk of chunks) {
        const promises = chunk.map(subdomain => {
          return makeRequest(`https://${subdomain}`, {
            method: 'HEAD',
            timeout: 5000  // Short timeout for live checks
          }).then(resp => {
            if (!resp.error) {
              liveSubdomains.push({
                domain: subdomain,
                status: resp.status
              });
            }
          }).catch(() => {
            // Ignore individual request errors
          });
        });
        
        await Promise.all(promises);
      }
      
      return {
        status: 'success',
        scanner: 'subdomains',
        data: {
          subdomains,
          total: subdomains.length,
          live: liveSubdomains
        },
        timeTaken: Date.now() - startTime
      };
    }
    
    return {
      status: 'success',
      scanner: 'subdomains',
      data: {
        subdomains,
        total: subdomains.length
      },
      timeTaken: Date.now() - startTime
    };
  } catch (error) {
    return {
      status: 'failure',
      scanner: 'subdomains',
      error: (error as Error).message || 'Unknown error',
      data: {
        subdomains: [],
        total: 0
      },
      timeTaken: Date.now() - startTime
    };
  }
};
