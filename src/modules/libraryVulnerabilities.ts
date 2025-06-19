import { LibraryVulnerabilityResult, Scanner, ScannerInput } from '../types';
import { makeRequest, createScannerInput } from '../core/request';

interface RetireJsVuln {
  identifiers: {
    CVE?: string[];
    [key: string]: string[] | undefined;
  };
  severity: string;
  info: string[];
}

interface RetireJsResult {
  version: string;
  component: string;
  vulnerabilities?: RetireJsVuln[];
}

// Common CDN patterns to detect libraries
const COMMON_LIBRARIES = [
  { name: 'jQuery', regex: /jquery[-.](\d+\.\d+\.\d+)(?:\.min)?\.js/i },
  { name: 'Bootstrap', regex: /bootstrap[-.](\d+\.\d+\.\d+)(?:\.min)?\.(?:js|css)/i },
  { name: 'React', regex: /react[-.](\d+\.\d+\.\d+)(?:\.min)?\.js/i },
  { name: 'Angular', regex: /angular[-.]?(?:core[\./])?(\d+\.\d+\.\d+)(?:\.min)?\.js/i },
  { name: 'Vue', regex: /vue(?:\.esm)?[-.](\d+\.\d+\.\d+)(?:\.min)?\.js/i },
  { name: 'Lodash', regex: /lodash(?:\.core)?[-.](\d+\.\d+\.\d+)(?:\.min)?\.js/i },
  { name: 'Moment', regex: /moment[-.](\d+\.\d+\.\d+)(?:\.min)?\.js/i },
  { name: 'D3', regex: /d3(?:\.v\d)?[-.](\d+\.\d+\.\d+)(?:\.min)?\.js/i },
  { name: 'Axios', regex: /axios[-.](\d+\.\d+\.\d+)(?:\.min)?\.js/i },
];

// List of additional vulnerability data sources
const VULNERABILITY_SOURCES = [
  'https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json',
  // Snyk doesn't provide direct JSON access, so we'll stick with RetireJS for now
  // Additional open source vulnerability sources could be added here
];

/**
 * Scan for vulnerable JavaScript libraries using Retire.js data and additional techniques
 */
export const scanLibraryVulnerabilities: Scanner<LibraryVulnerabilityResult> = async (
  input: ScannerInput
) => {
  const startTime = Date.now();
  const normalizedInput = createScannerInput(input);
  
  try {
    // Fetch Retire.js vulnerability database
    const retireDbUrl = 'https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json';
    
    const dbResponse = await makeRequest(retireDbUrl, {
      timeout: normalizedInput.timeout || 15000
    });
    
    if (dbResponse.error || !dbResponse.data) {
      return {
        status: 'failure',
        scanner: 'libraryVulnerabilities',
        error: dbResponse.error || 'Failed to retrieve vulnerability database',
        data: {
          vulnerableLibs: [],
          totalVulnerabilities: 0
        },
        timeTaken: Date.now() - startTime
      };
    }
    
    // Parse vulnerability database
    let vulnerabilityDb: Record<string, any>;
    if (typeof dbResponse.data === 'string') {
      try {
        vulnerabilityDb = JSON.parse(dbResponse.data);
      } catch (e) {
        return {
          status: 'failure',
          scanner: 'libraryVulnerabilities',
          error: 'Failed to parse vulnerability database',
          data: {
            vulnerableLibs: [],
            totalVulnerabilities: 0
          },
          timeTaken: Date.now() - startTime
        };
      }
    } else {
      vulnerabilityDb = dbResponse.data;
    }
    
    // Get HTML content to scan
    let html: string;
    
    if (normalizedInput.options?.html) {
      html = normalizedInput.options.html;
    } else {
      // Make a request to get the HTML
      const response = await makeRequest(normalizedInput.target, {
        method: 'GET',
        timeout: normalizedInput.timeout || 10000,
        headers: {
          ...normalizedInput.headers,
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'
        }
      });
      
      if (response.error || !response.data) {
        return {
          status: 'failure',
          scanner: 'libraryVulnerabilities',
          error: response.error || 'Failed to retrieve website content',
          data: {
            vulnerableLibs: [],
            totalVulnerabilities: 0
          },
          timeTaken: Date.now() - startTime
        };
      }
      
      html = typeof response.data === 'string' ? response.data : String(response.data);
    }
    
    // Extract script URLs using regex
    const scriptRegex = /<script[^>]*src=["']([^"']+)["'][^>]*>/g;
    let match;
    const scriptUrls: string[] = [];
    
    while ((match = scriptRegex.exec(html)) !== null) {
      let url = match[1];
      
      // Make relative URLs absolute
      if (url.startsWith('/') && !url.startsWith('//')) {
        const baseUrl = new URL(normalizedInput.target);
        url = baseUrl.origin + url;
      } else if (!url.startsWith('http') && !url.startsWith('//')) {
        const baseUrl = new URL(normalizedInput.target);
        url = baseUrl.href.replace(/\/$/, '') + '/' + url;
      } else if (url.startsWith('//')) {
        url = 'https:' + url;
      }
      
      scriptUrls.push(url);
    }
    
    // Also extract style URLs for CSS frameworks
    const styleRegex = /<link[^>]*rel=["']stylesheet["'][^>]*href=["']([^"']+)["'][^>]*>/g;
    while ((match = styleRegex.exec(html)) !== null) {
      let url = match[1];
      
      // Make relative URLs absolute
      if (url.startsWith('/') && !url.startsWith('//')) {
        const baseUrl = new URL(normalizedInput.target);
        url = baseUrl.origin + url;
      } else if (!url.startsWith('http') && !url.startsWith('//')) {
        const baseUrl = new URL(normalizedInput.target);
        url = baseUrl.href.replace(/\/$/, '') + '/' + url;
      } else if (url.startsWith('//')) {
        url = 'https:' + url;
      }
      
      scriptUrls.push(url); // Add to same list for processing
    }
    
    // Also extract inline script content for identification
    const inlineScriptRegex = /<script[^>]*>([\s\S]*?)<\/script>/g;
    const inlineScripts: string[] = [];
    
    while ((match = inlineScriptRegex.exec(html)) !== null) {
      if (match[1].trim()) {
        inlineScripts.push(match[1]);
      }
    }
    
    // Analyze script URLs for known libraries
    const vulnerableLibs: LibraryVulnerabilityResult['vulnerableLibs'] = [];
    const detectedLibs: Map<string, string> = new Map(); // Store all detected libs for reporting
    
    // Function to check URL for library indicators
    const checkUrlForLibrary = async (url: string) => {
      // First check URL against common library patterns
      for (const lib of COMMON_LIBRARIES) {
        const match = url.match(lib.regex);
        if (match && match[1]) {
          const version = match[1];
          detectedLibs.set(lib.name, version);
        }
      }
      
      // Then check against RetireJS database
      Object.keys(vulnerabilityDb).forEach(libName => {
        const lib = vulnerabilityDb[libName];
        
        if (lib.extractors && lib.extractors.uri) {
          lib.extractors.uri.forEach((pattern: string) => {
            try {
              const regex = new RegExp(pattern);
              const match = url.match(regex);
              
              if (match) {
                // Try to extract version from URL
                let version = '';
                
                if (match.length > 1) {
                  version = match[1];
                }
                
                // Store in detected libs
                detectedLibs.set(libName, version);
                
                // Check if this version has vulnerabilities
                const vulnerabilities = findLibraryVulnerabilities(lib, version);
                
                if (vulnerabilities.length > 0) {
                  const existingLib = vulnerableLibs.find(l => 
                    l.name === libName && l.version === version);
                  
                  if (!existingLib) {
                    vulnerableLibs.push({
                      name: libName,
                      version: version,
                      vulnerabilities: vulnerabilities
                    });
                  }
                }
              }
            } catch (e) {
              // Skip invalid regex patterns
            }
          });
        }
      });
      
      // For certain CDNs, try to fetch the actual script content
      if (url.includes('cdn.') || url.includes('.min.js')) {
        try {
          // Only fetch JS files, not CSS
          if (url.endsWith('.js') || !url.includes('.')) {
            const scriptContent = await makeRequest(url, {
              timeout: 5000 // Short timeout for external resources
            }).then(r => typeof r.data === 'string' ? r.data : String(r.data))
              .catch(() => ''); // Ignore failures
              
            if (scriptContent) {
              // Check content for library signatures
              Object.keys(vulnerabilityDb).forEach(libName => {
                const lib = vulnerabilityDb[libName];
                
                if (lib.extractors && lib.extractors.filecontent) {
                  lib.extractors.filecontent.forEach((pattern: string) => {
                    try {
                      const regex = new RegExp(pattern);
                      const match = scriptContent.match(regex);
                      
                      if (match) {
                        // Try to extract version
                        let version = '';
                        
                        if (match.length > 1) {
                          version = match[1];
                        }
                        
                        // Store in detected libs
                        detectedLibs.set(libName, version);
                        
                        // Check if this version has vulnerabilities
                        const vulnerabilities = findLibraryVulnerabilities(lib, version);
                        
                        if (vulnerabilities.length > 0) {
                          const existingLib = vulnerableLibs.find(l => 
                            l.name === libName && l.version === version);
                          
                          if (!existingLib) {
                            vulnerableLibs.push({
                              name: libName,
                              version: version,
                              vulnerabilities: vulnerabilities
                            });
                          }
                        }
                      }
                    } catch (e) {
                      // Skip invalid regex patterns
                    }
                  });
                }
              });
            }
          }
        } catch (e) {
          // Ignore errors fetching external scripts
        }
      }
    };
    
    // Process script URLs - limit concurrency to avoid overwhelming the server
    const concurrentLimit = normalizedInput.options?.concurrentLimit || 5;
    const chunks: string[][] = [];
    
    // Split URLs into chunks for concurrent processing
    for (let i = 0; i < scriptUrls.length; i += concurrentLimit) {
      chunks.push(scriptUrls.slice(i, i + concurrentLimit));
    }
    
    // Process each chunk of URLs
    for (const chunk of chunks) {
      await Promise.all(chunk.map(url => checkUrlForLibrary(url)));
    }
    
    // Process inline scripts
    for (const script of inlineScripts) {
      // Check for library signature in inline scripts
      Object.keys(vulnerabilityDb).forEach(libName => {
        const lib = vulnerabilityDb[libName];
        
        if (lib.extractors && lib.extractors.filecontent) {
          lib.extractors.filecontent.forEach((pattern: string) => {
            try {
              const regex = new RegExp(pattern);
              const match = script.match(regex);
              
              if (match) {
                // Try to extract version
                let version = '';
                
                if (match.length > 1) {
                  version = match[1];
                }
                
                // Store in detected libs
                detectedLibs.set(libName, version);
                
                // Check if this version has vulnerabilities
                const vulnerabilities = findLibraryVulnerabilities(lib, version);
                
                if (vulnerabilities.length > 0) {
                  // Check if we already found this library
                  const existingLib = vulnerableLibs.find(lib => 
                    lib.name === libName && lib.version === version);
                
                  if (!existingLib) {
                    vulnerableLibs.push({
                      name: libName,
                      version: version,
                      vulnerabilities: vulnerabilities
                    });
                  }
                }
              }
            } catch (e) {
              // Skip invalid regex patterns
            }
          });
        }
      });
    }
    
    // Count total vulnerabilities
    const totalVulnerabilities = vulnerableLibs.reduce(
      (total, lib) => total + lib.vulnerabilities.length, 0
    );
    
    // Add detected libraries info in the response if requested
    let result: any = {
      vulnerableLibs,
      totalVulnerabilities
    };
    
    // Include all detected libraries if requested
    if (normalizedInput.options?.includeAllLibraries) {
      result.detectedLibraries = Array.from(detectedLibs.entries()).map(([name, version]) => ({
        name,
        version
      }));
    }
    
    return {
      status: 'success',
      scanner: 'libraryVulnerabilities',
      data: result,
      timeTaken: Date.now() - startTime
    };
  } catch (error) {
    return {
      status: 'failure',
      scanner: 'libraryVulnerabilities',
      error: (error as Error).message || 'Unknown error',
      data: {
        vulnerableLibs: [],
        totalVulnerabilities: 0
      },
      timeTaken: Date.now() - startTime
    };
  }
};

/**
 * Helper function to find vulnerabilities for a specific library version
 */
function findLibraryVulnerabilities(
  lib: any,
  version: string
): { id: string; severity: 'high' | 'medium' | 'low'; info: string }[] {
  if (!lib.vulnerabilities || !version) {
    return [];
  }
  
  const vulnerabilities: { id: string; severity: 'high' | 'medium' | 'low'; info: string }[] = [];
  
  lib.vulnerabilities.forEach((vuln: any) => {
    // Check if version is in vulnerable range
    let isVulnerable = false;
    
    if (vuln.below && isVersionBelow(version, vuln.below)) {
      isVulnerable = true;
    }
    
    if (vuln.atOrAbove && vuln.below && 
        isVersionAtOrAbove(version, vuln.atOrAbove) && 
        isVersionBelow(version, vuln.below)) {
      isVulnerable = true;
    }
    
    if (isVulnerable) {
      let id = 'UNKNOWN';
      
      // Look for CVE or other identifier
      if (vuln.identifiers) {
        if (vuln.identifiers.CVE && vuln.identifiers.CVE.length > 0) {
          id = vuln.identifiers.CVE[0];
        } else if (vuln.identifiers.bug && vuln.identifiers.bug.length > 0) {
          id = `BUG-${vuln.identifiers.bug[0]}`;
        } else if (vuln.identifiers.issue && vuln.identifiers.issue.length > 0) {
          id = `ISSUE-${vuln.identifiers.issue[0]}`;
        }
      }
      
      // Map severity
      let severity: 'high' | 'medium' | 'low' = 'medium';
      
      if (vuln.severity === 'high' || vuln.severity === 'critical') {
        severity = 'high';
      } else if (vuln.severity === 'medium' || vuln.severity === 'moderate') {
        severity = 'medium';
      } else if (vuln.severity === 'low') {
        severity = 'low';
      }
      
      // Get info
      const info = vuln.info && vuln.info.length > 0 
        ? vuln.info[0] 
        : `Vulnerability in ${lib.component} < ${vuln.below}`;
      
      vulnerabilities.push({
        id,
        severity,
        info
      });
    }
  });
  
  return vulnerabilities;
}

/**
 * Simple semantic version comparison helper functions
 */
function isVersionBelow(version: string, targetVersion: string): boolean {
  // Handle non-semantic versions and extract numeric parts
  const cleanVersion = version.replace(/[^\d.]/g, '');
  const cleanTarget = targetVersion.replace(/[^\d.]/g, '');
  
  if (!cleanVersion || !cleanTarget) return false;
  
  const v1 = cleanVersion.split('.').map(p => parseInt(p, 10) || 0);
  const v2 = cleanTarget.split('.').map(p => parseInt(p, 10) || 0);
  
  for (let i = 0; i < Math.max(v1.length, v2.length); i++) {
    const n1 = i < v1.length ? v1[i] : 0;
    const n2 = i < v2.length ? v2[i] : 0;
    
    if (n1 < n2) return true;
    if (n1 > n2) return false;
  }
  
  return false; // Versions are equal
}

function isVersionAtOrAbove(version: string, targetVersion: string): boolean {
  return !isVersionBelow(version, targetVersion);
}
