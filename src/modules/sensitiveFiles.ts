import { ScannerInput, Scanner, SensitiveFileResult } from '../types';
import { makeRequest, normalizeUrl, createScannerInput } from '../core/request';

// List of potentially sensitive files/paths to check
const SENSITIVE_PATHS = [
  '/.git/config',
  '/.env',
  '/.env.local',
  '/.env.development',
  '/.env.production',
  '/config.json',
  '/config.js',
  '/config.php',
  '/wp-config.php',
  '/config.xml',
  '/credentials.json',
  '/secrets.json',
  '/settings.json',
  '/database.yml',
  '/db.sqlite',
  '/backup.zip',
  '/backup.sql',
  '/backup.tar.gz',
  '/dump.sql',
  '/users.sql',
  '/users.csv',
  '/phpinfo.php',
  '/info.php',
  '/.htpasswd',
  '/server-status',
  '/server-info',
  '/readme.md',
  '/README.md',
  '/api/swagger',
  '/api/docs',
  '/swagger.json',
  '/swagger-ui.html',
  '/robots.txt',
  '/sitemap.xml',
  '/.well-known/security.txt'
];

/**
 * Scan for exposed sensitive files
 */
export const scanSensitiveFiles: Scanner<SensitiveFileResult> = async (
  input: ScannerInput
) => {
  const startTime = Date.now();
  const normalizedInput = createScannerInput(input);
  const baseUrl = normalizeUrl(normalizedInput.target);
  const timeout = normalizedInput.timeout || 5000;
  
  const exposedFiles: SensitiveFileResult['exposedFiles'] = [];
  const issues: SensitiveFileResult['issues'] = [];
  
  try {
    // Filter paths to test based on options
    let pathsToTest = [...SENSITIVE_PATHS];
    if (normalizedInput.options?.additionalPaths) {
      pathsToTest = pathsToTest.concat(normalizedInput.options.additionalPaths);
    }
    
    // Limit concurrent requests to avoid overwhelming the server
    const concurrentLimit = normalizedInput.options?.concurrentLimit || 5;
    const chunks: string[][] = [];
    
    // Split paths into chunks for concurrent processing
    for (let i = 0; i < pathsToTest.length; i += concurrentLimit) {
      chunks.push(pathsToTest.slice(i, i + concurrentLimit));
    }
    
    // Process each chunk of paths
    for (const chunk of chunks) {
      const promises = chunk.map(path => {
        const url = baseUrl + path;
        
        // Use GET instead of HEAD to verify actual content
        return makeRequest(url, {
          method: 'GET',
          timeout: timeout,
          headers: normalizedInput.headers
        }).then(response => {
          // If there was an error with the request (status will be 0)
          if (response.error) {
            // Just skip this path - no need to log an error for 404s and such
            return;
          }
          
          // If the file exists (2xx or 3xx status code)
          if (response.status >= 200 && response.status < 400) {
            let contentTypeHeader = response.headers['content-type'];
            const contentType = Array.isArray(contentTypeHeader)
              ? contentTypeHeader.join(', ')
              : contentTypeHeader || undefined;
            const contentLength = response.headers['content-length'] 
              ? parseInt(
                  Array.isArray(response.headers['content-length'])
                    ? response.headers['content-length'][0]
                    : response.headers['content-length'] as string,
                  10
                ) 
              : undefined;
            
            // Detect false positives - check if content exists or is meaningful
            const hasContent = response.data && 
                            (typeof response.data === 'string' ? 
                              response.data.length > 50 : true);
            
            // Check if the response contains a default page or is completely empty
            const isDefaultPage = typeof response.data === 'string' && (
              response.data.includes('<html') && 
              response.data.includes('</html>') && 
              (response.data.includes('<title>Index of') === false) // Not a directory listing
            );
            
            // Modified condition to better detect false positives
            // Only skip if it's both a default HTML page AND has no content length
            if (isDefaultPage && !contentLength) {
              return;
            }
            
            exposedFiles.push({
              path,
              status: response.status,
              contentType,
              size: contentLength
            });
            
            // Determine severity based on path
            let severity: 'high' | 'medium' | 'low' = 'medium';
            let description = `Exposed file: ${path}`;
            
            // Higher risk files
            if (path.includes('.env') || 
                path.includes('config') || 
                path.includes('credential') || 
                path.includes('secret') || 
                path.includes('password') || 
                path.includes('.git/') ||
                path.includes('backup') ||
                path.includes('dump')) {
              severity = 'high';
              description = `Critical file exposed: ${path}. May contain sensitive information or credentials.`;
            } 
            // Lower risk files
            else if (path.includes('readme') || 
                    path.includes('robots.txt') || 
                    path.includes('sitemap.xml') || 
                    path.includes('.well-known')) {
              severity = 'low';
              description = `Information disclosure: ${path}. May reveal system information.`;
            }
            
            issues.push({ severity, path, description });
          }
        }).catch(error => {
          // Log specific errors that might indicate a bigger problem
          // but still continue with the scanning process
          if (normalizedInput.options?.debug) {
            console.error(`Error scanning ${url}: ${error.message}`);
          }
        });
      });
      
      // Wait for all promises to complete before moving to the next chunk
      await Promise.all(promises);
    }
    
    return {
      status: 'success',
      scanner: 'sensitiveFiles',
      data: {
        exposedFiles,
        issues
      },
      timeTaken: Date.now() - startTime
    };
  } catch (error) {
    return {
      status: 'failure',
      scanner: 'sensitiveFiles',
      error: (error as Error).message || 'Unknown error',
      data: {
        exposedFiles: [],
        issues: []
      },
      timeTaken: Date.now() - startTime
    };
  }
};
