import { Scanner, ScannerInput } from '../types';
import { createScannerInput, makeRequest } from '../core/request';

// Define the Cookie security result interface
export interface CookieSecurityResult {
  cookies: {
    name: string;
    secure: boolean;
    httpOnly: boolean;
    sameSite?: 'Strict' | 'Lax' | 'None' | null;
    path?: string;
    domain?: string;
    expires?: Date | null;
    maxAge?: number | null;
    raw: string;
  }[];
  issues: {
    severity: 'high' | 'medium' | 'low' | 'info';
    cookie?: string;
    description: string;
  }[];
  overallSecurity: 'high' | 'medium' | 'low';
  recommendations: string[];
}

/**
 * Scan cookies for security issues
 */
export const scanCookieSecurity: Scanner<CookieSecurityResult> = async (
  input: ScannerInput
) => {
  const startTime = Date.now();
  const normalizedInput = createScannerInput(input);
  
  try {
    // Make a GET request to get cookies
    const response = await makeRequest(normalizedInput.target, {
      method: 'GET',
      timeout: normalizedInput.timeout,
      headers: normalizedInput.headers
    });
    
    if (response.error || !response.headers) {
      return {
        status: 'failure',
        scanner: 'cookieSecurity',
        error: response.error || 'Failed to retrieve cookies',
        data: {
          cookies: [],
          issues: [{
            severity: 'info',
            description: 'Could not retrieve cookies from the target'
          }],
          overallSecurity: 'low',
          recommendations: ['Ensure the site is accessible and returns cookies']
        },
        timeTaken: Date.now() - startTime
      };
    }
    
    // Extract cookies from response headers
    const setCookieHeaders = response.headers['set-cookie'];
    if (!setCookieHeaders || (Array.isArray(setCookieHeaders) && setCookieHeaders.length === 0)) {
      return {
        status: 'success',
        scanner: 'cookieSecurity',
        data: {
          cookies: [],
          issues: [{
            severity: 'info',
            description: 'No cookies were set by the target'
          }],
          overallSecurity: 'medium',
          recommendations: ['If authentication is used, ensure proper cookies are set']
        },
        timeTaken: Date.now() - startTime
      };
    }
    
    // Convert to array if it's a string (single cookie)
    const cookies = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
    const parsedCookies: any[] = [];
    const issues: {
      severity: 'high' | 'medium' | 'low' | 'info';
      cookie?: string;
      description: string;
    }[] = [];
    
    // Parse each cookie and check for security attributes
    cookies.forEach((cookieStr: string) => {
      // Basic cookie parsing
      const parts = cookieStr.split(';').map(part => part.trim());
      const nameValue = parts[0].split('=');
      const name = nameValue[0];
      
      const cookie = {
        name,
        secure: false,
        httpOnly: false,
        sameSite: null as ('Strict' | 'Lax' | 'None' | null),
        path: '/',
        domain: undefined as string | undefined,
        expires: null as Date | null,
        maxAge: null as number | null,
        raw: cookieStr
      };
      
      // Parse attributes
      for (let i = 1; i < parts.length; i++) {
        const part = parts[i].toLowerCase();
        
        if (part === 'secure') {
          cookie.secure = true;
        } else if (part === 'httponly') {
          cookie.httpOnly = true;
        } else if (part.startsWith('samesite=')) {
          const sameSiteVal = part.substring(9).trim();
          cookie.sameSite = sameSiteVal.charAt(0).toUpperCase() + sameSiteVal.slice(1) as any;
        } else if (part.startsWith('path=')) {
          cookie.path = part.substring(5).trim();
        } else if (part.startsWith('domain=')) {
          cookie.domain = part.substring(7).trim();
        } else if (part.startsWith('expires=')) {
          try {
            cookie.expires = new Date(part.substring(8).trim());
          } catch (e) {
            // Invalid date format
          }
        } else if (part.startsWith('max-age=')) {
          const maxAge = parseInt(part.substring(8).trim(), 10);
          if (!isNaN(maxAge)) {
            cookie.maxAge = maxAge;
          }
        }
      }
      
      parsedCookies.push(cookie);
      
      // Check for security issues
      if (!cookie.secure) {
        issues.push({
          severity: 'high',
          cookie: cookie.name,
          description: `Cookie '${cookie.name}' is not secure (missing Secure flag)`
        });
      }
      
      if (!cookie.httpOnly) {
        issues.push({
          severity: 'medium',
          cookie: cookie.name,
          description: `Cookie '${cookie.name}' is not HttpOnly`
        });
      }
      
      if (!cookie.sameSite) {
        issues.push({
          severity: 'medium',
          cookie: cookie.name,
          description: `Cookie '${cookie.name}' has no SameSite attribute`
        });
      } else if (cookie.sameSite === 'None' && !cookie.secure) {
        issues.push({
          severity: 'high',
          cookie: cookie.name,
          description: `Cookie '${cookie.name}' uses SameSite=None without Secure flag`
        });
      }
    });
    
    // Determine overall security level
    let overallSecurity: 'high' | 'medium' | 'low' = 'high';
    const highIssues = issues.filter(i => i.severity === 'high').length;
    const mediumIssues = issues.filter(i => i.severity === 'medium').length;
    
    if (highIssues > 0) {
      overallSecurity = 'low';
    } else if (mediumIssues > 0) {
      overallSecurity = 'medium';
    }
    
    // Generate recommendations
    const recommendations: string[] = [];
    
    if (issues.some(i => i.description.includes('not secure'))) {
      recommendations.push('Set the Secure flag on all cookies to ensure they are only sent over HTTPS');
    }
    
    if (issues.some(i => i.description.includes('not HttpOnly'))) {
      recommendations.push('Set the HttpOnly flag on cookies to prevent access from JavaScript');
    }
    
    if (issues.some(i => i.description.includes('no SameSite'))) {
      recommendations.push('Set SameSite=Strict or SameSite=Lax on cookies to prevent CSRF attacks');
    }
    
    return {
      status: 'success',
      scanner: 'cookieSecurity',
      data: {
        cookies: parsedCookies,
        issues,
        overallSecurity,
        recommendations
      },
      timeTaken: Date.now() - startTime
    };
  } catch (error) {
    return {
      status: 'failure',
      scanner: 'cookieSecurity',
      error: (error as Error).message || 'Unknown error',
      data: {
        cookies: [],
        issues: [{
          severity: 'info',
          description: 'Failed to analyze cookies due to an error'
        }],
        overallSecurity: 'low',
        recommendations: ['Ensure the site is accessible']
      },
      timeTaken: Date.now() - startTime
    };
  }
};
