import { FormDetectionResult, Scanner, ScannerInput } from '../types.js';
import { makeRequest, createScannerInput } from '../core/request.js';
import * as cheerio from 'cheerio';

/**
 * Detect forms on a webpage and analyze their security
 */
export const detectForms: Scanner<FormDetectionResult> = async (
  input: ScannerInput
) => {
  const startTime = Date.now();
  const normalizedInput = createScannerInput(input);
  
  try {
    let html: string;
    
    // If content is provided in options, use that instead of making a request
    if (normalizedInput.options?.html) {
      html = normalizedInput.options.html;
    } else {
      // Make a request to get the HTML content
      const response = await makeRequest(normalizedInput.target, {
        method: 'GET',
        timeout: normalizedInput.timeout,
        headers: normalizedInput.headers
      });
      
      if (response.error || !response.data) {
        return {
          status: 'failure',
          scanner: 'formDetection',
          error: response.error || 'Failed to retrieve HTML content',
          data: { forms: [], total: 0 },
          timeTaken: Date.now() - startTime
        };
      }
      
      html = typeof response.data === 'string' ? response.data : String(response.data);
    }
    
    // Load HTML into cheerio for DOM parsing
    const $ = cheerio.load(html);
    const forms = $('form');
    const formResults: FormDetectionResult['forms'] = [];    forms.each((_i: number, formElement: any) => {
      const form = $(formElement);
      const action = form.attr('action') || '';
      const method = (form.attr('method') || 'get').toLowerCase();
      
      // Parse inputs
      const inputs: {
        name?: string;
        type: string;
        id?: string;
        required: boolean;
        autocomplete?: string;
      }[] = [];
      
      const formInputs = form.find('input, select, textarea, button[type="submit"]');
      
      formInputs.each((_j: number, inputElement: any) => {
        const input = $(inputElement);
        const type = input.attr('type') || 'text';
        
        inputs.push({
          name: input.attr('name'),
          type,
          id: input.attr('id'),
          required: input.attr('required') !== undefined,
          autocomplete: input.attr('autocomplete')
        });
      });
      
      // Check if the form has a password field
      const hasPassword = inputs.some(input => input.type === 'password');
      
      // Check for CSRF protection tokens
      const hasCSRF = inputs.some(input => {
        const name = (input.name || '').toLowerCase();
        return name.includes('csrf') || 
               name.includes('token') || 
               name.includes('nonce') || 
               name === '_token';
      });
      
      // Identify potential security issues
      const issues: {
        severity: 'high' | 'medium' | 'low' | 'info';
        description: string;
      }[] = [];
      
      // For login/auth forms
      if (hasPassword) {
        // Insecure method
        if (method !== 'post') {
          issues.push({
            severity: 'high',
            description: 'Login form uses insecure method (GET). Should use POST to prevent credentials in URL.'
          });
        }
        
        // Missing CSRF protection
        if (!hasCSRF) {
          issues.push({
            severity: 'high',
            description: 'Form appears to be missing CSRF protection token.'
          });
        }
        
        // Check for HTTPS action
        if (action && action.startsWith('http:')) {
          issues.push({
            severity: 'high',
            description: 'Form submits to insecure (HTTP) endpoint.'
          });
        }
        
        // Check for autocomplete on password fields
        const passwordInputs = inputs.filter(input => input.type === 'password');
        if (passwordInputs.some(input => input.autocomplete !== 'off' && input.autocomplete !== 'new-password')) {
          issues.push({
            severity: 'medium',
            description: 'Password field doesn\'t have autocomplete="off" or autocomplete="new-password".'
          });
        }
      }
      
      formResults.push({
        action,
        method,
        inputs,
        hasPassword,
        hasCSRF,
        issues
      });
    });
    
    return {
      status: 'success',
      scanner: 'formDetection',
      data: {
        forms: formResults,
        total: formResults.length
      },
      timeTaken: Date.now() - startTime
    };
  } catch (error) {
    return {
      status: 'failure',
      scanner: 'formDetection',
      error: (error as Error).message || 'Unknown error',
      data: { forms: [], total: 0 },
      timeTaken: Date.now() - startTime
    };
  }
};
