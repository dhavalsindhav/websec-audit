/**
 * Frontend-specific exports for browser environments
 */

// Import from modules that work in browsers
// Note: All front-end functionality is exported from the main index
// This file exists to allow for selective imports

import { detectForms } from '../modules/formDetection.js';
import { scanSecurityHeaders } from '../modules/securityHeaders.js';

// Re-export for separate import paths
export { detectForms, scanSecurityHeaders };

/**
 * Browser-based DOM form detection that works directly with DOM
 */
export const detectFormsInDOM = async () => {
  // This function only works in browser environments
  if (typeof document === 'undefined') {
    throw new Error('detectFormsInDOM can only be used in browser environments');
  }
  
  // Get the HTML from the current document
  const html = document.documentElement.outerHTML;
  
  // Use the regular form detection with the HTML
  return detectForms({
    target: window.location.href,
    options: { html }
  });
};
