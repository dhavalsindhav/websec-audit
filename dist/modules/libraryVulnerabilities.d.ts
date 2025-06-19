import { LibraryVulnerabilityResult, Scanner } from '../types';
/**
 * Scan for vulnerable JavaScript libraries using Retire.js data and additional techniques
 */
export declare const scanLibraryVulnerabilities: Scanner<LibraryVulnerabilityResult>;
