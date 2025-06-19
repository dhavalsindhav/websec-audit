import { OSINTResult, Scanner } from '../types';
/**
 * Scan for historical data using Wayback Machine's API
 */
export declare const scanWaybackMachine: Scanner<Pick<OSINTResult, 'wayback'>>;
