import { PortScanResult, Scanner } from '../types';
/**
 * Scan for open ports
 * Note: This can only be used in a Node.js environment
 */
export declare const scanPorts: Scanner<PortScanResult>;
