import * as net from 'net';
import { PortScanResult, Scanner, ScannerInput } from '../types';
import { extractDomain, createScannerInput } from '../core/request';

// Default list of common ports to scan
const DEFAULT_PORTS = [
  21,    // FTP
  22,    // SSH
  23,    // Telnet
  25,    // SMTP
  53,    // DNS
  80,    // HTTP
  110,   // POP3
  143,   // IMAP
  443,   // HTTPS
  465,   // SMTPS
  587,   // SMTP Submission
  993,   // IMAPS
  995,   // POP3S
  3306,  // MySQL
  5432,  // PostgreSQL
  8080,  // HTTP Alternate
  8443   // HTTPS Alternate
];

// Map of common services by port
const SERVICE_NAMES: Record<number, string> = {
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  80: 'HTTP',
  110: 'POP3',
  143: 'IMAP',
  443: 'HTTPS',
  465: 'SMTPS',
  587: 'SMTP Submission',
  993: 'IMAPS',
  995: 'POP3S',
  3306: 'MySQL',
  5432: 'PostgreSQL',
  8080: 'HTTP Alternate',
  8443: 'HTTPS Alternate'
};

/**
 * Scan for open ports
 * Note: This can only be used in a Node.js environment
 */
export const scanPorts: Scanner<PortScanResult> = async (
  input: ScannerInput
) => {
  const startTime = Date.now();
  const normalizedInput = createScannerInput(input);
  const domain = extractDomain(normalizedInput.target);
  const timeout = normalizedInput.timeout || 3000; // Use short timeout for port scan
  
  // Get ports to scan from options or use defaults
  const portsToScan = normalizedInput.options?.ports || DEFAULT_PORTS;
  
  // Create result
  const result: PortScanResult = {
    openPorts: [],
    total: 0
  };
  
  try {
    // Scan each port
    const portPromises = portsToScan.map((port: number) => {
      return new Promise<void>(resolve => {
        // Create socket
        const socket = new net.Socket();
        let resolved = false;
        
        // Set timeout
        socket.setTimeout(timeout);
        
        // Handle connection
        socket.on('connect', () => {
          if (resolved) return;
          resolved = true;
          
          // Try to get banner by sending a simple request
          let banner = '';
          const bannerTimeout = setTimeout(() => {
            socket.destroy();
            result.openPorts.push({
              port,
              service: SERVICE_NAMES[port] || undefined,
              banner: banner || undefined
            });
            resolve();
          }, 1000);
          
          // Listen for data (banner)          
           socket.once('data', (data: Buffer) => {
            banner = data.toString().trim();
            clearTimeout(bannerTimeout);
            socket.destroy();
            
            result.openPorts.push({
              port,
              service: SERVICE_NAMES[port] || undefined,
              banner: banner || undefined
            });
            
            resolve();
          });
          
          // Send a request to trigger banner for common protocols
          if (port === 80) {
            socket.write('HEAD / HTTP/1.1\r\nHost: ' + domain + '\r\n\r\n');
          } else if (port === 443) {
            socket.destroy(); // HTTPS requires TLS, can't get banner directly
            result.openPorts.push({
              port,
              service: 'HTTPS'
            });
            resolve();
          } else if (port === 25 || port === 587) {
            // SMTP
            // Banner will be automatically sent
          } else if (port === 22) {
            // SSH banner will be automatically sent
          } else {
            // Other protocols - no specific request
            socket.destroy();
            result.openPorts.push({
              port,
              service: SERVICE_NAMES[port] || undefined
            });
            resolve();
          }
        });
        
        // Handle errors
        socket.on('error', () => {
          if (resolved) return;
          resolved = true;
          socket.destroy();
          resolve();
        });
        
        // Handle timeout
        socket.on('timeout', () => {
          if (resolved) return;
          resolved = true;
          socket.destroy();
          resolve();
        });
        
        // Try to connect
        socket.connect(port, domain);
      });
    });
    
    // Wait for all port scans to complete
    await Promise.all(portPromises);
    
    // Set total
    result.total = result.openPorts.length;
    
    return {
      status: 'success',
      scanner: 'portScan',
      data: result,
      timeTaken: Date.now() - startTime
    };
  } catch (error) {
    return {
      status: 'failure',
      scanner: 'portScan',
      error: (error as Error).message || 'Unknown error',
      data: result,
      timeTaken: Date.now() - startTime
    };
  }
};
