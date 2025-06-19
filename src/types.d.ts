/// <reference types="node" />

declare module 'retire' {
  export type RetireJsResult = any;
  export function scanFileContent(content: string): RetireJsResult[];
  export function scanUri(uri: string): RetireJsResult[];
}

declare module 'wappalyzer-core' {
  export function analyze(input: {
    url: string;
    html: string;
    headers: Record<string, any>;
  }): Promise<any[]>;
}

declare module 'dns2' {
  export const RECURSION_DESIRED: number;
  export const DNSSEC_OK: number;
  
  export class Packet {
    static create(options?: any): Packet;
  }
  
  export class DnsClient {
    constructor(options?: any);
    query(packet: Packet): Promise<any>;
    queryWithRetry(packet: Packet, retries?: number): Promise<any>;
  }
}

declare module 'whois-json' {
  export default function lookup(domain: string, options?: any): Promise<any>;
}
