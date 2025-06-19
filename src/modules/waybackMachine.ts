import { OSINTResult, Scanner, ScannerInput } from '../types';
import { makeRequest, extractDomain, createScannerInput } from '../core/request';

/**
 * Scan for historical data using Wayback Machine's API
 */
export const scanWaybackMachine: Scanner<Pick<OSINTResult, 'wayback'>> = async (
  input: ScannerInput
) => {
  const startTime = Date.now();
  const normalizedInput = createScannerInput(input);
  const domain = extractDomain(normalizedInput.target);
  
  try {
    // Use Wayback Machine API to get snapshots
    const waybackUrl = `https://archive.org/wayback/available?url=${domain}&timestamp=*&output=json`;
    
    const response = await makeRequest(waybackUrl, {
      method: 'GET',
      timeout: normalizedInput.timeout
    });
    
    if (response.error || !response.data) {
      return {
        status: 'failure',
        scanner: 'waybackMachine',
        error: response.error || 'Failed to retrieve Wayback Machine data',
        data: {
          wayback: {
            totalSnapshots: 0
          }
        },
        timeTaken: Date.now() - startTime
      };
    }
    
    // Parse response
    let waybackData;
    if (typeof response.data === 'string') {
      waybackData = JSON.parse(response.data);
    } else {
      waybackData = response.data;
    }
    
    // Check if there are snapshots
    if (!waybackData.archived_snapshots || Object.keys(waybackData.archived_snapshots).length === 0) {
      return {
        status: 'success',
        scanner: 'waybackMachine',
        data: {
          wayback: {
            totalSnapshots: 0
          }
        },
        timeTaken: Date.now() - startTime
      };
    }
    
    // Get additional snapshots from the CDX API (to get more than just the closest)
    const cdxUrl = `https://web.archive.org/cdx/search/cdx?url=${domain}&output=json&limit=50`;
    
    const cdxResponse = await makeRequest(cdxUrl, {
      method: 'GET',
      timeout: normalizedInput.timeout
    });
    
    let snapshots: { url: string; timestamp: string }[] = [];
    
    if (!cdxResponse.error && cdxResponse.data) {
      try {
        let cdxData;
        if (typeof cdxResponse.data === 'string') {
          cdxData = JSON.parse(cdxResponse.data);
        } else {
          cdxData = cdxResponse.data;
        }
        
        // Skip the first row as it contains field names
        if (cdxData.length > 1) {
          // Format: [urlkey, timestamp, original, mimetype, statuscode, digest, length]
          for (let i = 1; i < cdxData.length; i++) {
            const item = cdxData[i];
            if (item && item.length >= 3) {
              snapshots.push({
                url: `https://web.archive.org/web/${item[1]}/${item[2]}`,
                timestamp: item[1]
              });
            }
          }
        }
      } catch (e) {
        // If CDX API fails, we still have basic data
      }
    }
    
    // Get first and last snapshot dates
    const timestamps = snapshots.map(s => s.timestamp);
    let firstSeen;
    let lastSeen;
    
    if (timestamps.length > 0) {
      timestamps.sort();
      firstSeen = formatWaybackTimestamp(timestamps[0]);
      lastSeen = formatWaybackTimestamp(timestamps[timestamps.length - 1]);
    } else if (waybackData.archived_snapshots.closest) {
      const timestamp = waybackData.archived_snapshots.closest.timestamp;
      firstSeen = formatWaybackTimestamp(timestamp);
      lastSeen = formatWaybackTimestamp(timestamp);
    }
    
    return {
      status: 'success',
      scanner: 'waybackMachine',
      data: {
        wayback: {
          firstSeen,
          lastSeen,
          totalSnapshots: snapshots.length || 1,
          snapshots: snapshots.length > 0 ? snapshots : undefined
        }
      },
      timeTaken: Date.now() - startTime
    };
  } catch (error) {
    return {
      status: 'failure',
      scanner: 'waybackMachine',
      error: (error as Error).message || 'Unknown error',
      data: {
        wayback: {
          totalSnapshots: 0
        }
      },
      timeTaken: Date.now() - startTime
    };
  }
};

/**
 * Format wayback machine timestamp (YYYYMMDDHHMMSS) to ISO date
 */
function formatWaybackTimestamp(timestamp: string): string {
  if (!timestamp || timestamp.length < 8) {
    return 'Unknown';
  }
  
  // Extract components, assuming minimum YYYYMMDD format
  const year = timestamp.slice(0, 4);
  const month = timestamp.slice(4, 6);
  const day = timestamp.slice(6, 8);
  
  const time = timestamp.length >= 14 ? 
    `${timestamp.slice(8, 10)}:${timestamp.slice(10, 12)}:${timestamp.slice(12, 14)}` :
    '00:00:00';
  
  return `${year}-${month}-${day}T${time}Z`;
}
