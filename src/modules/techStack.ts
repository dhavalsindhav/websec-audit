import { ScannerInput, Scanner, TechStackResult } from '../types';
import { makeRequest, createScannerInput } from '../core/request';

// Technology detection patterns
const TECH_PATTERNS = {
  // Front-end Frameworks
  'React': {
    patterns: ['react.js', 'react-dom', 'reactjs', '"react"', '_reactjs_', 'react.production.min.js', 'react.development.js'],
    category: 'Web Frameworks',
    language: 'JavaScript'
  },
  'Vue.js': {
    patterns: ['vue.js', 'vue@', 'vue.min.js', 'vue.runtime', 'vue.common', 'vue.esm'],
    category: 'Web Frameworks',
    language: 'JavaScript'
  },
  'Angular': {
    patterns: ['angular.js', 'ng-app', 'ng-controller', 'angular.min.js', 'angular/core', '@angular'],
    category: 'Web Frameworks',
    language: 'JavaScript'
  },
  'jQuery': {
    patterns: ['jquery.js', 'jquery.min.js', '/jquery-', 'jquery/jquery', 'code.jquery'],
    category: 'JavaScript Libraries',
    language: 'JavaScript'
  },
  'Bootstrap': {
    patterns: ['bootstrap.css', 'bootstrap.min.css', 'bootstrap.bundle', 'bootstrap/dist', 'class="container"', 'class="row"', 'class="col-'],
    category: 'Web Frameworks',
    language: 'CSS'
  },
  'Tailwind CSS': {
    patterns: [
      'tailwind.css', 
      'tailwindcss', 
      'tailwind.min.css', 
      'class="tw-',
      'class="bg-', 
      'class="text-', 
      'class="flex',
      '/tailwind/',
      'tailwind.config.js',
      '@tailwind base',
      'tailwindcss/dist'
    ],
    category: 'CSS Frameworks',
    language: 'CSS'
  },
  'Nuxt.js': {
    patterns: [
      '__NUXT__',
      '/_nuxt/',
      '<nuxt-link',
      '"nuxt":',
      '@nuxtjs',
      'Nuxt.js',
      'window.$nuxt',
      'nuxt.config.js',
      '/_nuxt/commons.',
      'data-n-head',
      '<div id="__nuxt"'
    ],
    category: 'Web Frameworks',
    language: 'JavaScript'
  },
  'Next.js': {
    patterns: ['next.js', '__NEXT_DATA__', '/_next/', '"next":', 'next/link'],
    category: 'Web Frameworks',
    language: 'JavaScript'
  },
  
  // CMS
  'WordPress': {
    patterns: ['wp-content', 'wp-includes', 'wordpress', 'wp-json'],
    category: 'CMS',
    language: 'PHP'
  },
  'Drupal': {
    patterns: ['Drupal.settings', '/sites/default/files', 'drupal.js'],
    category: 'CMS',
    language: 'PHP'
  },
  'Joomla': {
    patterns: ['/administrator/index.php', 'joomla', 'com_content'],
    category: 'CMS',
    language: 'PHP'
  },
  'Shopify': {
    patterns: ['Shopify.', 'shopify', '.myshopify.com'],
    category: 'Ecommerce',
    language: 'Ruby'
  },
  'Magento': {
    patterns: ['magento', 'Mage.', '/skin/frontend/'],
    category: 'Ecommerce',
    language: 'PHP'
  },
  'WooCommerce': {
    patterns: ['woocommerce', 'wc-api', 'wc_add_to_cart'],
    category: 'Ecommerce',
    language: 'PHP'
  },
  
  // Back-end Technologies  
  'Laravel': {
    patterns: [
      // More specific Laravel patterns
      'laravel_session=',
      'XSRF-TOKEN',
      'X-XSRF-TOKEN',
      'Laravel Framework',
      'laravel.js',
      '/laravel/',
      'app/Http/Controllers',
      'Illuminate\\',
      'laravel.mix'
    ],
    category: 'Web Frameworks',
    language: 'PHP'
  },
  'Express.js': {
    patterns: ['express', 'express.js', 'expressjs'],
    category: 'Web Frameworks',
    language: 'JavaScript'
  },
  'Django': {
    patterns: ['django', 'csrftoken', 'csrfmiddlewaretoken'],
    category: 'Web Frameworks',
    language: 'Python'
  },
  'Ruby on Rails': {
    patterns: ['rails', 'ruby on rails', 'csrf-token'],
    category: 'Web Frameworks',
    language: 'Ruby'
  },
  'ASP.NET': {
    patterns: [
      // More specific ASP.NET patterns
      '__VIEWSTATE',
      '__EVENTVALIDATION',
      '.aspx',
      '.ashx',
      '.asmx',
      'ASP.NET_SessionId',
      'X-AspNet-Version',
      'X-AspNetMvc-Version'
    ],
    category: 'Web Frameworks',
    language: 'C#'
  },
  'Spring': {
    patterns: ['spring', 'spring.js', 'org.springframework'],
    category: 'Web Frameworks',
    language: 'Java'
  },
  
  // Web Servers
  'Apache': {
    patterns: ['apache', 'apache/'],
    category: 'Web Servers',
    language: ''
  },
  'Nginx': {
    patterns: ['nginx'],
    category: 'Web Servers',
    language: ''
  },
  'IIS': {
    patterns: ['iis', 'microsoft-iis', 'ms-iis'],
    category: 'Web Servers',
    language: ''
  },
  'Cloudflare': {
    patterns: ['cloudflare', 'cf-ray', '__cfduid'],
    category: 'CDN',
    language: ''
  },
  'Litespeed': {
    patterns: ['litespeed'],
    category: 'Web Servers',
    language: ''
  },
  
  // Languages
  'PHP': {
    patterns: [
      // More specific PHP patterns to reduce false positives
      '/index.php', 
      'phpinfo()', 
      'php_version', 
      'PHPSESSID=',
      'content="php"', 
      'Powered by PHP', 
      '.php?'
    ],
    category: 'Programming Languages',
    language: 'PHP'
  },
  'Node.js': {
    patterns: ['node.js', 'nodejs', 'node_modules'],
    category: 'Programming Languages',
    language: 'JavaScript'
  },
  'Python': {
    patterns: [
      // More specific Python patterns
      'python-requests', 
      'wsgi.py',
      'django.contrib',
      '.py?',
      'PYTHONPATH',
      'content="python"',
      'Powered by Python'
    ],
    category: 'Programming Languages',
    language: 'Python'
  },
  'Ruby': {
    patterns: ['ruby', '.rb', 'ruby on'],
    category: 'Programming Languages',
    language: 'Ruby'
  },
  'Java': {
    patterns: ['java', '.jsp', '.jar'],
    category: 'Programming Languages',
    language: 'Java'
  }
};

/**
 * Enhanced tech detection using pattern matching
 */
function detectTechByPatterns(html: string, headers: Record<string, string | string[]>): {
  technologies: Array<{name: string; categories: string[]; confidence: number; version?: string}>;
  frameworks: string[];
  languages: string[];
  servers: string[];
} {
  const technologies: Array<{name: string; categories: string[]; confidence: number; version?: string}> = [];
  const frameworks: Set<string> = new Set();
  const languages: Set<string> = new Set();
  const servers: Set<string> = new Set();
  
  // Convert headers to string for easier search
  const headersString = JSON.stringify(headers).toLowerCase();
  
  // Minimum confidence threshold required to include a technology
  const MIN_CONFIDENCE_THRESHOLD = 40;
  
  // Stronger weight for some pattern matches that are more definitive
  const STRONG_PATTERN_INDICATORS = [
    '__VIEWSTATE', // ASP.NET
    'PHPSESSID', // PHP
    'laravel_session=', // Laravel
    'wp-content', // WordPress
    'class="container"', // Bootstrap
    '/tailwind' // Tailwind
  ];
  
  // Detect technologies by patterns
  Object.entries(TECH_PATTERNS).forEach(([techName, techInfo]) => {
    // Calculate a score based on how many patterns are found
    let matchCount = 0;
    let strongMatchFound = false;
    let headerMatchFound = false;
    const htmlLower = html.toLowerCase();
    
    for (const pattern of techInfo.patterns) {
      const patternLower = pattern.toLowerCase();
      
      // Check in HTML content
      if (htmlLower.includes(patternLower)) {
        matchCount++;
        
        // Check if this is a strong indicator
        if (STRONG_PATTERN_INDICATORS.some(indicator => 
            patternLower.includes(indicator.toLowerCase()))) {
          strongMatchFound = true;
          matchCount += 2; // Bonus points for strong indicators
        }
      }
      
      // Check in headers
      if (headersString.includes(patternLower)) {
        headerMatchFound = true;
        matchCount += 2; // Headers are more reliable indicators
      }
    }
    
    // Adjust confidence calculation based on match strength
    let confidence = 0;
    
    if (matchCount > 0) {
      // Base confidence on matches
      confidence = Math.min(100, matchCount * 20); 
      
      // Bonus for header matches (very reliable)
      if (headerMatchFound) {
        confidence = Math.min(100, confidence + 30);
      }
      
      // Bonus for strong indicator matches
      if (strongMatchFound) {
        confidence = Math.min(100, confidence + 20);
      }
      
      // Only add technologies that meet the minimum confidence threshold
      if (confidence >= MIN_CONFIDENCE_THRESHOLD) {
        technologies.push({
          name: techName,
          categories: [techInfo.category],
          confidence: confidence
        });
        
        // Add to specific categories
        if (techInfo.category === 'Web Frameworks') {
          frameworks.add(techName);
        }
        
        if (techInfo.category === 'Web Servers') {
          servers.add(techName);
        }
        
        // Add associated language if present and confidence is high enough
        if (techInfo.language && confidence >= 60) {
          languages.add(techInfo.language);
        }
      }
    }
  });
  
  // Additional header-based detection
  
  // Server detection
  if (headers['server']) {
    const serverHeader = Array.isArray(headers['server']) 
      ? headers['server'][0] 
      : headers['server'];
    
    servers.add(serverHeader);
    
    if (!technologies.some(t => t.name === serverHeader)) {
      technologies.push({
        name: serverHeader,
        categories: ['Web Servers'],
        confidence: 100
      });
    }
  }
  
  // X-Powered-By detection
  if (headers['x-powered-by']) {
    const poweredBy = Array.isArray(headers['x-powered-by']) 
      ? headers['x-powered-by'][0] 
      : headers['x-powered-by'];
    
    const poweredByParts = poweredBy.split(', ');
    
    poweredByParts.forEach(tech => {
      if (!technologies.some(t => t.name === tech)) {
        technologies.push({
          name: tech,
          categories: ['Web Frameworks'],
          confidence: 90 // High but not absolute confidence
        });
      }
      
      // Extract specific technologies from X-Powered-By with verification
      const techLower = tech.toLowerCase();
      
      // Only add PHP if specifically mentioned in x-powered-by
      if (techLower.includes('php/') || techLower === 'php') {
        languages.add('PHP');
        
        // Look for version information
        const phpVersionMatch = techLower.match(/php\/([0-9.]+)/i);
        if (phpVersionMatch && !technologies.some(t => t.name === 'PHP')) {
          technologies.push({
            name: 'PHP',
            version: phpVersionMatch[1],
            categories: ['Programming Languages'],
            confidence: 95
          });
        }
      }
      
      // Only add ASP.NET if specifically mentioned
      if (techLower === 'asp.net' || techLower.includes('asp.net/')) {
        frameworks.add('ASP.NET');
        languages.add('C#');
        
        // Look for explicit version
        const aspVersionMatch = techLower.match(/asp\.net[/\s]+([0-9.]+)/i);
        if (aspVersionMatch && !technologies.some(t => t.name === 'ASP.NET')) {
          technologies.push({
            name: 'ASP.NET',
            version: aspVersionMatch[1],
            categories: ['Web Frameworks'],
            confidence: 95
          });
        }
      }
      
      // Explicit framework mentions
      if (techLower.includes('express/')) frameworks.add('Express.js');
      if (techLower.includes('node/')) languages.add('JavaScript');
      if (techLower.includes('nuxt/')) frameworks.add('Nuxt.js');
    });
  }
  
  // Extract generator meta tag
  const generatorMatch = html.match(/<meta\s+name=["']generator["']\s+content=["']([^"']+)["']/i);
  if (generatorMatch && generatorMatch[1]) {
    const generator = generatorMatch[1];
    
    if (!technologies.some(t => t.name === generator)) {
      technologies.push({
        name: generator,
        categories: ['CMS'],
        confidence: 100
      });
    }
    
    // Extract CMS from generator
    const generatorLower = generator.toLowerCase();
    if (generatorLower.includes('wordpress')) {
      frameworks.add('WordPress');
      languages.add('PHP');
    }
    if (generatorLower.includes('drupal')) {
      frameworks.add('Drupal');
      languages.add('PHP');
    }
    if (generatorLower.includes('joomla')) {
      frameworks.add('Joomla');
      languages.add('PHP');
    }
  }
  
  return {
    technologies,
    frameworks: Array.from(frameworks),
    languages: Array.from(languages),
    servers: Array.from(servers)
  };
}

/**
 * Validates and filters technology detection results
 * to remove low-confidence and duplicate entries
 */
function validateAndCleanResults(results: {
  technologies: Array<{name: string; categories: string[]; confidence: number; version?: string}>;
  frameworks: string[];
  languages: string[];
  servers: string[];
}) {
  // Filter out low confidence technologies
  results.technologies = results.technologies.filter(tech => tech.confidence >= 50);
  
  // De-duplicate technologies
  const techMap = new Map();
  results.technologies.forEach(tech => {
    const existingTech = techMap.get(tech.name);
    if (!existingTech || existingTech.confidence < tech.confidence) {
      techMap.set(tech.name, tech);
    }
  });
  results.technologies = Array.from(techMap.values());
  
  // Remove duplicate frameworks and ensure each exists in the technologies list
  results.frameworks = [...new Set(results.frameworks)].filter(framework => 
    results.technologies.some(tech => tech.name === framework || 
    // Handle Nuxt/Nuxt.js variation
    (tech.name === 'Nuxt.js' && framework === 'Nuxt') ||
    (tech.name === 'Nuxt' && framework === 'Nuxt.js'))
  );
  
  // Remove duplicate languages and validate against technologies
  const languagesWithTech = results.languages.filter(lang => {
    // Keep languages that have explicit technology matches
    return results.technologies.some(tech => 
      tech.categories.includes('Programming Languages') && tech.name === lang);
  });
  
  // Get languages from frameworks too (only highly confident ones)
  const languagesFromFrameworks = results.technologies
    .filter(tech => tech.categories.includes('Web Frameworks') && tech.confidence >= 75)
    .map(tech => {
      // Map frameworks to their typical languages
      switch(tech.name) {
        case 'ASP.NET': return 'C#';
        case 'Laravel': return 'PHP';
        case 'Django': return 'Python';
        case 'Nuxt.js': case 'Nuxt': case 'Vue.js': case 'React': case 'Angular': 
          return 'JavaScript';
        case 'Ruby on Rails': return 'Ruby';
        case 'Spring': return 'Java';
        default: return null;
      }
    })
    .filter(Boolean) as string[];
  
  // Combine and de-duplicate languages
  results.languages = [...new Set([...languagesWithTech, ...languagesFromFrameworks])];
  
  // Remove duplicate servers and validate
  results.servers = [...new Set(results.servers)].filter(server => 
    results.technologies.some(tech => tech.name === server || 
    // Handle IIS/Microsoft-IIS variation
    (tech.name.toLowerCase().includes('iis') && server.toLowerCase().includes('iis')))
  );
  
  return results;
}

/**
 * Detect technologies used on a website
 */
export const detectTechStack: Scanner<TechStackResult> = async (
  input: ScannerInput
) => {
  const startTime = Date.now();
  const normalizedInput = createScannerInput(input);
  
  try {
    // Import wappalyzer is done dynamically to handle both frontend/backend cases
    const Wappalyzer: any = {
      analyze: async () => []
    };
    let usingFallbackDetection = true;
    
    try {
      // This will work in Node.js environment
      // Use dynamic import for Node.js environments
      if (typeof window === 'undefined') {
        try {
          // eslint-disable-next-line @typescript-eslint/no-var-requires
          const wappalyzerCore = require('wappalyzer-core');
          if (wappalyzerCore && typeof wappalyzerCore.analyze === 'function') {
            // If available, use the real Wappalyzer
            Object.assign(Wappalyzer, wappalyzerCore);
            usingFallbackDetection = false;
          }
        } catch (err) {
          // Wappalyzer not installed, use fallback detection
          usingFallbackDetection = true;
        }
      } else {
        usingFallbackDetection = true;
      }
    } catch (e) {
      usingFallbackDetection = true;
    }
    
    // Make multiple requests to capture more context
    const mainPageRequest = makeRequest(normalizedInput.target, {
      method: 'GET',
      timeout: normalizedInput.timeout,
      headers: normalizedInput.headers
    });
      // Also try to fetch common JS files that might reveal technologies
    const defaultTimeout = normalizedInput.timeout || 10000;
    const jsRequest = makeRequest(`${normalizedInput.target}/main.js`, {
      method: 'GET',
      timeout: defaultTimeout / 2, // Shorter timeout for auxiliary requests
      headers: normalizedInput.headers
    }).catch(() => ({ data: '', headers: {}, status: 0, error: null }));
    
    const cssRequest = makeRequest(`${normalizedInput.target}/main.css`, {
      method: 'GET',
      timeout: defaultTimeout / 2,
      headers: normalizedInput.headers
    }).catch(() => ({ data: '', headers: {}, status: 0, error: null }));
    
    // Wait for the main page response
    const response = await mainPageRequest;
    const [jsResponse, cssResponse] = await Promise.all([jsRequest, cssRequest]);
    
    if (response.error || !response.data) {
      return {
        status: 'failure',
        scanner: 'techStack',
        error: response.error || 'Failed to retrieve website content',
        data: {
          technologies: [],
          frameworks: [],
          languages: [],
          servers: []
        },
        timeTaken: Date.now() - startTime
      };
    }
    
    // Combine HTML from main page with JS and CSS for better detection
    let html = typeof response.data === 'string' ? response.data : String(response.data);
    const jsContent = typeof jsResponse.data === 'string' ? jsResponse.data : String(jsResponse.data || '');
    const cssContent = typeof cssResponse.data === 'string' ? cssResponse.data : String(cssResponse.data || '');
    
    // Combine all content for pattern matching
    const combinedContent = html + ' ' + jsContent + ' ' + cssContent;
    const headers = response.headers;
    
    let technologies: Array<{
      name: string;
      version?: string;
      categories: string[];
      confidence: number;
    }> = [];
    
    let frameworks: string[] = [];
    let languages: string[] = [];
    let servers: string[] = [];
    
    if (!usingFallbackDetection) {
      // Use Wappalyzer when available
      const wappalyzerInput = {
        url: normalizedInput.target,
        html,
        headers: headers
      };
      
      // Analyze with Wappalyzer
      const detectedTechnologies = await Wappalyzer.analyze(wappalyzerInput);
      
      // Process results
      technologies = detectedTechnologies.map((tech: any) => ({
        name: tech.name,
        version: tech.version,
        categories: tech.categories.map((cat: any) => cat.name),
        confidence: tech.confidence
      }));
      
      // Extract frameworks, languages, servers
      technologies.forEach((tech: { 
        name: string; 
        categories: string[]; 
      }) => {
        if (tech.categories.includes('Web Frameworks')) {
          frameworks.push(tech.name);
        }
        
        if (tech.categories.includes('Programming Languages')) {
          languages.push(tech.name);
        }
        
        if (tech.categories.includes('Web Servers')) {
          servers.push(tech.name);
        }
      });
      
      // If Wappalyzer didn't find anything, fall back to our pattern detection
      if (technologies.length === 0) {
        usingFallbackDetection = true;
      }
    }
    
    // Use our pattern-based detection if Wappalyzer didn't work or found nothing
    if (usingFallbackDetection) {
      const patternResults = detectTechByPatterns(combinedContent, headers);
      technologies = patternResults.technologies;
      frameworks = patternResults.frameworks;
      languages = patternResults.languages;
      servers = patternResults.servers;
    }
    
    // Validate and clean up results to improve accuracy
    const cleanedResults = validateAndCleanResults({
      technologies,
      frameworks,
      languages,
      servers
    });
    
    return {
      status: 'success',
      scanner: 'techStack',
      data: {
        technologies: cleanedResults.technologies,
        frameworks: cleanedResults.frameworks,
        languages: cleanedResults.languages,
        servers: cleanedResults.servers
      },
      timeTaken: Date.now() - startTime
    };
  } catch (error) {
    return {
      status: 'failure',
      scanner: 'techStack',
      error: (error as Error).message || 'Unknown error',
      data: {
        technologies: [],
        frameworks: [],
        languages: [],
        servers: []
      },
      timeTaken: Date.now() - startTime
    };
  }
};
