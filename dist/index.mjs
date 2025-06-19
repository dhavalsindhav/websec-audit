import axios from 'axios';
import * as cheerio from 'cheerio';
import * as tls from 'tls';
import * as net from 'net';
import * as dns2 from 'dns';
import * as crypto from 'crypto';
import { promisify } from 'util';

var __getOwnPropNames = Object.getOwnPropertyNames;
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};

// node_modules/wappalyzer-core/wappalyzer.js
var require_wappalyzer = __commonJS({
  "node_modules/wappalyzer-core/wappalyzer.js"(exports, module) {
    function toArray(value) {
      return Array.isArray(value) ? value : [value];
    }
    var benchmarkEnabled = typeof process !== "undefined" ? !!process.env.WAPPALYZER_BENCHMARK : false;
    var benchmarks = [];
    function benchmark(duration, pattern, value = "", technology) {
      if (!benchmarkEnabled) {
        return;
      }
      benchmarks.push({
        duration,
        pattern: String(pattern.regex),
        value: String(value).slice(0, 100),
        valueLength: value.length,
        technology: technology.name
      });
    }
    function benchmarkSummary() {
      if (!benchmarkEnabled) {
        return;
      }
      const totalPatterns = Object.values(benchmarks).length;
      const totalDuration = Object.values(benchmarks).reduce(
        (sum, { duration }) => sum + duration,
        0
      );
      console.log({
        totalPatterns,
        totalDuration,
        averageDuration: Math.round(totalDuration / totalPatterns),
        slowestTechnologies: Object.values(
          benchmarks.reduce((benchmarks2, { duration, technology }) => {
            if (benchmarks2[technology]) {
              benchmarks2[technology].duration += duration;
            } else {
              benchmarks2[technology] = { technology, duration };
            }
            return benchmarks2;
          }, {})
        ).sort(({ duration: a }, { duration: b }) => a > b ? -1 : 1).filter(({ duration }) => duration).slice(0, 5).reduce(
          (technologies, { technology, duration }) => ({
            ...technologies,
            [technology]: duration
          }),
          {}
        ),
        slowestPatterns: Object.values(benchmarks).sort(({ duration: a }, { duration: b }) => a > b ? -1 : 1).filter(({ duration }) => duration).slice(0, 5)
      });
    }
    var Wappalyzer = {
      technologies: [],
      categories: [],
      requires: [],
      categoryRequires: [],
      slugify: (string) => string.toLowerCase().replace(/[^a-z0-9-]/g, "-").replace(/--+/g, "-").replace(/(?:^-|-$)/g, ""),
      getTechnology: (name) => [
        ...Wappalyzer.technologies,
        ...Wappalyzer.requires.map(({ technologies }) => technologies).flat(),
        ...Wappalyzer.categoryRequires.map(({ technologies }) => technologies).flat()
      ].find(({ name: _name }) => name === _name),
      getCategory: (id) => Wappalyzer.categories.find(({ id: _id }) => id === _id),
      /**
       * Resolve promises for implied technology.
       * @param {Array} detections
       */
      resolve(detections = []) {
        const resolved = detections.reduce((resolved2, { technology, lastUrl }) => {
          if (resolved2.findIndex(
            ({ technology: { name } }) => name === technology?.name
          ) === -1) {
            let version = "";
            let confidence = 0;
            let rootPath;
            detections.filter(
              ({ technology: _technology }) => _technology && _technology.name === technology.name
            ).forEach(
              ({
                technology: { name },
                pattern,
                version: _version = "",
                rootPath: _rootPath
              }) => {
                confidence = Math.min(100, confidence + pattern.confidence);
                version = _version.length > version.length && _version.length <= 15 && (parseInt(_version, 10) || 0) < 1e4 ? _version : version;
                rootPath = rootPath || _rootPath || void 0;
              }
            );
            resolved2.push({ technology, confidence, version, rootPath, lastUrl });
          }
          return resolved2;
        }, []);
        Wappalyzer.resolveExcludes(resolved);
        Wappalyzer.resolveImplies(resolved);
        const priority = ({ technology: { categories } }) => categories.reduce(
          (max, id) => Math.max(max, Wappalyzer.getCategory(id).priority),
          0
        );
        return resolved.sort((a, b) => priority(a) > priority(b) ? 1 : -1).map(
          ({
            technology: {
              name,
              description,
              slug,
              categories,
              icon,
              website,
              pricing,
              cpe
            },
            confidence,
            version,
            rootPath,
            lastUrl
          }) => ({
            name,
            description,
            slug,
            categories: categories.map((id) => Wappalyzer.getCategory(id)),
            confidence,
            version,
            icon,
            website,
            pricing,
            cpe,
            rootPath,
            lastUrl
          })
        );
      },
      /**
       * Resolve promises for version of technology.
       * @param {Promise} resolved
       * @param match
       */
      resolveVersion({ version, regex }, match) {
        let resolved = version;
        if (version) {
          const matches = regex.exec(match);
          if (matches) {
            matches.forEach((match2, index) => {
              if (String(match2).length > 10) {
                return;
              }
              const ternary = new RegExp(`\\\\${index}\\?([^:]+):(.*)$`).exec(
                version
              );
              if (ternary && ternary.length === 3) {
                resolved = version.replace(
                  ternary[0],
                  match2 ? ternary[1] : ternary[2]
                );
              }
              resolved = resolved.trim().replace(new RegExp(`\\\\${index}`, "g"), match2 || "");
            });
            resolved = resolved.replace(/\\\d/, "");
          }
        }
        return resolved;
      },
      /**
       * Resolve promises for excluded technology.
       * @param {Promise} resolved
       */
      resolveExcludes(resolved) {
        resolved.forEach(({ technology }) => {
          technology.excludes.forEach(({ name }) => {
            const excluded = Wappalyzer.getTechnology(name);
            if (!excluded) {
              throw new Error(`Excluded technology does not exist: ${name}`);
            }
            let index;
            do {
              index = resolved.findIndex(
                ({ technology: { name: name2 } }) => name2 === excluded.name
              );
              if (index !== -1) {
                resolved.splice(index, 1);
              }
            } while (index !== -1);
          });
        });
      },
      /**
       * Resolve promises for implied technology.
       * @param {Promise} resolved
       */
      resolveImplies(resolved) {
        let done = false;
        do {
          done = true;
          resolved.forEach(({ technology, confidence, lastUrl }) => {
            technology.implies.forEach(
              ({ name, confidence: _confidence, version }) => {
                const implied = Wappalyzer.getTechnology(name);
                if (!implied) {
                  throw new Error(`Implied technology does not exist: ${name}`);
                }
                if (resolved.findIndex(
                  ({ technology: { name: name2 } }) => name2 === implied.name
                ) === -1) {
                  resolved.push({
                    technology: implied,
                    confidence: Math.min(confidence, _confidence),
                    version: version || "",
                    lastUrl
                  });
                  done = false;
                }
              }
            );
          });
        } while (resolved.length && !done);
      },
      /**
       * Initialize analyzation.
       * @param {*} param0
       */
      analyze(items, technologies = Wappalyzer.technologies) {
        benchmarks = [];
        const oo = Wappalyzer.analyzeOneToOne;
        const om = Wappalyzer.analyzeOneToMany;
        const mm = Wappalyzer.analyzeManyToMany;
        const relations = {
          certIssuer: oo,
          cookies: mm,
          css: oo,
          dns: mm,
          headers: mm,
          html: oo,
          meta: mm,
          probe: mm,
          robots: oo,
          scriptSrc: om,
          scripts: oo,
          text: oo,
          url: oo,
          xhr: oo
        };
        try {
          const detections = technologies.map(
            (technology) => Object.keys(relations).map(
              (type) => items[type] && relations[type](technology, type, items[type])
            ).flat()
          ).flat().filter((technology) => technology);
          benchmarkSummary();
          return detections;
        } catch (error) {
          throw new Error(error.message || error.toString());
        }
      },
      /**
       * Extract technologies from data collected.
       * @param {object} data
       */
      setTechnologies(data) {
        const transform = Wappalyzer.transformPatterns;
        Wappalyzer.technologies = Object.keys(data).reduce((technologies, name) => {
          const {
            cats,
            certIssuer,
            cookies,
            cpe,
            css,
            description,
            dns: dns3,
            dom,
            excludes,
            headers,
            html,
            icon,
            implies,
            js,
            meta,
            pricing,
            probe,
            requires,
            requiresCategory,
            robots,
            scriptSrc,
            scripts,
            text,
            url,
            website,
            xhr
          } = data[name];
          technologies.push({
            categories: cats || [],
            certIssuer: transform(certIssuer),
            cookies: transform(cookies),
            cpe: cpe || null,
            css: transform(css),
            description: description || null,
            dns: transform(dns3),
            dom: transform(
              typeof dom === "string" || Array.isArray(dom) ? toArray(dom).reduce(
                (dom2, selector) => ({ ...dom2, [selector]: { exists: "" } }),
                {}
              ) : dom,
              true,
              false
            ),
            excludes: transform(excludes).map(({ value }) => ({ name: value })),
            headers: transform(headers),
            html: transform(html),
            icon: icon || "default.svg",
            implies: transform(implies).map(({ value, confidence, version }) => ({
              name: value,
              confidence,
              version
            })),
            js: transform(js, true),
            meta: transform(meta),
            name,
            pricing: pricing || [],
            probe: transform(probe, true),
            requires: transform(requires).map(({ value }) => ({ name: value })),
            requiresCategory: transform(requiresCategory).map(({ value }) => ({
              id: value
            })),
            robots: transform(robots),
            scriptSrc: transform(scriptSrc),
            scripts: transform(scripts),
            slug: Wappalyzer.slugify(name),
            text: transform(text),
            url: transform(url),
            website: website || null,
            xhr: transform(xhr)
          });
          return technologies;
        }, []);
        Wappalyzer.technologies.filter(({ requires }) => requires.length).forEach(
          (technology) => technology.requires.forEach(({ name }) => {
            if (!Wappalyzer.getTechnology(name)) {
              throw new Error(`Required technology does not exist: ${name}`);
            }
            Wappalyzer.requires[name] = Wappalyzer.requires[name] || [];
            Wappalyzer.requires[name].push(technology);
          })
        );
        Wappalyzer.requires = Object.keys(Wappalyzer.requires).map((name) => ({
          name,
          technologies: Wappalyzer.requires[name]
        }));
        Wappalyzer.technologies.filter(({ requiresCategory }) => requiresCategory.length).forEach(
          (technology) => technology.requiresCategory.forEach(({ id }) => {
            Wappalyzer.categoryRequires[id] = Wappalyzer.categoryRequires[id] || [];
            Wappalyzer.categoryRequires[id].push(technology);
          })
        );
        Wappalyzer.categoryRequires = Object.keys(Wappalyzer.categoryRequires).map(
          (id) => ({
            categoryId: parseInt(id, 10),
            technologies: Wappalyzer.categoryRequires[id]
          })
        );
        Wappalyzer.technologies = Wappalyzer.technologies.filter(
          ({ requires, requiresCategory }) => !requires.length && !requiresCategory.length
        );
      },
      /**
       * Assign categories for data.
       * @param {Object} data
       */
      setCategories(data) {
        Wappalyzer.categories = Object.keys(data).reduce((categories, id) => {
          const category = data[id];
          categories.push({
            id: parseInt(id, 10),
            slug: Wappalyzer.slugify(category.name),
            ...category
          });
          return categories;
        }, []).sort(({ priority: a }, { priority: b }) => a > b ? -1 : 0);
      },
      /**
       * Transform patterns for internal use.
       * @param {string|array} patterns
       * @param {boolean} caseSensitive
       */
      transformPatterns(patterns, caseSensitive = false, isRegex = true) {
        if (!patterns) {
          return [];
        }
        if (typeof patterns === "string" || typeof patterns === "number" || Array.isArray(patterns)) {
          patterns = { main: patterns };
        }
        const parsed = Object.keys(patterns).reduce((parsed2, key) => {
          parsed2[caseSensitive ? key : key.toLowerCase()] = toArray(
            patterns[key]
          ).map((pattern) => Wappalyzer.parsePattern(pattern, isRegex));
          return parsed2;
        }, {});
        return "main" in parsed ? parsed.main : parsed;
      },
      /**
       * Extract information from regex pattern.
       * @param {string|object} pattern
       */
      parsePattern(pattern, isRegex = true) {
        if (typeof pattern === "object") {
          return Object.keys(pattern).reduce(
            (parsed, key) => ({
              ...parsed,
              [key]: Wappalyzer.parsePattern(pattern[key])
            }),
            {}
          );
        } else {
          const { value, regex, confidence, version } = pattern.toString().split("\\;").reduce((attrs, attr, i) => {
            if (i) {
              attr = attr.split(":");
              if (attr.length > 1) {
                attrs[attr.shift()] = attr.join(":");
              }
            } else {
              attrs.value = typeof pattern === "number" ? pattern : attr;
              attrs.regex = new RegExp(
                isRegex ? attr.replace(/\//g, "\\/").replace(/\\\+/g, "__escapedPlus__").replace(/\+/g, "{1,250}").replace(/\*/g, "{0,250}").replace(/__escapedPlus__/g, "\\+") : "",
                "i"
              );
            }
            return attrs;
          }, {});
          return {
            value,
            regex,
            confidence: parseInt(confidence || 100, 10),
            version: version || ""
          };
        }
      },
      /**
       * @todo describe
       * @param {Object} technology
       * @param {String} type
       * @param {String} value
       */
      analyzeOneToOne(technology, type, value) {
        return technology[type].reduce((technologies, pattern) => {
          const startTime = Date.now();
          const matches = pattern.regex.exec(value);
          if (matches) {
            technologies.push({
              technology,
              pattern: {
                ...pattern,
                type,
                value,
                match: matches[0]
              },
              version: Wappalyzer.resolveVersion(pattern, value)
            });
          }
          benchmark(Date.now() - startTime, pattern, value, technology);
          return technologies;
        }, []);
      },
      /**
       * @todo update
       * @param {Object} technology
       * @param {String} type
       * @param {Array} items
       */
      analyzeOneToMany(technology, type, items = []) {
        return items.reduce((technologies, value) => {
          const patterns = technology[type] || [];
          patterns.forEach((pattern) => {
            const startTime = Date.now();
            const matches = pattern.regex.exec(value);
            if (matches) {
              technologies.push({
                technology,
                pattern: {
                  ...pattern,
                  type,
                  value,
                  match: matches[0]
                },
                version: Wappalyzer.resolveVersion(pattern, value)
              });
            }
            benchmark(Date.now() - startTime, pattern, value, technology);
          });
          return technologies;
        }, []);
      },
      /**
       *
       * @param {Object} technology
       * @param {string} types
       * @param {Array} items
       */
      analyzeManyToMany(technology, types, items = {}) {
        const [type, ...subtypes] = types.split(".");
        return Object.keys(technology[type]).reduce((technologies, key) => {
          const patterns = technology[type][key] || [];
          const values = items[key] || [];
          patterns.forEach((_pattern) => {
            const pattern = (subtypes || []).reduce(
              (pattern2, subtype) => pattern2[subtype] || {},
              _pattern
            );
            values.forEach((value) => {
              const startTime = Date.now();
              const matches = pattern.regex.exec(value);
              if (matches) {
                technologies.push({
                  technology,
                  pattern: {
                    ...pattern,
                    type,
                    value,
                    match: matches[0]
                  },
                  version: Wappalyzer.resolveVersion(pattern, value)
                });
              }
              benchmark(Date.now() - startTime, pattern, value, technology);
            });
          });
          return technologies;
        }, []);
      }
    };
    if (typeof module !== "undefined") {
      module.exports = Wappalyzer;
    }
  }
});
var makeRequest = async (url, options) => {
  try {
    const config = {
      url,
      method: options?.method || "GET",
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
        ...options?.headers
      },
      timeout: options?.timeout || 1e4,
      // Default 10s timeout
      data: options?.data,
      validateStatus: () => true
      // Don't throw on any HTTP status code
    };
    const response = await axios(config);
    return {
      status: response.status,
      headers: response.headers,
      data: response.data,
      error: null
    };
  } catch (error) {
    return {
      status: 0,
      headers: {},
      data: null,
      error: error.message || "Request failed"
    };
  }
};
var normalizeUrl = (input) => {
  if (!input)
    return "";
  let url = input;
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "https://" + url;
  }
  try {
    const parsed = new URL(url);
    return parsed.origin;
  } catch (e) {
    return url;
  }
};
var extractDomain = (url) => {
  try {
    const parsed = new URL(normalizeUrl(url));
    let domain = parsed.hostname;
    if (domain.startsWith("www.")) {
      domain = domain.substring(4);
    }
    return domain;
  } catch (e) {
    return url.replace(/^(https?:\/\/)?(www\.)?/, "").split("/")[0];
  }
};
var safeJsonParse = (text) => {
  try {
    return JSON.parse(text);
  } catch (e) {
    return null;
  }
};
var createScannerInput = (target) => {
  if (typeof target === "string") {
    return {
      target: normalizeUrl(target),
      timeout: 1e4
    };
  }
  return {
    ...target,
    target: normalizeUrl(target.target)
  };
};

// src/modules/securityHeaders.ts
var SECURITY_HEADERS = {
  "strict-transport-security": {
    description: "HTTP Strict Transport Security (HSTS) enforces secure (HTTPS) connections",
    severity: "high"
  },
  "content-security-policy": {
    description: "Content Security Policy prevents XSS and data injection attacks",
    severity: "high"
  },
  "x-content-type-options": {
    description: "X-Content-Type-Options prevents MIME-sniffing",
    severity: "medium"
  },
  "x-frame-options": {
    description: "X-Frame-Options protects against clickjacking",
    severity: "medium"
  },
  "x-xss-protection": {
    description: "X-XSS-Protection enables the cross-site scripting filter",
    severity: "medium"
  },
  "referrer-policy": {
    description: "Referrer Policy controls how much information is sent in the Referer header",
    severity: "low"
  },
  "permissions-policy": {
    description: "Permissions Policy controls which browser features can be used",
    severity: "low"
  },
  "cross-origin-embedder-policy": {
    description: "Cross-Origin Embedder Policy prevents loading cross-origin resources",
    severity: "low"
  },
  "cross-origin-opener-policy": {
    description: "Cross-Origin Opener Policy prevents opening cross-origin windows",
    severity: "low"
  },
  "cross-origin-resource-policy": {
    description: "Cross-Origin Resource Policy prevents cross-origin loading",
    severity: "low"
  }
};
var scanSecurityHeaders = async (input) => {
  const startTime = Date.now();
  const normalizedInput = createScannerInput(input);
  try {
    const response = await makeRequest(normalizedInput.target, {
      method: "HEAD",
      timeout: normalizedInput.timeout,
      headers: normalizedInput.headers
    });
    if (response.error || !response.headers) {
      return {
        status: "failure",
        scanner: "securityHeaders",
        error: response.error || "Failed to retrieve headers",
        data: {
          headers: {},
          missing: Object.keys(SECURITY_HEADERS),
          issues: [],
          score: 0
        },
        timeTaken: Date.now() - startTime
      };
    }
    const headers = {};
    const headerNames = Object.keys(response.headers);
    headerNames.forEach((name) => {
      headers[name.toLowerCase()] = response.headers[name];
    });
    const missing = [];
    const issues = [];
    Object.keys(SECURITY_HEADERS).forEach((header) => {
      if (!headers[header]) {
        missing.push(header);
        issues.push({
          severity: SECURITY_HEADERS[header].severity,
          header,
          description: `Missing ${header} header. ${SECURITY_HEADERS[header].description}`
        });
      }
    });
    const totalHeaders = Object.keys(SECURITY_HEADERS).length;
    const presentHeaders = totalHeaders - missing.length;
    const score = Math.round(presentHeaders / totalHeaders * 100);
    if (headers["strict-transport-security"] && !headers["strict-transport-security"].includes("max-age=")) {
      issues.push({
        severity: "medium",
        header: "strict-transport-security",
        description: "HSTS header does not include max-age directive"
      });
    }
    if (headers["x-frame-options"] && !["DENY", "SAMEORIGIN"].includes(headers["x-frame-options"].toUpperCase())) {
      issues.push({
        severity: "medium",
        header: "x-frame-options",
        description: "X-Frame-Options should be set to DENY or SAMEORIGIN"
      });
    }
    return {
      status: "success",
      scanner: "securityHeaders",
      data: {
        headers,
        missing,
        issues,
        score
      },
      timeTaken: Date.now() - startTime
    };
  } catch (error) {
    return {
      status: "failure",
      scanner: "securityHeaders",
      error: error.message || "Unknown error",
      data: {
        headers: {},
        missing: Object.keys(SECURITY_HEADERS),
        issues: [],
        score: 0
      },
      timeTaken: Date.now() - startTime
    };
  }
};
var detectForms = async (input) => {
  const startTime = Date.now();
  const normalizedInput = createScannerInput(input);
  try {
    let html;
    if (normalizedInput.options?.html) {
      html = normalizedInput.options.html;
    } else {
      const response = await makeRequest(normalizedInput.target, {
        method: "GET",
        timeout: normalizedInput.timeout,
        headers: normalizedInput.headers
      });
      if (response.error || !response.data) {
        return {
          status: "failure",
          scanner: "formDetection",
          error: response.error || "Failed to retrieve HTML content",
          data: { forms: [], total: 0 },
          timeTaken: Date.now() - startTime
        };
      }
      html = typeof response.data === "string" ? response.data : String(response.data);
    }
    const $ = cheerio.load(html);
    const forms = $("form");
    const formResults = [];
    forms.each((_i, formElement) => {
      const form = $(formElement);
      const action = form.attr("action") || "";
      const method = (form.attr("method") || "get").toLowerCase();
      const inputs = [];
      const formInputs = form.find('input, select, textarea, button[type="submit"]');
      formInputs.each((_j, inputElement) => {
        const input2 = $(inputElement);
        const type = input2.attr("type") || "text";
        inputs.push({
          name: input2.attr("name"),
          type,
          id: input2.attr("id"),
          required: input2.attr("required") !== void 0,
          autocomplete: input2.attr("autocomplete")
        });
      });
      const hasPassword = inputs.some((input2) => input2.type === "password");
      const hasCSRF = inputs.some((input2) => {
        const name = (input2.name || "").toLowerCase();
        return name.includes("csrf") || name.includes("token") || name.includes("nonce") || name === "_token";
      });
      const issues = [];
      if (hasPassword) {
        if (method !== "post") {
          issues.push({
            severity: "high",
            description: "Login form uses insecure method (GET). Should use POST to prevent credentials in URL."
          });
        }
        if (!hasCSRF) {
          issues.push({
            severity: "high",
            description: "Form appears to be missing CSRF protection token."
          });
        }
        if (action && action.startsWith("http:")) {
          issues.push({
            severity: "high",
            description: "Form submits to insecure (HTTP) endpoint."
          });
        }
        const passwordInputs = inputs.filter((input2) => input2.type === "password");
        if (passwordInputs.some((input2) => input2.autocomplete !== "off" && input2.autocomplete !== "new-password")) {
          issues.push({
            severity: "medium",
            description: `Password field doesn't have autocomplete="off" or autocomplete="new-password".`
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
      status: "success",
      scanner: "formDetection",
      data: {
        forms: formResults,
        total: formResults.length
      },
      timeTaken: Date.now() - startTime
    };
  } catch (error) {
    return {
      status: "failure",
      scanner: "formDetection",
      error: error.message || "Unknown error",
      data: { forms: [], total: 0 },
      timeTaken: Date.now() - startTime
    };
  }
};

// src/modules/sensitiveFiles.ts
var SENSITIVE_PATHS = [
  "/.git/config",
  "/.env",
  "/.env.local",
  "/.env.development",
  "/.env.production",
  "/config.json",
  "/config.js",
  "/config.php",
  "/wp-config.php",
  "/config.xml",
  "/credentials.json",
  "/secrets.json",
  "/settings.json",
  "/database.yml",
  "/db.sqlite",
  "/backup.zip",
  "/backup.sql",
  "/backup.tar.gz",
  "/dump.sql",
  "/users.sql",
  "/users.csv",
  "/phpinfo.php",
  "/info.php",
  "/.htpasswd",
  "/server-status",
  "/server-info",
  "/readme.md",
  "/README.md",
  "/api/swagger",
  "/api/docs",
  "/swagger.json",
  "/swagger-ui.html",
  "/robots.txt",
  "/sitemap.xml",
  "/.well-known/security.txt"
];
var scanSensitiveFiles = async (input) => {
  const startTime = Date.now();
  const normalizedInput = createScannerInput(input);
  const baseUrl = normalizeUrl(normalizedInput.target);
  const timeout = normalizedInput.timeout || 5e3;
  const exposedFiles = [];
  const issues = [];
  try {
    let pathsToTest = [...SENSITIVE_PATHS];
    if (normalizedInput.options?.additionalPaths) {
      pathsToTest = pathsToTest.concat(normalizedInput.options.additionalPaths);
    }
    const concurrentLimit = normalizedInput.options?.concurrentLimit || 5;
    const chunks = [];
    for (let i = 0; i < pathsToTest.length; i += concurrentLimit) {
      chunks.push(pathsToTest.slice(i, i + concurrentLimit));
    }
    for (const chunk of chunks) {
      const promises = chunk.map((path) => {
        const url = baseUrl + path;
        return makeRequest(url, {
          method: "GET",
          timeout,
          headers: normalizedInput.headers
        }).then((response) => {
          if (response.error) {
            return;
          }
          if (response.status >= 200 && response.status < 400) {
            let contentTypeHeader = response.headers["content-type"];
            const contentType = Array.isArray(contentTypeHeader) ? contentTypeHeader.join(", ") : contentTypeHeader || void 0;
            const contentLength = response.headers["content-length"] ? parseInt(
              Array.isArray(response.headers["content-length"]) ? response.headers["content-length"][0] : response.headers["content-length"],
              10
            ) : void 0;
            const hasContent = response.data && (typeof response.data === "string" ? response.data.length > 50 : true);
            const isDefaultPage = typeof response.data === "string" && (response.data.includes("<html") && response.data.includes("</html>") && response.data.includes("<title>Index of") === false);
            if (isDefaultPage && !contentLength) {
              return;
            }
            exposedFiles.push({
              path,
              status: response.status,
              contentType,
              size: contentLength
            });
            let severity = "medium";
            let description = `Exposed file: ${path}`;
            if (path.includes(".env") || path.includes("config") || path.includes("credential") || path.includes("secret") || path.includes("password") || path.includes(".git/") || path.includes("backup") || path.includes("dump")) {
              severity = "high";
              description = `Critical file exposed: ${path}. May contain sensitive information or credentials.`;
            } else if (path.includes("readme") || path.includes("robots.txt") || path.includes("sitemap.xml") || path.includes(".well-known")) {
              severity = "low";
              description = `Information disclosure: ${path}. May reveal system information.`;
            }
            issues.push({ severity, path, description });
          }
        }).catch((error) => {
          if (normalizedInput.options?.debug) {
            console.error(`Error scanning ${url}: ${error.message}`);
          }
        });
      });
      await Promise.all(promises);
    }
    return {
      status: "success",
      scanner: "sensitiveFiles",
      data: {
        exposedFiles,
        issues
      },
      timeTaken: Date.now() - startTime
    };
  } catch (error) {
    return {
      status: "failure",
      scanner: "sensitiveFiles",
      error: error.message || "Unknown error",
      data: {
        exposedFiles: [],
        issues: []
      },
      timeTaken: Date.now() - startTime
    };
  }
};

// src/modules/subdomains.ts
var scanSubdomains = async (input) => {
  const startTime = Date.now();
  const normalizedInput = createScannerInput(input);
  const domain = extractDomain(normalizedInput.target);
  try {
    const crtShUrl = `https://crt.sh/?q=%.${domain}&output=json`;
    const response = await makeRequest(crtShUrl, {
      method: "GET",
      timeout: normalizedInput.timeout || 15e3,
      // Increase default timeout for crt.sh
      headers: {
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"
      }
    });
    if (response.error) {
      return {
        status: "failure",
        scanner: "subdomains",
        error: `Failed to retrieve certificate data: ${response.error}`,
        data: {
          subdomains: [],
          total: 0
        },
        timeTaken: Date.now() - startTime
      };
    }
    let crtData = [];
    if (typeof response.data === "string") {
      try {
        const cleanJson = response.data.trim().replace(/\n/g, "");
        crtData = JSON.parse(cleanJson);
      } catch (e) {
        if (response.data.includes("<HTML>") || response.data.includes("<html>")) {
          return {
            status: "failure",
            scanner: "subdomains",
            error: "crt.sh returned HTML instead of JSON. Try again later.",
            data: {
              subdomains: [],
              total: 0
            },
            timeTaken: Date.now() - startTime
          };
        }
        console.error("JSON Parse Error:", e);
        console.error("Response data sample:", response.data.substring(0, 200));
        return {
          status: "failure",
          scanner: "subdomains",
          error: `Failed to parse certificate data: ${e.message}`,
          data: {
            subdomains: [],
            total: 0
          },
          timeTaken: Date.now() - startTime
        };
      }
    } else if (Array.isArray(response.data)) {
      crtData = response.data;
    } else if (response.data && typeof response.data === "object") {
      crtData = [response.data];
    }
    if (!crtData || crtData.length === 0) {
      return {
        status: "failure",
        scanner: "subdomains",
        error: "No certificate data found for this domain",
        data: {
          subdomains: [],
          total: 0
        },
        timeTaken: Date.now() - startTime
      };
    }
    const allDomains = /* @__PURE__ */ new Set();
    crtData.forEach((cert) => {
      if (cert && cert.name_value) {
        const name = cert.name_value.toLowerCase();
        const domains = name.split(/[,\s]+/);
        domains.forEach((d) => {
          const cleanDomain = d.trim();
          if (cleanDomain.endsWith("." + domain) && cleanDomain !== domain) {
            allDomains.add(cleanDomain);
          }
        });
      }
    });
    const subdomains = Array.from(allDomains).sort();
    if (normalizedInput.options?.checkLive === true) {
      const liveSubdomains = [];
      const concurrentLimit = normalizedInput.options?.concurrentLimit || 5;
      const chunks = [];
      for (let i = 0; i < subdomains.length; i += concurrentLimit) {
        chunks.push(subdomains.slice(i, i + concurrentLimit));
      }
      for (const chunk of chunks) {
        const promises = chunk.map((subdomain) => {
          return makeRequest(`https://${subdomain}`, {
            method: "HEAD",
            timeout: 5e3
            // Short timeout for live checks
          }).then((resp) => {
            if (!resp.error) {
              liveSubdomains.push({
                domain: subdomain,
                status: resp.status
              });
            }
          }).catch(() => {
          });
        });
        await Promise.all(promises);
      }
      return {
        status: "success",
        scanner: "subdomains",
        data: {
          subdomains,
          total: subdomains.length,
          live: liveSubdomains
        },
        timeTaken: Date.now() - startTime
      };
    }
    return {
      status: "success",
      scanner: "subdomains",
      data: {
        subdomains,
        total: subdomains.length
      },
      timeTaken: Date.now() - startTime
    };
  } catch (error) {
    return {
      status: "failure",
      scanner: "subdomains",
      error: error.message || "Unknown error",
      data: {
        subdomains: [],
        total: 0
      },
      timeTaken: Date.now() - startTime
    };
  }
};

// src/modules/techStack.ts
var TECH_PATTERNS = {
  // Front-end Frameworks
  "React": {
    patterns: ["react.js", "react-dom", "reactjs", '"react"', "_reactjs_", "react.production.min.js", "react.development.js"],
    category: "Web Frameworks",
    language: "JavaScript"
  },
  "Vue.js": {
    patterns: ["vue.js", "vue@", "vue.min.js", "vue.runtime", "vue.common", "vue.esm"],
    category: "Web Frameworks",
    language: "JavaScript"
  },
  "Angular": {
    patterns: ["angular.js", "ng-app", "ng-controller", "angular.min.js", "angular/core", "@angular"],
    category: "Web Frameworks",
    language: "JavaScript"
  },
  "jQuery": {
    patterns: ["jquery.js", "jquery.min.js", "/jquery-", "jquery/jquery", "code.jquery"],
    category: "JavaScript Libraries",
    language: "JavaScript"
  },
  "Bootstrap": {
    patterns: ["bootstrap.css", "bootstrap.min.css", "bootstrap.bundle", "bootstrap/dist", 'class="container"', 'class="row"', 'class="col-'],
    category: "Web Frameworks",
    language: "CSS"
  },
  "Tailwind CSS": {
    patterns: [
      "tailwind.css",
      "tailwindcss",
      "tailwind.min.css",
      'class="tw-',
      'class="bg-',
      'class="text-',
      'class="flex',
      "/tailwind/",
      "tailwind.config.js",
      "@tailwind base",
      "tailwindcss/dist"
    ],
    category: "CSS Frameworks",
    language: "CSS"
  },
  "Nuxt.js": {
    patterns: [
      "__NUXT__",
      "/_nuxt/",
      "<nuxt-link",
      '"nuxt":',
      "@nuxtjs",
      "Nuxt.js",
      "window.$nuxt",
      "nuxt.config.js",
      "/_nuxt/commons.",
      "data-n-head",
      '<div id="__nuxt"'
    ],
    category: "Web Frameworks",
    language: "JavaScript"
  },
  "Next.js": {
    patterns: ["next.js", "__NEXT_DATA__", "/_next/", '"next":', "next/link"],
    category: "Web Frameworks",
    language: "JavaScript"
  },
  // CMS
  "WordPress": {
    patterns: ["wp-content", "wp-includes", "wordpress", "wp-json"],
    category: "CMS",
    language: "PHP"
  },
  "Drupal": {
    patterns: ["Drupal.settings", "/sites/default/files", "drupal.js"],
    category: "CMS",
    language: "PHP"
  },
  "Joomla": {
    patterns: ["/administrator/index.php", "joomla", "com_content"],
    category: "CMS",
    language: "PHP"
  },
  "Shopify": {
    patterns: ["Shopify.", "shopify", ".myshopify.com"],
    category: "Ecommerce",
    language: "Ruby"
  },
  "Magento": {
    patterns: ["magento", "Mage.", "/skin/frontend/"],
    category: "Ecommerce",
    language: "PHP"
  },
  "WooCommerce": {
    patterns: ["woocommerce", "wc-api", "wc_add_to_cart"],
    category: "Ecommerce",
    language: "PHP"
  },
  // Back-end Technologies  
  "Laravel": {
    patterns: [
      // More specific Laravel patterns
      "laravel_session=",
      "XSRF-TOKEN",
      "X-XSRF-TOKEN",
      "Laravel Framework",
      "laravel.js",
      "/laravel/",
      "app/Http/Controllers",
      "Illuminate\\",
      "laravel.mix"
    ],
    category: "Web Frameworks",
    language: "PHP"
  },
  "Express.js": {
    patterns: ["express", "express.js", "expressjs"],
    category: "Web Frameworks",
    language: "JavaScript"
  },
  "Django": {
    patterns: ["django", "csrftoken", "csrfmiddlewaretoken"],
    category: "Web Frameworks",
    language: "Python"
  },
  "Ruby on Rails": {
    patterns: ["rails", "ruby on rails", "csrf-token"],
    category: "Web Frameworks",
    language: "Ruby"
  },
  "ASP.NET": {
    patterns: [
      // More specific ASP.NET patterns
      "__VIEWSTATE",
      "__EVENTVALIDATION",
      ".aspx",
      ".ashx",
      ".asmx",
      "ASP.NET_SessionId",
      "X-AspNet-Version",
      "X-AspNetMvc-Version"
    ],
    category: "Web Frameworks",
    language: "C#"
  },
  "Spring": {
    patterns: ["spring", "spring.js", "org.springframework"],
    category: "Web Frameworks",
    language: "Java"
  },
  // Web Servers
  "Apache": {
    patterns: ["apache", "apache/"],
    category: "Web Servers",
    language: ""
  },
  "Nginx": {
    patterns: ["nginx"],
    category: "Web Servers",
    language: ""
  },
  "IIS": {
    patterns: ["iis", "microsoft-iis", "ms-iis"],
    category: "Web Servers",
    language: ""
  },
  "Cloudflare": {
    patterns: ["cloudflare", "cf-ray", "__cfduid"],
    category: "CDN",
    language: ""
  },
  "Litespeed": {
    patterns: ["litespeed"],
    category: "Web Servers",
    language: ""
  },
  // Languages
  "PHP": {
    patterns: [
      // More specific PHP patterns to reduce false positives
      "/index.php",
      "phpinfo()",
      "php_version",
      "PHPSESSID=",
      'content="php"',
      "Powered by PHP",
      ".php?"
    ],
    category: "Programming Languages",
    language: "PHP"
  },
  "Node.js": {
    patterns: ["node.js", "nodejs", "node_modules"],
    category: "Programming Languages",
    language: "JavaScript"
  },
  "Python": {
    patterns: [
      // More specific Python patterns
      "python-requests",
      "wsgi.py",
      "django.contrib",
      ".py?",
      "PYTHONPATH",
      'content="python"',
      "Powered by Python"
    ],
    category: "Programming Languages",
    language: "Python"
  },
  "Ruby": {
    patterns: ["ruby", ".rb", "ruby on"],
    category: "Programming Languages",
    language: "Ruby"
  },
  "Java": {
    patterns: ["java", ".jsp", ".jar"],
    category: "Programming Languages",
    language: "Java"
  }
};
function detectTechByPatterns(html, headers) {
  const technologies = [];
  const frameworks = /* @__PURE__ */ new Set();
  const languages = /* @__PURE__ */ new Set();
  const servers = /* @__PURE__ */ new Set();
  const headersString = JSON.stringify(headers).toLowerCase();
  const MIN_CONFIDENCE_THRESHOLD = 40;
  const STRONG_PATTERN_INDICATORS = [
    "__VIEWSTATE",
    // ASP.NET
    "PHPSESSID",
    // PHP
    "laravel_session=",
    // Laravel
    "wp-content",
    // WordPress
    'class="container"',
    // Bootstrap
    "/tailwind"
    // Tailwind
  ];
  Object.entries(TECH_PATTERNS).forEach(([techName, techInfo]) => {
    let matchCount = 0;
    let strongMatchFound = false;
    let headerMatchFound = false;
    const htmlLower = html.toLowerCase();
    for (const pattern of techInfo.patterns) {
      const patternLower = pattern.toLowerCase();
      if (htmlLower.includes(patternLower)) {
        matchCount++;
        if (STRONG_PATTERN_INDICATORS.some((indicator) => patternLower.includes(indicator.toLowerCase()))) {
          strongMatchFound = true;
          matchCount += 2;
        }
      }
      if (headersString.includes(patternLower)) {
        headerMatchFound = true;
        matchCount += 2;
      }
    }
    let confidence = 0;
    if (matchCount > 0) {
      confidence = Math.min(100, matchCount * 20);
      if (headerMatchFound) {
        confidence = Math.min(100, confidence + 30);
      }
      if (strongMatchFound) {
        confidence = Math.min(100, confidence + 20);
      }
      if (confidence >= MIN_CONFIDENCE_THRESHOLD) {
        technologies.push({
          name: techName,
          categories: [techInfo.category],
          confidence
        });
        if (techInfo.category === "Web Frameworks") {
          frameworks.add(techName);
        }
        if (techInfo.category === "Web Servers") {
          servers.add(techName);
        }
        if (techInfo.language && confidence >= 60) {
          languages.add(techInfo.language);
        }
      }
    }
  });
  if (headers["server"]) {
    const serverHeader = Array.isArray(headers["server"]) ? headers["server"][0] : headers["server"];
    servers.add(serverHeader);
    if (!technologies.some((t) => t.name === serverHeader)) {
      technologies.push({
        name: serverHeader,
        categories: ["Web Servers"],
        confidence: 100
      });
    }
  }
  if (headers["x-powered-by"]) {
    const poweredBy = Array.isArray(headers["x-powered-by"]) ? headers["x-powered-by"][0] : headers["x-powered-by"];
    const poweredByParts = poweredBy.split(", ");
    poweredByParts.forEach((tech) => {
      if (!technologies.some((t) => t.name === tech)) {
        technologies.push({
          name: tech,
          categories: ["Web Frameworks"],
          confidence: 90
          // High but not absolute confidence
        });
      }
      const techLower = tech.toLowerCase();
      if (techLower.includes("php/") || techLower === "php") {
        languages.add("PHP");
        const phpVersionMatch = techLower.match(/php\/([0-9.]+)/i);
        if (phpVersionMatch && !technologies.some((t) => t.name === "PHP")) {
          technologies.push({
            name: "PHP",
            version: phpVersionMatch[1],
            categories: ["Programming Languages"],
            confidence: 95
          });
        }
      }
      if (techLower === "asp.net" || techLower.includes("asp.net/")) {
        frameworks.add("ASP.NET");
        languages.add("C#");
        const aspVersionMatch = techLower.match(/asp\.net[/\s]+([0-9.]+)/i);
        if (aspVersionMatch && !technologies.some((t) => t.name === "ASP.NET")) {
          technologies.push({
            name: "ASP.NET",
            version: aspVersionMatch[1],
            categories: ["Web Frameworks"],
            confidence: 95
          });
        }
      }
      if (techLower.includes("express/"))
        frameworks.add("Express.js");
      if (techLower.includes("node/"))
        languages.add("JavaScript");
      if (techLower.includes("nuxt/"))
        frameworks.add("Nuxt.js");
    });
  }
  const generatorMatch = html.match(/<meta\s+name=["']generator["']\s+content=["']([^"']+)["']/i);
  if (generatorMatch && generatorMatch[1]) {
    const generator = generatorMatch[1];
    if (!technologies.some((t) => t.name === generator)) {
      technologies.push({
        name: generator,
        categories: ["CMS"],
        confidence: 100
      });
    }
    const generatorLower = generator.toLowerCase();
    if (generatorLower.includes("wordpress")) {
      frameworks.add("WordPress");
      languages.add("PHP");
    }
    if (generatorLower.includes("drupal")) {
      frameworks.add("Drupal");
      languages.add("PHP");
    }
    if (generatorLower.includes("joomla")) {
      frameworks.add("Joomla");
      languages.add("PHP");
    }
  }
  return {
    technologies,
    frameworks: Array.from(frameworks),
    languages: Array.from(languages),
    servers: Array.from(servers)
  };
}
function validateAndCleanResults(results) {
  results.technologies = results.technologies.filter((tech) => tech.confidence >= 50);
  const techMap = /* @__PURE__ */ new Map();
  results.technologies.forEach((tech) => {
    const existingTech = techMap.get(tech.name);
    if (!existingTech || existingTech.confidence < tech.confidence) {
      techMap.set(tech.name, tech);
    }
  });
  results.technologies = Array.from(techMap.values());
  results.frameworks = [...new Set(results.frameworks)].filter(
    (framework) => results.technologies.some((tech) => tech.name === framework || // Handle Nuxt/Nuxt.js variation
    tech.name === "Nuxt.js" && framework === "Nuxt" || tech.name === "Nuxt" && framework === "Nuxt.js")
  );
  const languagesWithTech = results.languages.filter((lang) => {
    return results.technologies.some((tech) => tech.categories.includes("Programming Languages") && tech.name === lang);
  });
  const languagesFromFrameworks = results.technologies.filter((tech) => tech.categories.includes("Web Frameworks") && tech.confidence >= 75).map((tech) => {
    switch (tech.name) {
      case "ASP.NET":
        return "C#";
      case "Laravel":
        return "PHP";
      case "Django":
        return "Python";
      case "Nuxt.js":
      case "Nuxt":
      case "Vue.js":
      case "React":
      case "Angular":
        return "JavaScript";
      case "Ruby on Rails":
        return "Ruby";
      case "Spring":
        return "Java";
      default:
        return null;
    }
  }).filter(Boolean);
  results.languages = [.../* @__PURE__ */ new Set([...languagesWithTech, ...languagesFromFrameworks])];
  results.servers = [...new Set(results.servers)].filter(
    (server) => results.technologies.some((tech) => tech.name === server || // Handle IIS/Microsoft-IIS variation
    tech.name.toLowerCase().includes("iis") && server.toLowerCase().includes("iis"))
  );
  return results;
}
var detectTechStack = async (input) => {
  const startTime = Date.now();
  const normalizedInput = createScannerInput(input);
  try {
    const Wappalyzer = {
      analyze: async () => []
    };
    let usingFallbackDetection = true;
    try {
      if (typeof window === "undefined") {
        try {
          const wappalyzerCore = require_wappalyzer();
          if (wappalyzerCore && typeof wappalyzerCore.analyze === "function") {
            Object.assign(Wappalyzer, wappalyzerCore);
            usingFallbackDetection = false;
          }
        } catch (err) {
          usingFallbackDetection = true;
        }
      } else {
        usingFallbackDetection = true;
      }
    } catch (e) {
      usingFallbackDetection = true;
    }
    const mainPageRequest = makeRequest(normalizedInput.target, {
      method: "GET",
      timeout: normalizedInput.timeout,
      headers: normalizedInput.headers
    });
    const defaultTimeout = normalizedInput.timeout || 1e4;
    const jsRequest = makeRequest(`${normalizedInput.target}/main.js`, {
      method: "GET",
      timeout: defaultTimeout / 2,
      // Shorter timeout for auxiliary requests
      headers: normalizedInput.headers
    }).catch(() => ({ data: "", headers: {}, status: 0, error: null }));
    const cssRequest = makeRequest(`${normalizedInput.target}/main.css`, {
      method: "GET",
      timeout: defaultTimeout / 2,
      headers: normalizedInput.headers
    }).catch(() => ({ data: "", headers: {}, status: 0, error: null }));
    const response = await mainPageRequest;
    const [jsResponse, cssResponse] = await Promise.all([jsRequest, cssRequest]);
    if (response.error || !response.data) {
      return {
        status: "failure",
        scanner: "techStack",
        error: response.error || "Failed to retrieve website content",
        data: {
          technologies: [],
          frameworks: [],
          languages: [],
          servers: []
        },
        timeTaken: Date.now() - startTime
      };
    }
    let html = typeof response.data === "string" ? response.data : String(response.data);
    const jsContent = typeof jsResponse.data === "string" ? jsResponse.data : String(jsResponse.data || "");
    const cssContent = typeof cssResponse.data === "string" ? cssResponse.data : String(cssResponse.data || "");
    const combinedContent = html + " " + jsContent + " " + cssContent;
    const headers = response.headers;
    let technologies = [];
    let frameworks = [];
    let languages = [];
    let servers = [];
    if (!usingFallbackDetection) {
      const wappalyzerInput = {
        url: normalizedInput.target,
        html,
        headers
      };
      const detectedTechnologies = await Wappalyzer.analyze(wappalyzerInput);
      technologies = detectedTechnologies.map((tech) => ({
        name: tech.name,
        version: tech.version,
        categories: tech.categories.map((cat) => cat.name),
        confidence: tech.confidence
      }));
      technologies.forEach((tech) => {
        if (tech.categories.includes("Web Frameworks")) {
          frameworks.push(tech.name);
        }
        if (tech.categories.includes("Programming Languages")) {
          languages.push(tech.name);
        }
        if (tech.categories.includes("Web Servers")) {
          servers.push(tech.name);
        }
      });
      if (technologies.length === 0) {
        usingFallbackDetection = true;
      }
    }
    if (usingFallbackDetection) {
      const patternResults = detectTechByPatterns(combinedContent, headers);
      technologies = patternResults.technologies;
      frameworks = patternResults.frameworks;
      languages = patternResults.languages;
      servers = patternResults.servers;
    }
    const cleanedResults = validateAndCleanResults({
      technologies,
      frameworks,
      languages,
      servers
    });
    return {
      status: "success",
      scanner: "techStack",
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
      status: "failure",
      scanner: "techStack",
      error: error.message || "Unknown error",
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

// src/modules/libraryVulnerabilities.ts
var COMMON_LIBRARIES = [
  { name: "jQuery", regex: /jquery[-.](\d+\.\d+\.\d+)(?:\.min)?\.js/i },
  { name: "Bootstrap", regex: /bootstrap[-.](\d+\.\d+\.\d+)(?:\.min)?\.(?:js|css)/i },
  { name: "React", regex: /react[-.](\d+\.\d+\.\d+)(?:\.min)?\.js/i },
  { name: "Angular", regex: /angular[-.]?(?:core[\./])?(\d+\.\d+\.\d+)(?:\.min)?\.js/i },
  { name: "Vue", regex: /vue(?:\.esm)?[-.](\d+\.\d+\.\d+)(?:\.min)?\.js/i },
  { name: "Lodash", regex: /lodash(?:\.core)?[-.](\d+\.\d+\.\d+)(?:\.min)?\.js/i },
  { name: "Moment", regex: /moment[-.](\d+\.\d+\.\d+)(?:\.min)?\.js/i },
  { name: "D3", regex: /d3(?:\.v\d)?[-.](\d+\.\d+\.\d+)(?:\.min)?\.js/i },
  { name: "Axios", regex: /axios[-.](\d+\.\d+\.\d+)(?:\.min)?\.js/i }
];
var scanLibraryVulnerabilities = async (input) => {
  const startTime = Date.now();
  const normalizedInput = createScannerInput(input);
  try {
    const retireDbUrl = "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json";
    const dbResponse = await makeRequest(retireDbUrl, {
      timeout: normalizedInput.timeout || 15e3
    });
    if (dbResponse.error || !dbResponse.data) {
      return {
        status: "failure",
        scanner: "libraryVulnerabilities",
        error: dbResponse.error || "Failed to retrieve vulnerability database",
        data: {
          vulnerableLibs: [],
          totalVulnerabilities: 0
        },
        timeTaken: Date.now() - startTime
      };
    }
    let vulnerabilityDb;
    if (typeof dbResponse.data === "string") {
      try {
        vulnerabilityDb = JSON.parse(dbResponse.data);
      } catch (e) {
        return {
          status: "failure",
          scanner: "libraryVulnerabilities",
          error: "Failed to parse vulnerability database",
          data: {
            vulnerableLibs: [],
            totalVulnerabilities: 0
          },
          timeTaken: Date.now() - startTime
        };
      }
    } else {
      vulnerabilityDb = dbResponse.data;
    }
    let html;
    if (normalizedInput.options?.html) {
      html = normalizedInput.options.html;
    } else {
      const response = await makeRequest(normalizedInput.target, {
        method: "GET",
        timeout: normalizedInput.timeout || 1e4,
        headers: {
          ...normalizedInput.headers,
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
        }
      });
      if (response.error || !response.data) {
        return {
          status: "failure",
          scanner: "libraryVulnerabilities",
          error: response.error || "Failed to retrieve website content",
          data: {
            vulnerableLibs: [],
            totalVulnerabilities: 0
          },
          timeTaken: Date.now() - startTime
        };
      }
      html = typeof response.data === "string" ? response.data : String(response.data);
    }
    const scriptRegex = /<script[^>]*src=["']([^"']+)["'][^>]*>/g;
    let match;
    const scriptUrls = [];
    while ((match = scriptRegex.exec(html)) !== null) {
      let url = match[1];
      if (url.startsWith("/") && !url.startsWith("//")) {
        const baseUrl = new URL(normalizedInput.target);
        url = baseUrl.origin + url;
      } else if (!url.startsWith("http") && !url.startsWith("//")) {
        const baseUrl = new URL(normalizedInput.target);
        url = baseUrl.href.replace(/\/$/, "") + "/" + url;
      } else if (url.startsWith("//")) {
        url = "https:" + url;
      }
      scriptUrls.push(url);
    }
    const styleRegex = /<link[^>]*rel=["']stylesheet["'][^>]*href=["']([^"']+)["'][^>]*>/g;
    while ((match = styleRegex.exec(html)) !== null) {
      let url = match[1];
      if (url.startsWith("/") && !url.startsWith("//")) {
        const baseUrl = new URL(normalizedInput.target);
        url = baseUrl.origin + url;
      } else if (!url.startsWith("http") && !url.startsWith("//")) {
        const baseUrl = new URL(normalizedInput.target);
        url = baseUrl.href.replace(/\/$/, "") + "/" + url;
      } else if (url.startsWith("//")) {
        url = "https:" + url;
      }
      scriptUrls.push(url);
    }
    const inlineScriptRegex = /<script[^>]*>([\s\S]*?)<\/script>/g;
    const inlineScripts = [];
    while ((match = inlineScriptRegex.exec(html)) !== null) {
      if (match[1].trim()) {
        inlineScripts.push(match[1]);
      }
    }
    const vulnerableLibs = [];
    const detectedLibs = /* @__PURE__ */ new Map();
    const checkUrlForLibrary = async (url) => {
      for (const lib of COMMON_LIBRARIES) {
        const match2 = url.match(lib.regex);
        if (match2 && match2[1]) {
          const version = match2[1];
          detectedLibs.set(lib.name, version);
        }
      }
      Object.keys(vulnerabilityDb).forEach((libName) => {
        const lib = vulnerabilityDb[libName];
        if (lib.extractors && lib.extractors.uri) {
          lib.extractors.uri.forEach((pattern) => {
            try {
              const regex = new RegExp(pattern);
              const match2 = url.match(regex);
              if (match2) {
                let version = "";
                if (match2.length > 1) {
                  version = match2[1];
                }
                detectedLibs.set(libName, version);
                const vulnerabilities = findLibraryVulnerabilities(lib, version);
                if (vulnerabilities.length > 0) {
                  const existingLib = vulnerableLibs.find((l) => l.name === libName && l.version === version);
                  if (!existingLib) {
                    vulnerableLibs.push({
                      name: libName,
                      version,
                      vulnerabilities
                    });
                  }
                }
              }
            } catch (e) {
            }
          });
        }
      });
      if (url.includes("cdn.") || url.includes(".min.js")) {
        try {
          if (url.endsWith(".js") || !url.includes(".")) {
            const scriptContent = await makeRequest(url, {
              timeout: 5e3
              // Short timeout for external resources
            }).then((r) => typeof r.data === "string" ? r.data : String(r.data)).catch(() => "");
            if (scriptContent) {
              Object.keys(vulnerabilityDb).forEach((libName) => {
                const lib = vulnerabilityDb[libName];
                if (lib.extractors && lib.extractors.filecontent) {
                  lib.extractors.filecontent.forEach((pattern) => {
                    try {
                      const regex = new RegExp(pattern);
                      const match2 = scriptContent.match(regex);
                      if (match2) {
                        let version = "";
                        if (match2.length > 1) {
                          version = match2[1];
                        }
                        detectedLibs.set(libName, version);
                        const vulnerabilities = findLibraryVulnerabilities(lib, version);
                        if (vulnerabilities.length > 0) {
                          const existingLib = vulnerableLibs.find((l) => l.name === libName && l.version === version);
                          if (!existingLib) {
                            vulnerableLibs.push({
                              name: libName,
                              version,
                              vulnerabilities
                            });
                          }
                        }
                      }
                    } catch (e) {
                    }
                  });
                }
              });
            }
          }
        } catch (e) {
        }
      }
    };
    const concurrentLimit = normalizedInput.options?.concurrentLimit || 5;
    const chunks = [];
    for (let i = 0; i < scriptUrls.length; i += concurrentLimit) {
      chunks.push(scriptUrls.slice(i, i + concurrentLimit));
    }
    for (const chunk of chunks) {
      await Promise.all(chunk.map((url) => checkUrlForLibrary(url)));
    }
    for (const script of inlineScripts) {
      Object.keys(vulnerabilityDb).forEach((libName) => {
        const lib = vulnerabilityDb[libName];
        if (lib.extractors && lib.extractors.filecontent) {
          lib.extractors.filecontent.forEach((pattern) => {
            try {
              const regex = new RegExp(pattern);
              const match2 = script.match(regex);
              if (match2) {
                let version = "";
                if (match2.length > 1) {
                  version = match2[1];
                }
                detectedLibs.set(libName, version);
                const vulnerabilities = findLibraryVulnerabilities(lib, version);
                if (vulnerabilities.length > 0) {
                  const existingLib = vulnerableLibs.find((lib2) => lib2.name === libName && lib2.version === version);
                  if (!existingLib) {
                    vulnerableLibs.push({
                      name: libName,
                      version,
                      vulnerabilities
                    });
                  }
                }
              }
            } catch (e) {
            }
          });
        }
      });
    }
    const totalVulnerabilities = vulnerableLibs.reduce(
      (total, lib) => total + lib.vulnerabilities.length,
      0
    );
    let result = {
      vulnerableLibs,
      totalVulnerabilities
    };
    if (normalizedInput.options?.includeAllLibraries) {
      result.detectedLibraries = Array.from(detectedLibs.entries()).map(([name, version]) => ({
        name,
        version
      }));
    }
    return {
      status: "success",
      scanner: "libraryVulnerabilities",
      data: result,
      timeTaken: Date.now() - startTime
    };
  } catch (error) {
    return {
      status: "failure",
      scanner: "libraryVulnerabilities",
      error: error.message || "Unknown error",
      data: {
        vulnerableLibs: [],
        totalVulnerabilities: 0
      },
      timeTaken: Date.now() - startTime
    };
  }
};
function findLibraryVulnerabilities(lib, version) {
  if (!lib.vulnerabilities || !version) {
    return [];
  }
  const vulnerabilities = [];
  lib.vulnerabilities.forEach((vuln) => {
    let isVulnerable = false;
    if (vuln.below && isVersionBelow(version, vuln.below)) {
      isVulnerable = true;
    }
    if (vuln.atOrAbove && vuln.below && isVersionAtOrAbove(version, vuln.atOrAbove) && isVersionBelow(version, vuln.below)) {
      isVulnerable = true;
    }
    if (isVulnerable) {
      let id = "UNKNOWN";
      if (vuln.identifiers) {
        if (vuln.identifiers.CVE && vuln.identifiers.CVE.length > 0) {
          id = vuln.identifiers.CVE[0];
        } else if (vuln.identifiers.bug && vuln.identifiers.bug.length > 0) {
          id = `BUG-${vuln.identifiers.bug[0]}`;
        } else if (vuln.identifiers.issue && vuln.identifiers.issue.length > 0) {
          id = `ISSUE-${vuln.identifiers.issue[0]}`;
        }
      }
      let severity = "medium";
      if (vuln.severity === "high" || vuln.severity === "critical") {
        severity = "high";
      } else if (vuln.severity === "medium" || vuln.severity === "moderate") {
        severity = "medium";
      } else if (vuln.severity === "low") {
        severity = "low";
      }
      const info = vuln.info && vuln.info.length > 0 ? vuln.info[0] : `Vulnerability in ${lib.component} < ${vuln.below}`;
      vulnerabilities.push({
        id,
        severity,
        info
      });
    }
  });
  return vulnerabilities;
}
function isVersionBelow(version, targetVersion) {
  const cleanVersion = version.replace(/[^\d.]/g, "");
  const cleanTarget = targetVersion.replace(/[^\d.]/g, "");
  if (!cleanVersion || !cleanTarget)
    return false;
  const v1 = cleanVersion.split(".").map((p) => parseInt(p, 10) || 0);
  const v2 = cleanTarget.split(".").map((p) => parseInt(p, 10) || 0);
  for (let i = 0; i < Math.max(v1.length, v2.length); i++) {
    const n1 = i < v1.length ? v1[i] : 0;
    const n2 = i < v2.length ? v2[i] : 0;
    if (n1 < n2)
      return true;
    if (n1 > n2)
      return false;
  }
  return false;
}
function isVersionAtOrAbove(version, targetVersion) {
  return !isVersionBelow(version, targetVersion);
}

// src/modules/waybackMachine.ts
var scanWaybackMachine = async (input) => {
  const startTime = Date.now();
  const normalizedInput = createScannerInput(input);
  const domain = extractDomain(normalizedInput.target);
  try {
    const waybackUrl = `https://archive.org/wayback/available?url=${domain}&timestamp=*&output=json`;
    const response = await makeRequest(waybackUrl, {
      method: "GET",
      timeout: normalizedInput.timeout
    });
    if (response.error || !response.data) {
      return {
        status: "failure",
        scanner: "waybackMachine",
        error: response.error || "Failed to retrieve Wayback Machine data",
        data: {
          wayback: {
            totalSnapshots: 0
          }
        },
        timeTaken: Date.now() - startTime
      };
    }
    let waybackData;
    if (typeof response.data === "string") {
      waybackData = JSON.parse(response.data);
    } else {
      waybackData = response.data;
    }
    if (!waybackData.archived_snapshots || Object.keys(waybackData.archived_snapshots).length === 0) {
      return {
        status: "success",
        scanner: "waybackMachine",
        data: {
          wayback: {
            totalSnapshots: 0
          }
        },
        timeTaken: Date.now() - startTime
      };
    }
    const cdxUrl = `https://web.archive.org/cdx/search/cdx?url=${domain}&output=json&limit=50`;
    const cdxResponse = await makeRequest(cdxUrl, {
      method: "GET",
      timeout: normalizedInput.timeout
    });
    let snapshots = [];
    if (!cdxResponse.error && cdxResponse.data) {
      try {
        let cdxData;
        if (typeof cdxResponse.data === "string") {
          cdxData = JSON.parse(cdxResponse.data);
        } else {
          cdxData = cdxResponse.data;
        }
        if (cdxData.length > 1) {
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
      }
    }
    const timestamps = snapshots.map((s) => s.timestamp);
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
      status: "success",
      scanner: "waybackMachine",
      data: {
        wayback: {
          firstSeen,
          lastSeen,
          totalSnapshots: snapshots.length || 1,
          snapshots: snapshots.length > 0 ? snapshots : void 0
        }
      },
      timeTaken: Date.now() - startTime
    };
  } catch (error) {
    return {
      status: "failure",
      scanner: "waybackMachine",
      error: error.message || "Unknown error",
      data: {
        wayback: {
          totalSnapshots: 0
        }
      },
      timeTaken: Date.now() - startTime
    };
  }
};
function formatWaybackTimestamp(timestamp) {
  if (!timestamp || timestamp.length < 8) {
    return "Unknown";
  }
  const year = timestamp.slice(0, 4);
  const month = timestamp.slice(4, 6);
  const day = timestamp.slice(6, 8);
  const time = timestamp.length >= 14 ? `${timestamp.slice(8, 10)}:${timestamp.slice(10, 12)}:${timestamp.slice(12, 14)}` : "00:00:00";
  return `${year}-${month}-${day}T${time}Z`;
}

// src/modules/firewall.ts
var FIREWALL_SIGNATURES = {
  "Cloudflare": [
    "cf-ray",
    "__cfduid",
    "cf-request-id",
    "cf-cache-status",
    "cf-connecting-ip",
    "cloudflare",
    "cloudflare-nginx",
    "__cf",
    "cfduid"
  ],
  "Akamai": [
    "x-akamai-transformed",
    "akamai-origin-hop",
    "akamai-global-host",
    "x-akamai",
    "x-check-cacheable",
    "akamai"
  ],
  "Incapsula": [
    "incap_ses",
    "visid_incap",
    "incap_visid_",
    "incapsula",
    "x-iinfo",
    "x-cdn"
  ],
  "Sucuri": [
    "x-sucuri-id",
    "x-sucuri-cache",
    "sucuri",
    "x-sucuri"
  ],
  "ModSecurity": [
    "x-mod-security",
    "modsecurity",
    "mod_security"
  ],
  "AWS WAF": [
    "x-amz-cf-id",
    "x-amz-cf-pop",
    "awselb",
    "aws-alb",
    "x-amz-id",
    "aws"
  ],
  "Fastly": [
    "fastly-io-info",
    "x-fastly",
    "fastly-ssl",
    "fastly",
    "x-served-by"
  ],
  "F5 BIG-IP ASM": [
    "x-wa-info",
    "x-asc",
    "bigip",
    "x-cnection",
    "x-f5"
  ],
  "Barracuda": [
    "x-barracuda",
    "barracuda",
    "barra_counter",
    "barracudacentral"
  ],
  "Imperva": [
    "x-iinfo",
    "x-cdn",
    "imperva",
    "_imp_apg_r_",
    "_imp_di_",
    "imperva_session"
  ],
  "Citrix ADC": [
    "ns_af",
    "citrix_ns_id",
    "ns-cache",
    "ns_tvc",
    "netscaler"
  ],
  "Fortinet/FortiWeb": [
    "fortigate",
    "fortiweb",
    "fortinet",
    "fortiwafsid"
  ],
  "Radware": [
    "x-sl",
    "x-sl-compstate",
    "radware",
    "rwsc"
  ],
  "Wordfence": [
    "wordfence",
    "wfCBLBypass"
  ],
  "SiteLock": [
    "x-sitelock",
    "sitelock-site-verification",
    "sitelock"
  ],
  "Distil Networks": [
    "x-distil-cs",
    "distil_ratelimit",
    "distil"
  ],
  "Reblaze": [
    "rbzid",
    "rbsession",
    "reblaze"
  ]
};
var WAF_BEHAVIOR_SIGNATURES = {
  "Cloudflare": [
    "cloudflare ray id:",
    "cloudflare to restrict access",
    "cloudflare security",
    "checking your browser"
  ],
  "Sucuri": [
    "sucuri website firewall",
    "access denied - sucuri website firewall",
    "blocked by the sucuri website firewall"
  ],
  "ModSecurity": [
    "mod_security",
    "this request has been blocked by the mod security",
    "mod_security rules triggered"
  ],
  "AWS WAF": [
    "aws web application firewall",
    "request blocked by web application firewall"
  ],
  "Imperva": [
    "imperva",
    "incapsula incident id",
    "your request was blocked by imperva"
  ],
  "Akamai": [
    "akamai reference number",
    "you don't have permission to access",
    "access denied. please try again after"
  ],
  "Wordfence": [
    "wordfence security",
    "site access blocked by wordfence",
    "generated by wordfence",
    "a wordfence firewall blocked"
  ],
  "Barracuda": [
    "barracuda networks",
    "you were blocked by the barracuda web application firewall"
  ],
  "F5 BIG-IP ASM": [
    "request rejected by big-ip",
    "the requested url was rejected",
    "please consult with your administrator"
  ],
  "Fortinet/FortiWeb": [
    "your request was blocked by fortinet",
    "your access to this page has been limited by fortiweb"
  ]
};
var WAF_DETECTION_PAYLOADS = [
  // SQL Injection payloads
  "' OR 1=1 --",
  "1' OR '1'='1",
  // XSS payloads
  "<script>alert(1)</script>",
  "<img src=x onerror=alert('XSS')>",
  // Path traversal
  "../../../etc/passwd",
  // Command injection
  "& cat /etc/passwd",
  "; ls -la",
  // Local File Inclusion
  "file:///etc/passwd",
  // Generic malicious patterns
  "eval(base64_decode",
  "union select password"
];
async function testWAFBlocking(url, timeout, headers) {
  const normalResponse = await makeRequest(url, {
    method: "GET",
    timeout,
    headers
  }).catch(() => ({ status: 0, headers: {}, data: "" }));
  for (const payload of WAF_DETECTION_PAYLOADS) {
    try {
      const testUrl = url.includes("?") ? `${url}&waftest=${encodeURIComponent(payload)}` : `${url}?waftest=${encodeURIComponent(payload)}`;
      const response = await makeRequest(testUrl, {
        method: "GET",
        timeout,
        headers
      }).catch((err) => ({
        status: err.response?.status || 0,
        headers: err.response?.headers || {},
        data: err.response?.data || "",
        error: err.message
      }));
      if (normalResponse.status >= 200 && normalResponse.status < 400 && (response.status === 0 || response.status === 403 || response.status === 406 || response.status === 429 || response.status >= 500)) {
        return {
          blocked: true,
          response,
          payload
        };
      }
      if (response.data && typeof response.data === "string") {
        const responseText = response.data.toLowerCase();
        const wafTerms = [
          "waf",
          "firewall",
          "blocked",
          "security",
          "attack",
          "malicious",
          "denied",
          "suspicious",
          "protection",
          "threat",
          "detected"
        ];
        if (wafTerms.filter((term) => responseText.includes(term)).length >= 2) {
          return {
            blocked: true,
            response,
            payload
          };
        }
      }
    } catch (error) {
      return {
        blocked: true,
        response: {
          status: 0,
          headers: {},
          data: "",
          error: error.message
        },
        payload
      };
    }
  }
  return {
    blocked: false,
    response: normalResponse,
    payload: ""
  };
}
var detectFirewall = async (input) => {
  const startTime = Date.now();
  const normalizedInput = createScannerInput(input);
  const timeout = normalizedInput.timeout || 1e4;
  try {
    const headResponse = await makeRequest(normalizedInput.target, {
      method: "HEAD",
      timeout,
      headers: normalizedInput.headers
    });
    const getResponse = await makeRequest(normalizedInput.target, {
      method: "GET",
      timeout,
      headers: normalizedInput.headers
    });
    if (headResponse.error && getResponse.error || !headResponse.headers && !getResponse.data) {
      return {
        status: "failure",
        scanner: "firewall",
        error: headResponse.error || getResponse.error || "Failed to retrieve responses",
        data: {
          detected: false,
          confidence: 0,
          evidence: []
        },
        timeTaken: Date.now() - startTime
      };
    }
    const allHeaders = {
      ...headResponse.headers || {},
      ...getResponse.headers || {}
    };
    const headers = Object.keys(allHeaders).map((key) => key.toLowerCase());
    const headerValues = Object.values(allHeaders).map(
      (val) => val ? val.toString().toLowerCase() : ""
    );
    const responseContent = typeof getResponse.data === "string" ? getResponse.data.toLowerCase() : JSON.stringify(getResponse.data || "").toLowerCase();
    let detected = false;
    let detectedFirewall;
    let confidence = 0;
    let evidence = [];
    for (const [firewallName, signatures] of Object.entries(FIREWALL_SIGNATURES)) {
      let matchCount = 0;
      const matchedEvidence = [];
      for (const signature of signatures) {
        const signatureLower = signature.toLowerCase();
        const headerMatch = headers.find((h) => h.includes(signatureLower));
        if (headerMatch) {
          matchCount++;
          matchedEvidence.push(`Header name match: ${headerMatch}`);
          continue;
        }
        const valueMatch = headerValues.some((v) => v.includes(signatureLower));
        if (valueMatch) {
          matchCount++;
          matchedEvidence.push(`Header value contains: ${signature}`);
          continue;
        }
        if (responseContent.includes(signatureLower)) {
          matchCount++;
          matchedEvidence.push(`Response body contains: ${signature}`);
        }
      }
      if (matchCount > 0) {
        const signatureConfidence = Math.min(90, Math.round(matchCount / signatures.length * 100));
        if (signatureConfidence > confidence) {
          detected = true;
          detectedFirewall = firewallName;
          confidence = signatureConfidence;
          evidence = matchedEvidence;
        }
      }
    }
    for (const [firewallName, patterns] of Object.entries(WAF_BEHAVIOR_SIGNATURES)) {
      for (const pattern of patterns) {
        if (responseContent.includes(pattern.toLowerCase())) {
          const contentConfidence = 95;
          if (contentConfidence > confidence) {
            detected = true;
            detectedFirewall = firewallName;
            confidence = contentConfidence;
            evidence = [`Response content contains WAF signature: ${pattern}`];
          }
          break;
        }
      }
    }
    if (allHeaders.server) {
      const serverHeader = allHeaders.server.toLowerCase();
      if (serverHeader.includes("cloudflare")) {
        detected = true;
        detectedFirewall = "Cloudflare";
        confidence = Math.max(confidence, 90);
        evidence.push(`Server header: ${allHeaders.server}`);
      } else if (serverHeader.includes("aws")) {
        detected = true;
        detectedFirewall = "AWS";
        confidence = Math.max(confidence, 50);
        evidence.push(`Server header: ${allHeaders.server}`);
      } else if (serverHeader.includes("nginx")) {
        if (!detected) {
          detected = true;
          detectedFirewall = "Possibly Nginx as WAF";
          confidence = 30;
          evidence.push(`Server header: ${allHeaders.server}`);
        }
      } else if (serverHeader.includes("akamai")) {
        detected = true;
        detectedFirewall = "Akamai";
        confidence = Math.max(confidence, 90);
        evidence.push(`Server header: ${allHeaders.server}`);
      }
    }
    if (!detected || confidence < 50) {
      try {
        const blockTest = await testWAFBlocking(
          normalizedInput.target,
          Math.min(timeout, 5e3),
          // Use shorter timeout for the test requests
          normalizedInput.headers
        );
        if (blockTest.blocked) {
          detected = true;
          if (!detectedFirewall) {
            detectedFirewall = "Unknown WAF";
          }
          confidence = Math.max(confidence, 80);
          evidence.push(`Blocked suspicious request with payload: ${blockTest.payload}`);
          if (blockTest.response.status) {
            evidence.push(`Block response status: ${blockTest.response.status}`);
          }
          if (blockTest.response.data && typeof blockTest.response.data === "string") {
            const blockResponseText = blockTest.response.data.toLowerCase();
            for (const [firewallName, patterns] of Object.entries(WAF_BEHAVIOR_SIGNATURES)) {
              for (const pattern of patterns) {
                if (blockResponseText.includes(pattern.toLowerCase())) {
                  detectedFirewall = firewallName;
                  confidence = 95;
                  evidence.push(`Block response contains signature of: ${firewallName}`);
                  break;
                }
              }
            }
          }
        }
      } catch (error) {
        evidence.push(`Note: Active testing error: ${error.message}`);
      }
    }
    return {
      status: "success",
      scanner: "firewall",
      data: {
        detected,
        name: detectedFirewall,
        confidence,
        evidence
      },
      timeTaken: Date.now() - startTime
    };
  } catch (error) {
    return {
      status: "failure",
      scanner: "firewall",
      error: error.message || "Unknown error",
      data: {
        detected: false,
        confidence: 0,
        evidence: []
      },
      timeTaken: Date.now() - startTime
    };
  }
};

// src/frontend/index.ts
var detectFormsInDOM = async () => {
  if (typeof document === "undefined") {
    throw new Error("detectFormsInDOM can only be used in browser environments");
  }
  const html = document.documentElement.outerHTML;
  return detectForms({
    target: window.location.href,
    options: { html }
  });
};
var dnsLookup = promisify(dns2.lookup);
var CIPHER_RATINGS = {
  // Strong modern ciphers
  "TLS_AES_256_GCM_SHA384": "strong",
  "TLS_AES_128_GCM_SHA256": "strong",
  "TLS_CHACHA20_POLY1305_SHA256": "strong",
  // Recommended ciphers
  "ECDHE-ECDSA-AES256-GCM-SHA384": "recommended",
  "ECDHE-RSA-AES256-GCM-SHA384": "recommended",
  "ECDHE-ECDSA-AES128-GCM-SHA256": "recommended",
  "ECDHE-RSA-AES128-GCM-SHA256": "recommended",
  "ECDHE-ECDSA-CHACHA20-POLY1305": "recommended",
  "ECDHE-RSA-CHACHA20-POLY1305": "recommended",
  // Adequate ciphers
  "DHE-RSA-AES256-GCM-SHA384": "adequate",
  "DHE-RSA-AES128-GCM-SHA256": "adequate",
  "ECDHE-ECDSA-AES256-SHA384": "adequate",
  "ECDHE-RSA-AES256-SHA384": "adequate",
  "ECDHE-ECDSA-AES128-SHA256": "adequate",
  "ECDHE-RSA-AES128-SHA256": "adequate",
  // Weak ciphers - should be avoided
  "ECDHE-RSA-AES256-SHA": "weak",
  "ECDHE-ECDSA-AES256-SHA": "weak",
  "DHE-RSA-AES256-SHA": "weak",
  "ECDHE-RSA-AES128-SHA": "weak",
  "ECDHE-ECDSA-AES128-SHA": "weak",
  "DHE-RSA-AES128-SHA": "weak",
  "RSA-AES256-GCM-SHA384": "weak",
  "RSA-AES128-GCM-SHA256": "weak",
  "RSA-AES256-SHA256": "weak",
  "RSA-AES128-SHA256": "weak",
  "RSA-AES256-SHA": "weak",
  "RSA-AES128-SHA": "weak",
  // Insecure ciphers - should never be used
  "DES-CBC3-SHA": "insecure",
  "ECDHE-RSA-DES-CBC3-SHA": "insecure",
  "EDH-RSA-DES-CBC3-SHA": "insecure",
  "RC4-SHA": "insecure",
  "RC4-MD5": "insecure",
  "NULL-SHA": "insecure",
  "NULL-MD5": "insecure",
  "EXP-RC4-MD5": "insecure",
  "EXP-DES-CBC-SHA": "insecure"
};
var PROTOCOL_RATINGS = {
  "TLSv1.3": {
    rating: "secure",
    description: "Modern, secure protocol with perfect forward secrecy and improved handshake encryption"
  },
  "TLSv1.2": {
    rating: "recommended",
    description: "Secure protocol when configured properly, widely supported"
  },
  "TLSv1.1": {
    rating: "weak",
    description: "Outdated protocol with known vulnerabilities, should be disabled"
  },
  "TLSv1": {
    rating: "insecure",
    description: "Outdated protocol with known vulnerabilities, should be disabled"
  },
  "SSLv3": {
    rating: "insecure",
    description: "Insecure protocol affected by POODLE vulnerability, must be disabled"
  },
  "SSLv2": {
    rating: "insecure",
    description: "Critically insecure legacy protocol, must be disabled"
  }
};
var KNOWN_VULNERABILITIES = [
  {
    name: "BEAST",
    affects: ["TLSv1"],
    description: "Browser Exploit Against SSL/TLS. Affects CBC ciphers in TLS 1.0 and earlier.",
    severity: "high"
  },
  {
    name: "POODLE",
    affects: ["SSLv3"],
    description: "Padding Oracle On Downgraded Legacy Encryption. Affects all SSLv3 connections.",
    severity: "high"
  },
  {
    name: "FREAK",
    affects: ["TLSv1", "TLSv1.1", "TLSv1.2"],
    description: "Forcing RSA Export Keys. Server supports export-grade cipher suites.",
    severity: "high",
    testFor: (cipher) => cipher.includes("EXP")
  },
  {
    name: "LOGJAM",
    affects: ["TLSv1", "TLSv1.1", "TLSv1.2"],
    description: "Weak Diffie-Hellman key exchange. Server may use weak DH parameters.",
    severity: "high",
    testFor: (cipher) => cipher.includes("DHE") && cipher.includes("EXPORT")
  },
  {
    name: "ROBOT",
    affects: ["TLSv1", "TLSv1.1", "TLSv1.2"],
    description: "Return Of Bleichenbacher's Oracle Threat. RSA padding oracle vulnerability.",
    severity: "high",
    testFor: (cipher) => cipher.startsWith("RSA")
  },
  {
    name: "LUCKY13",
    affects: ["TLSv1", "TLSv1.1", "TLSv1.2"],
    description: "Timing attack against CBC ciphers.",
    severity: "medium",
    testFor: (cipher) => cipher.includes("CBC")
  },
  {
    name: "HEARTBLEED",
    affects: ["TLSv1", "TLSv1.1", "TLSv1.2"],
    description: "OpenSSL heartbeat information disclosure. Can't be detected from connection alone.",
    severity: "critical"
  },
  {
    name: "Sweet32",
    affects: ["TLSv1", "TLSv1.1", "TLSv1.2"],
    description: "Birthday attacks on 64-bit block ciphers (3DES/DES)",
    severity: "medium",
    testFor: (cipher) => cipher.includes("3DES") || cipher.includes("DES-CBC")
  }
];
async function isPortOpen(host, port, timeout) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let isOpen = false;
    socket.setTimeout(timeout);
    socket.on("connect", () => {
      isOpen = true;
      socket.end();
    });
    socket.on("timeout", () => {
      socket.destroy();
      resolve(false);
    });
    socket.on("error", () => {
      resolve(false);
    });
    socket.on("close", () => {
      resolve(isOpen);
    });
    socket.connect(port, host);
  });
}
function testForVulnerabilities(protocol, cipher) {
  const vulnerabilities = [];
  for (const vuln of KNOWN_VULNERABILITIES) {
    if (vuln.affects.includes(protocol)) {
      if (!vuln.testFor || vuln.testFor(cipher.name)) {
        vulnerabilities.push({
          name: vuln.name,
          description: vuln.description,
          severity: vuln.severity
        });
      }
    }
  }
  return vulnerabilities;
}
function calculateKeyStrength(cert) {
  let strength = 0;
  let algorithm = "unknown";
  let rating = "weak";
  if (cert.pubkey) {
    if (cert.pubkey.algo === "rsa") {
      strength = cert.pubkey.bits || 0;
      algorithm = "RSA";
      if (strength >= 4096) {
        rating = "strong";
      } else if (strength >= 2048) {
        rating = "adequate";
      } else if (strength >= 1024) {
        rating = "weak";
      } else {
        rating = "insecure";
      }
    } else if (cert.pubkey.algo === "ec") {
      strength = cert.pubkey.bits || 0;
      algorithm = "ECDSA";
      if (strength >= 384) {
        rating = "strong";
      } else if (strength >= 256) {
        rating = "adequate";
      } else {
        rating = "weak";
      }
    }
  }
  return { strength, algorithm, rating };
}
function checkCertificateFeatures(cert) {
  const features = [];
  const hasSCT = cert.ext && (cert.ext.includes("CT Precertificate SCTs") || cert.ext.includes("signed certificate timestamp"));
  features.push({
    feature: "Certificate Transparency",
    supported: !!hasSCT,
    description: hasSCT ? "Certificate includes embedded SCTs, complying with Certificate Transparency" : "Certificate does not include Certificate Transparency information"
  });
  const hasOCSPMustStaple = cert.ext && cert.ext.includes("OCSP Must-Staple");
  features.push({
    feature: "OCSP Must-Staple",
    supported: !!hasOCSPMustStaple,
    description: hasOCSPMustStaple ? "Certificate requires the server to provide OCSP stapling" : "Certificate does not enforce OCSP stapling"
  });
  const hasKeyUsage = cert.ext && cert.ext.includes("X509v3 Key Usage");
  features.push({
    feature: "Key Usage Restrictions",
    supported: !!hasKeyUsage,
    description: hasKeyUsage ? "Certificate specifies permitted key usages" : "Certificate does not restrict key usages"
  });
  return features;
}
async function tryTLSConnection(host, port, timeout, options = {}) {
  return new Promise((resolve) => {
    try {
      const socketOptions = {
        host,
        port,
        timeout,
        rejectUnauthorized: false,
        secureContext: options.secureContext,
        secureProtocol: options.secureProtocol,
        ALPNProtocols: ["h2", "http/1.1"],
        // Test for HTTP/2 support
        requestCert: true,
        ...options
      };
      const socket = tls.connect(socketOptions);
      socket.setTimeout(timeout);
      socket.on("secureConnect", () => {
        const details = {};
        try {
          details.alpnProtocol = socket.alpnProtocol;
        } catch (e) {
        }
        try {
          details.hostname = host;
        } catch (e) {
        }
        try {
          details.negotiatedProtocol = socket.getProtocol();
        } catch (e) {
        }
        resolve({ success: true, socket, details });
      });
      socket.on("error", (error) => {
        socket.destroy();
        resolve({ success: false, error });
      });
      socket.on("timeout", () => {
        socket.destroy();
        resolve({ success: false, error: new Error("Connection timeout") });
      });
    } catch (error) {
      resolve({ success: false, error });
    }
  });
}
async function testCipherSupport(host, port, timeout, protocol) {
  const supportedCiphers = [];
  const allCiphers = crypto.getCiphers().filter(
    (c) => (
      // Filter to just TLS/SSL ciphers
      c.includes("-") && !c.startsWith("id-") && !c.includes("NULL")
    )
  );
  const cipherGroups = {
    modern: allCiphers.filter(
      (c) => c.includes("ECDHE") && (c.includes("GCM") || c.includes("CHACHA20"))
    ),
    recommended: allCiphers.filter(
      (c) => c.includes("DHE") && (c.includes("GCM") || c.includes("CHACHA20"))
    ),
    legacy: allCiphers.filter(
      (c) => c.includes("AES") && !c.includes("GCM")
    ),
    weak: allCiphers.filter(
      (c) => c.includes("RC4") || c.includes("DES") || c.includes("3DES") || c.includes("MD5")
    )
  };
  const cipherList = [
    ...cipherGroups.modern,
    ...cipherGroups.recommended,
    ...cipherGroups.legacy,
    ...cipherGroups.weak
  ];
  const maxCiphersToTest = 30;
  const selectedCiphers = cipherList.slice(0, maxCiphersToTest);
  for (const cipher of selectedCiphers) {
    try {
      const options = {
        minVersion: protocol,
        maxVersion: protocol,
        ciphers: cipher
      };
      const result = await tryTLSConnection(host, port, timeout / 2, options);
      if (result.success && result.socket) {
        supportedCiphers.push(result.socket.getCipher().name);
        result.socket.destroy();
      }
    } catch (e) {
    }
  }
  return [...new Set(supportedCiphers)];
}
function extractCertificateInfo(socket, host) {
  const protocol = socket.getProtocol() || "";
  const cipher = socket.getCipher();
  const cert = socket.getPeerCertificate(true);
  const chain = [];
  let currentCert = cert;
  while (currentCert && !(currentCert.issuerCertificate?.fingerprint === currentCert.fingerprint)) {
    if (chain.findIndex((c) => c.fingerprint === currentCert.fingerprint) === -1) {
      chain.push({
        subject: currentCert.subject,
        issuer: currentCert.issuer,
        validFrom: currentCert.valid_from,
        validTo: currentCert.valid_to,
        fingerprint: currentCert.fingerprint
      });
      if (currentCert.issuerCertificate && currentCert.fingerprint !== currentCert.issuerCertificate.fingerprint) {
        currentCert = currentCert.issuerCertificate;
      } else {
        break;
      }
    } else {
      break;
    }
  }
  const now = /* @__PURE__ */ new Date();
  const validFrom = new Date(cert.valid_from);
  const validTo = new Date(cert.valid_to);
  const expiresIn = Math.round((validTo.getTime() - now.getTime()) / (1e3 * 60 * 60 * 24));
  const isExpired = now > validTo;
  const isNotYetValid = now < validFrom;
  const issues = [];
  if (isExpired) {
    issues.push({
      severity: "high",
      description: "SSL certificate has expired."
    });
  }
  if (isNotYetValid) {
    issues.push({
      severity: "high",
      description: "SSL certificate is not yet valid."
    });
  }
  if (expiresIn <= 30 && !isExpired) {
    issues.push({
      severity: "medium",
      description: `SSL certificate expires soon (${expiresIn} days).`
    });
  }
  const hostnames = [host];
  if (host.startsWith("www.")) {
    hostnames.push(host.substring(4));
  } else {
    hostnames.push(`www.${host}`);
  }
  const altNames = cert.subjectaltname?.split(", ").map((name) => {
    if (name.startsWith("DNS:")) {
      return name.substring(4);
    }
    return name;
  }) || [];
  const validNames = [
    cert.subject?.CN,
    ...altNames
  ].filter(Boolean);
  const hostnameMatch = hostnames.some(
    (hostname) => validNames.some((name) => {
      if (name.startsWith("*.")) {
        const domainPart = name.substring(2);
        return hostname.endsWith(domainPart) && hostname.split(".").length === domainPart.split(".").length + 1;
      }
      return name === hostname;
    })
  );
  if (!hostnameMatch) {
    issues.push({
      severity: "high",
      description: `Certificate hostname mismatch. Certificate is not valid for: ${host}`
    });
  }
  const protocolRating = PROTOCOL_RATINGS[protocol] || {
    rating: "unknown",
    description: "Unknown protocol version"
  };
  if (protocolRating.rating === "insecure" || protocolRating.rating === "weak") {
    issues.push({
      severity: "high",
      description: `Server uses ${protocolRating.rating} protocol: ${protocol}. ${protocolRating.description}`
    });
  } else if (protocolRating.rating === "adequate") {
    issues.push({
      severity: "medium",
      description: `Server uses ${protocolRating.rating} protocol: ${protocol}. ${protocolRating.description}`
    });
  }
  const cipherRating = CIPHER_RATINGS[cipher.name] || "weak";
  if (cipherRating === "insecure") {
    issues.push({
      severity: "high",
      description: `Server uses insecure cipher: ${cipher.name}.`
    });
  } else if (cipherRating === "weak") {
    issues.push({
      severity: "high",
      description: `Server uses weak cipher: ${cipher.name}.`
    });
  } else if (cipherRating === "adequate") {
    issues.push({
      severity: "medium",
      description: `Server uses adequate but not ideal cipher: ${cipher.name}.`
    });
  }
  const keyInfo = calculateKeyStrength(cert);
  if (keyInfo.rating === "insecure") {
    issues.push({
      severity: "high",
      description: `Certificate uses insecure ${keyInfo.algorithm} key (${keyInfo.strength} bits).`
    });
  } else if (keyInfo.rating === "weak") {
    issues.push({
      severity: "medium",
      description: `Certificate uses weak ${keyInfo.algorithm} key (${keyInfo.strength} bits).`
    });
  }
  const isSelfSigned = chain.length === 1 || cert.issuer.CN === cert.subject.CN && cert.issuer.O === cert.subject.O;
  if (isSelfSigned) {
    issues.push({
      severity: "high",
      description: "Certificate is self-signed and not from a trusted authority."
    });
  }
  const sigAlgo = cert.sigalg?.toLowerCase() || "";
  if (sigAlgo.includes("sha1") || sigAlgo.includes("md5")) {
    issues.push({
      severity: "high",
      description: `Certificate uses weak signature algorithm: ${cert.sigalg}`
    });
  }
  const vulnerabilities = testForVulnerabilities(protocol, cipher);
  for (const vuln of vulnerabilities) {
    issues.push({
      severity: vuln.severity,
      description: `${vuln.name}: ${vuln.description}`
    });
  }
  const features = checkCertificateFeatures(cert);
  let securityScore = 100;
  for (const issue of issues) {
    if (issue.severity === "high") {
      securityScore -= 25;
    } else if (issue.severity === "medium") {
      securityScore -= 10;
    } else if (issue.severity === "low") {
      securityScore -= 5;
    }
  }
  for (const feature of features) {
    if (feature.supported) {
      securityScore += 5;
    }
  }
  securityScore = Math.max(0, Math.min(100, securityScore));
  let securityRating;
  if (securityScore >= 95) {
    securityRating = "A+";
  } else if (securityScore >= 85) {
    securityRating = "A";
  } else if (securityScore >= 70) {
    securityRating = "B";
  } else if (securityScore >= 60) {
    securityRating = "C";
  } else if (securityScore >= 50) {
    securityRating = "D";
  } else {
    securityRating = "F";
  }
  return {
    protocol,
    cipher,
    certInfo: {
      issuer: cert.issuer.CN || cert.issuer.O || "Unknown",
      subject: cert.subject.CN || cert.subject.O || "Unknown",
      validFrom: validFrom.toISOString(),
      validTo: validTo.toISOString(),
      expiresIn,
      subjectAltNames: altNames,
      serialNumber: cert.serialNumber,
      signatureAlgorithm: cert.sigalg,
      keyStrength: keyInfo.strength,
      keyAlgorithm: keyInfo.algorithm
    },
    certificateChain: chain,
    issues,
    securityRating,
    features,
    vulnerabilities
  };
}
var scanTLS = async (input) => {
  const startTime = Date.now();
  const normalizedInput = createScannerInput(input);
  const domain = extractDomain(normalizedInput.target);
  const timeout = normalizedInput.timeout || 1e4;
  const diagnosticInfo = [];
  try {
    try {
      const dnsResult = await dnsLookup(domain);
      diagnosticInfo.push(`Domain ${domain} resolves to IP: ${dnsResult.address}`);
    } catch (error) {
      diagnosticInfo.push(`DNS lookup error: ${error.message}`);
      return {
        status: "failure",
        scanner: "tlsConfig",
        error: `Failed to resolve domain: ${error.message}`,
        data: {
          version: "",
          ciphers: [],
          certificate: {
            issuer: "",
            subject: "",
            validFrom: "",
            validTo: "",
            expiresIn: 0
          },
          isValid: false,
          issues: [{
            severity: "high",
            description: `Failed to resolve domain: ${error.message}`
          }],
          diagnosticInfo
        },
        timeTaken: Date.now() - startTime
      };
    }
    const portsToTry = [443, 8443];
    let portOpen = false;
    let openPort = 0;
    for (const port of portsToTry) {
      diagnosticInfo.push(`Checking if port ${port} is open...`);
      const isOpen = await isPortOpen(domain, port, timeout);
      if (isOpen) {
        diagnosticInfo.push(`Port ${port} is open.`);
        portOpen = true;
        openPort = port;
        break;
      } else {
        diagnosticInfo.push(`Port ${port} is closed or filtered.`);
      }
    }
    if (!portOpen) {
      return {
        status: "failure",
        scanner: "tlsConfig",
        error: "No open TLS ports found",
        data: {
          version: "",
          ciphers: [],
          certificate: {
            issuer: "",
            subject: "",
            validFrom: "",
            validTo: "",
            expiresIn: 0
          },
          isValid: false,
          issues: [{
            severity: "high",
            description: "No open TLS ports found (tried: 443, 8443)"
          }],
          diagnosticInfo
        },
        timeTaken: Date.now() - startTime
      };
    }
    const tlsVersions = [
      { version: "TLSv1.3", options: { minVersion: "TLSv1.3", maxVersion: "TLSv1.3" } },
      { version: "TLSv1.2", options: { minVersion: "TLSv1.2", maxVersion: "TLSv1.2" } },
      { version: "Default", options: {} }
      // Try with defaults as fallback
    ];
    for (const { version, options } of tlsVersions) {
      diagnosticInfo.push(`Attempting TLS connection on port ${openPort} with ${version} protocol...`);
      const connectionResult = await tryTLSConnection(domain, openPort, timeout, options);
      if (connectionResult.success && connectionResult.socket) {
        diagnosticInfo.push(`Successfully established TLS connection using ${version}.`);
        const {
          protocol,
          cipher,
          certInfo,
          issues,
          securityRating,
          features,
          vulnerabilities,
          certificateChain
        } = extractCertificateInfo(connectionResult.socket, domain);
        const supportedCiphers = await testCipherSupport(domain, openPort, timeout / 2, protocol);
        connectionResult.socket.end();
        const cipherStrengths = supportedCiphers.map((cipherName) => {
          const rating = CIPHER_RATINGS[cipherName] || "unknown";
          return {
            name: cipherName,
            strength: rating
          };
        });
        return {
          status: "success",
          scanner: "tlsConfig",
          data: {
            version: protocol,
            ciphers: supportedCiphers,
            cipherDetails: cipherStrengths,
            certificate: certInfo,
            certificateChain,
            isValid: !issues.some((issue) => issue.severity === "high"),
            issues,
            securityRating,
            supportedFeatures: features?.filter((f) => f.supported).map((f) => f.feature) || [],
            missingFeatures: features?.filter((f) => !f.supported).map((f) => f.feature) || [],
            vulnerabilities: vulnerabilities || [],
            diagnosticInfo
          },
          timeTaken: Date.now() - startTime
        };
      } else {
        const errorMsg = connectionResult.error?.message || "Unknown error";
        diagnosticInfo.push(`Failed with ${version}: ${errorMsg}`);
      }
    }
    return {
      status: "failure",
      scanner: "tlsConfig",
      error: "All TLS connection attempts failed",
      data: {
        version: "",
        ciphers: [],
        certificate: {
          issuer: "",
          subject: "",
          validFrom: "",
          validTo: "",
          expiresIn: 0
        },
        isValid: false,
        issues: [{
          severity: "high",
          description: "Failed to establish TLS connection after multiple attempts"
        }],
        diagnosticInfo
      },
      timeTaken: Date.now() - startTime
    };
  } catch (error) {
    return {
      status: "failure",
      scanner: "tlsConfig",
      error: error.message || "Unknown error",
      data: {
        version: "",
        ciphers: [],
        certificate: {
          issuer: "",
          subject: "",
          validFrom: "",
          validTo: "",
          expiresIn: 0
        },
        isValid: false,
        issues: [{
          severity: "high",
          description: `Error scanning TLS configuration: ${error.message}`
        }],
        diagnosticInfo
      },
      timeTaken: Date.now() - startTime
    };
  }
};
var resolveTxt2 = promisify(dns2.resolveTxt);
promisify(dns2.resolveMx);
var resolveNs2 = promisify(dns2.resolveNs);
var scanDNSRecords = async (input) => {
  const startTime = Date.now();
  const normalizedInput = createScannerInput(input);
  const domain = extractDomain(normalizedInput.target);
  const result = {
    spf: {
      exists: false,
      valid: false
    },
    dmarc: {
      exists: false,
      valid: false
    },
    dkim: {
      exists: false,
      valid: false
    },
    dnssec: {
      enabled: false,
      valid: false
    }
  };
  try {
    try {
      const txtRecords = await resolveTxt2(domain);
      const spfRecord = txtRecords.find((record) => {
        const recordStr = record.join("");
        return recordStr.startsWith("v=spf1");
      });
      if (spfRecord) {
        const recordStr = spfRecord.join("");
        result.spf = {
          exists: true,
          valid: true,
          record: recordStr,
          issues: []
        };
        if (!recordStr.includes("~all") && !recordStr.includes("-all")) {
          result.spf.issues = ["SPF record does not end with ~all or -all"];
          result.spf.valid = false;
        }
      }
    } catch (error) {
      result.spf.exists = false;
      result.spf.issues = ["Failed to retrieve SPF record"];
    }
    try {
      const dmarcRecords = await resolveTxt2("_dmarc." + domain);
      const dmarcRecord = dmarcRecords.find((record) => {
        const recordStr = record.join("");
        return recordStr.startsWith("v=DMARC1");
      });
      if (dmarcRecord) {
        const recordStr = dmarcRecord.join("");
        result.dmarc = {
          exists: true,
          valid: true,
          record: recordStr,
          issues: []
        };
        const policyMatch = recordStr.match(/p=([^;]+)/);
        if (policyMatch) {
          result.dmarc.policy = policyMatch[1];
        }
        if (!recordStr.includes("p=")) {
          result.dmarc.issues = ["DMARC record does not include a policy (p=)"];
          result.dmarc.valid = false;
        } else if (result.dmarc.policy === "none") {
          result.dmarc.issues = ['DMARC policy is set to "none" which only monitors but takes no action'];
        }
      }
    } catch (error) {
      result.dmarc.exists = false;
      result.dmarc.issues = ["Failed to retrieve DMARC record"];
    }
    const commonSelectors = ["default", "google", "selector1", "selector2", "k1"];
    const dkimResults = [];
    for (const selector of commonSelectors) {
      try {
        const dkimRecords = await resolveTxt2(`${selector}._domainkey.${domain}`);
        if (dkimRecords && dkimRecords.length > 0) {
          dkimResults.push(selector);
        }
      } catch (error) {
      }
    }
    if (dkimResults.length > 0) {
      result.dkim = {
        exists: true,
        valid: true,
        selectors: dkimResults
      };
    } else {
      result.dkim.issues = ["No DKIM records found for common selectors"];
    }
    try {
      const nsRecords = await resolveNs2(domain);
      if (nsRecords && nsRecords.length > 0) {
        result.dnssec = {
          enabled: true,
          valid: true,
          issues: ["Basic DNSSEC detection only. Full validation requires specialized tools."]
        };
      }
    } catch (error) {
      result.dnssec.issues = ["Failed to check nameservers for DNSSEC"];
    }
    return {
      status: "success",
      scanner: "dnsRecords",
      data: result,
      timeTaken: Date.now() - startTime
    };
  } catch (error) {
    return {
      status: "failure",
      scanner: "dnsRecords",
      error: error.message || "Unknown error",
      data: result,
      timeTaken: Date.now() - startTime
    };
  }
};
var DEFAULT_PORTS = [
  21,
  // FTP
  22,
  // SSH
  23,
  // Telnet
  25,
  // SMTP
  53,
  // DNS
  80,
  // HTTP
  110,
  // POP3
  143,
  // IMAP
  443,
  // HTTPS
  465,
  // SMTPS
  587,
  // SMTP Submission
  993,
  // IMAPS
  995,
  // POP3S
  3306,
  // MySQL
  5432,
  // PostgreSQL
  8080,
  // HTTP Alternate
  8443
  // HTTPS Alternate
];
var SERVICE_NAMES = {
  21: "FTP",
  22: "SSH",
  23: "Telnet",
  25: "SMTP",
  53: "DNS",
  80: "HTTP",
  110: "POP3",
  143: "IMAP",
  443: "HTTPS",
  465: "SMTPS",
  587: "SMTP Submission",
  993: "IMAPS",
  995: "POP3S",
  3306: "MySQL",
  5432: "PostgreSQL",
  8080: "HTTP Alternate",
  8443: "HTTPS Alternate"
};
var scanPorts = async (input) => {
  const startTime = Date.now();
  const normalizedInput = createScannerInput(input);
  const domain = extractDomain(normalizedInput.target);
  const timeout = normalizedInput.timeout || 3e3;
  const portsToScan = normalizedInput.options?.ports || DEFAULT_PORTS;
  const result = {
    openPorts: [],
    total: 0
  };
  try {
    const portPromises = portsToScan.map((port) => {
      return new Promise((resolve) => {
        const socket = new net.Socket();
        let resolved = false;
        socket.setTimeout(timeout);
        socket.on("connect", () => {
          if (resolved)
            return;
          resolved = true;
          let banner = "";
          const bannerTimeout = setTimeout(() => {
            socket.destroy();
            result.openPorts.push({
              port,
              service: SERVICE_NAMES[port] || void 0,
              banner: banner || void 0
            });
            resolve();
          }, 1e3);
          socket.once("data", (data) => {
            banner = data.toString().trim();
            clearTimeout(bannerTimeout);
            socket.destroy();
            result.openPorts.push({
              port,
              service: SERVICE_NAMES[port] || void 0,
              banner: banner || void 0
            });
            resolve();
          });
          if (port === 80) {
            socket.write("HEAD / HTTP/1.1\r\nHost: " + domain + "\r\n\r\n");
          } else if (port === 443) {
            socket.destroy();
            result.openPorts.push({
              port,
              service: "HTTPS"
            });
            resolve();
          } else if (port === 25 || port === 587) {
          } else if (port === 22) {
          } else {
            socket.destroy();
            result.openPorts.push({
              port,
              service: SERVICE_NAMES[port] || void 0
            });
            resolve();
          }
        });
        socket.on("error", () => {
          if (resolved)
            return;
          resolved = true;
          socket.destroy();
          resolve();
        });
        socket.on("timeout", () => {
          if (resolved)
            return;
          resolved = true;
          socket.destroy();
          resolve();
        });
        socket.connect(port, domain);
      });
    });
    await Promise.all(portPromises);
    result.total = result.openPorts.length;
    return {
      status: "success",
      scanner: "portScan",
      data: result,
      timeTaken: Date.now() - startTime
    };
  } catch (error) {
    return {
      status: "failure",
      scanner: "portScan",
      error: error.message || "Unknown error",
      data: result,
      timeTaken: Date.now() - startTime
    };
  }
};

export { createScannerInput, detectFirewall, detectForms, detectFormsInDOM, detectTechStack, extractDomain, makeRequest, normalizeUrl, safeJsonParse, scanDNSRecords, scanLibraryVulnerabilities, scanPorts, scanSecurityHeaders, scanSensitiveFiles, scanSubdomains, scanTLS, scanWaybackMachine };
//# sourceMappingURL=out.js.map
//# sourceMappingURL=index.mjs.map