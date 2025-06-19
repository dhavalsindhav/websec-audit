'use strict';

var axios = require('axios');
var cheerio = require('cheerio');

function _interopDefault (e) { return e && e.__esModule ? e : { default: e }; }

function _interopNamespace(e) {
  if (e && e.__esModule) return e;
  var n = Object.create(null);
  if (e) {
    Object.keys(e).forEach(function (k) {
      if (k !== 'default') {
        var d = Object.getOwnPropertyDescriptor(e, k);
        Object.defineProperty(n, k, d.get ? d : {
          enumerable: true,
          get: function () { return e[k]; }
        });
      }
    });
  }
  n.default = e;
  return Object.freeze(n);
}

var axios__default = /*#__PURE__*/_interopDefault(axios);
var cheerio__namespace = /*#__PURE__*/_interopNamespace(cheerio);

// src/core/request.ts
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
    const response = await axios__default.default(config);
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
    const $ = cheerio__namespace.load(html);
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

exports.detectForms = detectForms;
exports.detectFormsInDOM = detectFormsInDOM;
exports.scanSecurityHeaders = scanSecurityHeaders;
//# sourceMappingURL=out.js.map
//# sourceMappingURL=index.js.map