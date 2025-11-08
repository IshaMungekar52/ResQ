// backend/middleware/security.js
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import hpp from "hpp";
import logger from "../utils/secureLogger.js";

// ============================================
// 1. RATE LIMITING
// ============================================
export const createRateLimiter = (windowMs = 15 * 60 * 1000, max = 100) => {
  return rateLimit({
    windowMs,
    max,
    message: "Too many requests from this IP, please try again later.",
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      logger.security("Rate limit exceeded", {
        ip: req.ip,
        path: req.path,
        method: req.method
      });
      res.status(429).json({
        error: "Too many requests",
        message: "Please try again later"
      });
    }
  });
};

// Specific rate limiters
export const authLimiter = createRateLimiter(15 * 60 * 1000, 15); // 15 requests per 15 minutes
export const apiLimiter = createRateLimiter(15 * 60 * 1000, 100); // 100 requests per 15 minutes
export const strictLimiter = createRateLimiter(60 * 1000, 5); // 5 requests per minute

// ============================================
// 2. SECURITY HEADERS (Helmet)
// ============================================
export const securityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
});

// ============================================
// 3. HPP (HTTP Parameter Pollution)
// ============================================
export const parameterPollutionProtection = hpp();

// ============================================
// 4. MANUAL NoSQL INJECTION SANITIZATION
// ============================================
// ✅ FIXED: Custom sanitization without express-mongo-sanitize
const sanitizeValue = (value) => {
  if (value && typeof value === 'object') {
    // Remove any keys starting with $ or containing .
    const sanitized = {};
    for (const key in value) {
      if (!key.startsWith('$') && !key.includes('.')) {
        sanitized[key] = sanitizeValue(value[key]);
      }
    }
    return sanitized;
  }
  return value;
};

export const mongoSanitize = (req, res, next) => {
  try {
    // Sanitize request body
    if (req.body) {
      req.body = sanitizeValue(req.body);
    }
    
    // Sanitize query parameters
    if (req.query) {
      const sanitizedQuery = {};
      for (const key in req.query) {
        if (!key.startsWith('$') && !key.includes('.')) {
          sanitizedQuery[key] = sanitizeValue(req.query[key]);
        }
      }
      // Replace query object safely
      Object.keys(req.query).forEach(key => delete req.query[key]);
      Object.assign(req.query, sanitizedQuery);
    }
    
    // Sanitize params
    if (req.params) {
      req.params = sanitizeValue(req.params);
    }
    
    next();
  } catch (error) {
    logger.error("Error in mongoSanitize middleware", { error: error.message });
    next();
  }
};

// ============================================
// 5. IP BLACKLIST SYSTEM
// ============================================
const blacklistedIPs = new Map();

export const addToBlacklist = (ip, duration = 24 * 60 * 60 * 1000) => {
  const expiresAt = Date.now() + duration;
  blacklistedIPs.set(ip, expiresAt);
  
  logger.security("IP blacklisted", {
    ip,
    duration: duration / (60 * 60 * 1000) + " hours",
    expiresAt: new Date(expiresAt).toISOString()
  });
};

export const removeFromBlacklist = (ip) => {
  if (blacklistedIPs.has(ip)) {
    blacklistedIPs.delete(ip);
    logger.security("IP removed from blacklist", { ip });
    return true;
  }
  return false;
};

export const isBlacklisted = (ip) => {
  if (blacklistedIPs.has(ip)) {
    const expiresAt = blacklistedIPs.get(ip);
    
    if (Date.now() > expiresAt) {
      blacklistedIPs.delete(ip);
      return false;
    }
    return true;
  }
  return false;
};

// Clean expired blacklisted IPs every hour
setInterval(() => {
  const now = Date.now();
  for (const [ip, expiresAt] of blacklistedIPs.entries()) {
    if (now > expiresAt) {
      blacklistedIPs.delete(ip);
      logger.info("Expired blacklist entry removed", { ip });
    }
  }
}, 60 * 60 * 1000);

// ============================================
// 6. BLACKLIST CHECKER MIDDLEWARE
// ============================================
export const checkBlacklist = (req, res, next) => {
  const ip = req.ip;
  
  if (isBlacklisted(ip)) {
    logger.security("Blocked request from blacklisted IP", {
      ip,
      path: req.path,
      method: req.method
    });
    
    return res.status(403).json({
      error: "Access Denied",
      message: "Your IP has been temporarily blocked due to suspicious activity"
    });
  }
  
  next();
};

// ============================================
// 7. SUSPICIOUS PATTERN DETECTION
// ============================================
const suspiciousPatterns = [
  /(\.\.|\\|\/etc\/|\/var\/|\/usr\/)/i,  // Directory traversal
  /(\b(union|select|insert|update|delete|drop|create|alter|exec|script)\b)/i,  // SQL keywords
  /(<script|javascript:|onerror=|onload=)/i,  // XSS patterns
  /(eval\(|expression\(|vbscript:)/i,  // Code injection
];

export const detectSuspiciousPatterns = (req, res, next) => {
  const checkString = (str) => {
    return suspiciousPatterns.some(pattern => pattern.test(str));
  };

  const checkObject = (obj) => {
    for (const key in obj) {
      const value = obj[key];
      if (typeof value === 'string' && checkString(value)) {
        return true;
      } else if (typeof value === 'object' && value !== null) {
        if (checkObject(value)) return true;
      }
    }
    return false;
  };

  let suspicious = false;

  // Check URL
  if (checkString(req.url)) suspicious = true;

  // Check query parameters
  if (req.query && checkObject(req.query)) suspicious = true;

  // Check body
  if (req.body && checkObject(req.body)) suspicious = true;

  if (suspicious) {
    logger.security("Suspicious pattern detected", {
      ip: req.ip,
      path: req.path,
      method: req.method,
      userAgent: req.get("user-agent")
    });

    return res.status(400).json({
      error: "Bad Request",
      message: "Invalid input detected"
    });
  }

  next();
};

// ============================================
// 8. CORS CONFIGURATION
// ============================================
export const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      'http://localhost:3000',
      'http://localhost:5000',
      'http://127.0.0.1:3000'
    ];
    
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      logger.warn("CORS blocked", { origin });
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

// ============================================
// 9. COMBINED SECURITY MIDDLEWARE
// ============================================
export const applySecurity = (app) => {
  // Apply security headers
  app.use(securityHeaders);
  
  // Apply parameter pollution protection
  app.use(parameterPollutionProtection);
  
  // Apply custom NoSQL injection sanitization
  app.use(mongoSanitize);
  
  // Check IP blacklist
  app.use(checkBlacklist);
  
  // Detect suspicious patterns
  app.use(detectSuspiciousPatterns);
  
  // Apply rate limiting to all routes
  app.use(apiLimiter);
  
  logger.info("Security middleware applied successfully");
};

// ============================================
// 10. SECURITY REPORT
// ============================================
export const getSecurityReport = () => {
  const report = {
    timestamp: new Date().toISOString(),
    blacklistedIPs: [],
    activeBlacklists: blacklistedIPs.size
  };

  for (const [ip, expiresAt] of blacklistedIPs.entries()) {
    report.blacklistedIPs.push({
      ip,
      expiresAt: new Date(expiresAt).toISOString(),
      remainingTime: Math.max(0, Math.floor((expiresAt - Date.now()) / 1000 / 60)) + " minutes"
    });
  }

  return report;
};