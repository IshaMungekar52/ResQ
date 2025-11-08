// backend/utils/secureLogger.js
import winston from "winston";
import DailyRotateFile from "winston-daily-rotate-file";
import path from "path";
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const { combine, timestamp, printf, colorize, errors, json } = winston.format;

// Custom format for console output
const consoleFormat = printf(({ level, message, timestamp, ...metadata }) => {
  let msg = `${timestamp} [${level}]: ${message}`;
  
  if (Object.keys(metadata).length > 0) {
    // Mask sensitive data in console
    const sanitized = maskSensitiveData(metadata);
    msg += ` ${JSON.stringify(sanitized)}`;
  }
  
  return msg;
});

// Mask sensitive information in logs
const maskSensitiveData = (obj) => {
  const sensitiveFields = ['password', 'token', 'apiKey', 'secret', 'creditCard', 'ssn'];
  const masked = { ...obj };
  
  for (const key in masked) {
    if (sensitiveFields.some(field => key.toLowerCase().includes(field))) {
      masked[key] = '***REDACTED***';
    } else if (key === 'email') {
      // Partially mask email
      const email = masked[key];
      if (typeof email === 'string' && email.includes('@')) {
        const [local, domain] = email.split('@');
        masked[key] = `${local.substring(0, 2)}***@${domain}`;
      }
    } else if (typeof masked[key] === 'object' && masked[key] !== null) {
      masked[key] = maskSensitiveData(masked[key]);
    }
  }
  
  return masked;
};

// Security log format (detailed JSON for analysis)
const securityFormat = combine(
  timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  errors({ stack: true }),
  json()
);

// Daily rotating file transport for general logs
const generalLogTransport = new DailyRotateFile({
  filename: path.join(__dirname, '../../logs/application-%DATE%.log'),
  datePattern: 'YYYY-MM-DD',
  maxSize: '20m',
  maxFiles: '30d',
  format: combine(
    timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    json()
  )
});

// Daily rotating file transport for error logs
const errorLogTransport = new DailyRotateFile({
  filename: path.join(__dirname, '../../logs/error-%DATE%.log'),
  datePattern: 'YYYY-MM-DD',
  level: 'error',
  maxSize: '20m',
  maxFiles: '90d',
  format: securityFormat
});

// Security events log (intrusion attempts, suspicious activities)
const securityLogTransport = new DailyRotateFile({
  filename: path.join(__dirname, '../../logs/security-%DATE%.log'),
  datePattern: 'YYYY-MM-DD',
  maxSize: '50m',
  maxFiles: '365d', // Keep security logs for 1 year
  format: securityFormat
});

// Audit log (user actions, data changes)
const auditLogTransport = new DailyRotateFile({
  filename: path.join(__dirname, '../../logs/audit-%DATE%.log'),
  datePattern: 'YYYY-MM-DD',
  maxSize: '50m',
  maxFiles: '180d', // Keep audit logs for 6 months
  format: securityFormat
});

// Create logger instance
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  transports: [
    generalLogTransport,
    errorLogTransport
  ],
  exceptionHandlers: [
    new DailyRotateFile({
      filename: path.join(__dirname, '../../logs/exceptions-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      maxSize: '20m',
      maxFiles: '30d'
    })
  ],
  rejectionHandlers: [
    new DailyRotateFile({
      filename: path.join(__dirname, '../../logs/rejections-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      maxSize: '20m',
      maxFiles: '30d'
    })
  ]
});

// Add console transport in development
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: combine(
      colorize(),
      timestamp({ format: 'HH:mm:ss' }),
      consoleFormat
    )
  }));
}

// Security logger (for intrusion detection, suspicious activities)
export const securityLogger = winston.createLogger({
  level: 'warn',
  format: securityFormat,
  transports: [securityLogTransport],
  exceptionHandlers: [securityLogTransport]
});

// Audit logger (for user actions, compliance)
export const auditLogger = winston.createLogger({
  level: 'info',
  format: securityFormat,
  transports: [auditLogTransport]
});

// Log rotation cleanup
generalLogTransport.on('rotate', (oldFilename, newFilename) => {
  logger.info('Log file rotated', { oldFilename, newFilename });
});

// Enhanced logging methods
logger.security = (message, metadata = {}) => {
  securityLogger.error(message, {
    ...metadata,
    timestamp: new Date().toISOString(),
    category: 'SECURITY'
  });
};

logger.audit = (action, metadata = {}) => {
  auditLogger.info(action, {
    ...metadata,
    timestamp: new Date().toISOString(),
    category: 'AUDIT'
  });
};

// Log suspicious activity
logger.suspicious = (message, metadata = {}) => {
  securityLogger.warn(message, {
    ...metadata,
    timestamp: new Date().toISOString(),
    category: 'SUSPICIOUS',
    severity: 'HIGH'
  });
};

// Log authentication events
logger.auth = (event, metadata = {}) => {
  auditLogger.info(`AUTH: ${event}`, {
    ...maskSensitiveData(metadata),
    timestamp: new Date().toISOString(),
    category: 'AUTHENTICATION'
  });
};

// Log data access
logger.dataAccess = (resource, action, metadata = {}) => {
  auditLogger.info(`DATA ACCESS: ${action} on ${resource}`, {
    ...maskSensitiveData(metadata),
    timestamp: new Date().toISOString(),
    category: 'DATA_ACCESS'
  });
};

export default logger;