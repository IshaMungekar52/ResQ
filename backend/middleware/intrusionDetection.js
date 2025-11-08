// backend/middleware/intrusionDetection.js
import logger from "../utils/secureLogger.js";
import { addToBlacklist } from "./security.js";

// Store suspicious activity data
const activityTracker = new Map();
const alertTracker = new Map();
const alertHistory = {}; // Track alert history
const validationErrorHistory = {}; // Track validation errors per user

// Thresholds
const THRESHOLDS = {
  MAX_FAILED_LOGINS: 5,
  MAX_ALERTS_PER_HOUR: 3,
  MAX_VALIDATION_ERRORS: 5,  // Account blocked after 5 validation errors
  MAX_404_ERRORS: 20,
  TIME_WINDOW: 60 * 60 * 1000, // 1 hour
  ALERT_TIME_WINDOW: 60 * 60 * 1000, // 1 hour for alerts
  IP_BLOCK_THRESHOLD: 3,      // Block IP after 3 reports (IP first strategy)
  ACCOUNT_FLAG_THRESHOLD: 5   // Block account after 5 reports (Account second strategy)
};

// Calculate string similarity (Levenshtein distance)
function calculateSimilarity(str1, str2) {
  const len1 = str1.length;
  const len2 = str2.length;
  const matrix = Array(len2 + 1).fill(null).map(() => Array(len1 + 1).fill(0));

  for (let i = 0; i <= len1; i++) matrix[0][i] = i;
  for (let j = 0; j <= len2; j++) matrix[j][0] = j;

  for (let j = 1; j <= len2; j++) {
    for (let i = 1; i <= len1; i++) {
      const cost = str1[i - 1] === str2[j - 1] ? 0 : 1;
      matrix[j][i] = Math.min(
        matrix[j][i - 1] + 1,
        matrix[j - 1][i] + 1,
        matrix[j - 1][i - 1] + cost
      );
    }
  }

  const maxLen = Math.max(len1, len2);
  return maxLen === 0 ? 1 : 1 - matrix[len2][len1] / maxLen;
}

// Enhanced emergency alert tracking with duplicate detection
export function trackEmergencyAlert(req, userId, location, description) {
  const now = Date.now();
  const ONE_HOUR = 60 * 60 * 1000;
  const ip = req.ip;

  if (!alertHistory[userId]) {
    alertHistory[userId] = [];
  }

  // Clean up old alerts (older than 1 hour)
  alertHistory[userId] = alertHistory[userId].filter(
    alert => now - alert.timestamp < ONE_HOUR
  );

  // Check for duplicates or very similar reports
  let duplicateCount = 0;
  let similarCount = 0;
  
  for (const alert of alertHistory[userId]) {
    // Exact location match
    if (alert.location === location) {
      // Check description similarity
      if (alert.description === description) {
        duplicateCount++;
      } else {
        const similarity = calculateSimilarity(
          alert.description.toLowerCase(), 
          description.toLowerCase()
        );
        if (similarity > 0.8) { // 80% similar
          similarCount++;
        }
      }
    }
  }

  // Add current alert to history
  alertHistory[userId].push({
    timestamp: now,
    ip: ip,
    location,
    description
  });

  const totalAlerts = alertHistory[userId].length;
  let suspicious = false;
  let message = "";
  let severity = "info";
  let ipBlocked = false;
  let accountBlocked = false;

  // SECURITY STRATEGY: IP blocking first (network level), then account blocking (user level)
  
  // CRITICAL: Duplicate reports - Block both IP and Account immediately
  if (duplicateCount >= 2) {
    suspicious = true;
    severity = "critical";
    message = "DUPLICATE REPORTS: Exact same report submitted multiple times";
    ipBlocked = true;
    accountBlocked = true;
  } 
  // HIGH: Single duplicate or multiple similar - Block IP first
  else if (duplicateCount >= 1) {
    suspicious = true;
    severity = "warning";
    message = "Duplicate report detected from the same location";
    ipBlocked = true; // Block IP immediately
  } 
  else if (similarCount >= 2) {
    suspicious = true;
    severity = "warning";
    message = "Multiple similar reports detected from the same location";
    ipBlocked = true; // Block IP immediately
  } 
  // MEDIUM: Reaching IP threshold - Block IP (3+ reports)
  else if (totalAlerts >= THRESHOLDS.IP_BLOCK_THRESHOLD) {
    suspicious = true;
    severity = "warning";
    ipBlocked = true;
    message = "Multiple emergency alerts detected in short time. IP temporarily blocked.";
  }
  // HIGH: Reached account threshold - Block Account (5+ reports)
  else if (totalAlerts >= THRESHOLDS.ACCOUNT_FLAG_THRESHOLD) {
    suspicious = true;
    severity = "critical";
    accountBlocked = true;
    ipBlocked = true; // Also block IP at this point
    message = "Too many emergency alerts. Account suspended for review.";
  }

  // Block IP if necessary
  if (ipBlocked) {
    const blockDuration = severity === "critical" ? 24 * 60 * 60 * 1000 : 60 * 60 * 1000; // 24 hours for critical, 1 hour for warning
    addToBlacklist(ip, blockDuration);
    
    logger.error("🚫 IP BLOCKED", {
      ip,
      userId,
      severity,
      duration: blockDuration / (60 * 60 * 1000) + " hours",
      reason: message
    });
  }

  if (suspicious) {
    logger.error("🚨 FAKE ALERT DETECTION - Multiple emergency alerts", {
      userId,
      ip: ip,
      alertCount: totalAlerts,
      duplicateCount,
      similarCount,
      severity,
      ipBlocked,
      accountBlocked,
      timeWindow: "1 hour",
      alerts: alertHistory[userId]
    });

    // Send email notification for critical cases
    if (severity === "critical") {
      logger.error("📧 SECURITY ALERT: Fake Emergency Alerts", {
        userId,
        ip: ip,
        count: totalAlerts,
        duplicates: duplicateCount,
        ipBlocked,
        accountBlocked
      });
    }
  }

  logger.info("Emergency alert detection check", {
    userId,
    ip: ip,
    suspicious,
    severity,
    alertCount: totalAlerts,
    duplicateCount,
    similarCount,
    ipBlocked,
    accountBlocked,
    reason: message || "Unusual activity detected - multiple reports submitted"
  });

  if (suspicious) {
    logger.warn(`⚠️ ${severity.toUpperCase()} ALERT FLAGGED`, {
      userId,
      ip: ip,
      location,
      severity,
      reason: message,
      alertCount: totalAlerts,
      duplicates: duplicateCount,
      similar: similarCount,
      ipBlocked,
      accountBlocked
    });
  }

  return {
    suspicious,
    severity,
    message: message || "Unusual activity detected - multiple reports submitted",
    alertCount: totalAlerts,
    duplicateCount,
    similarCount,
    ipBlocked,
    accountBlocked,
    alerts: alertHistory[userId]
  };
}

// Send security alert (implement your notification system)
const sendSecurityAlert = (alertType, details) => {
  logger.error(`📧 SECURITY ALERT: ${alertType}`, details);
  
  // TODO: Implement email/SMS notification
  // Example: sendEmail(admin, `Security Alert: ${alertType}`, details);
  // Example: sendSMS(adminPhone, `ALERT: ${alertType}`);
};

// Middleware to integrate with Express
export const intrusionDetectionMiddleware = (req, res, next) => {
  const ip = req.ip;
  
  // Add intrusion detection context to request
  req.intrusionDetection = {
    track: {
      emergencyAlert: (userId, location, description) => 
        trackEmergencyAlert(req, userId, location, description)
    }
  };
  
  next();
};