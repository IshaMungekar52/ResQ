// backend/routes/emergencyRoutes.js
import express from "express";
import multer from "multer";
import path from "path";
import fs from "fs";
import { body, validationResult } from "express-validator";
import { verifyToken } from "../middleware/authMiddleware.js";

// Safe logger import with fallback
let logger;
try {
  const loggerModule = await import("../utils/secureLogger.js");
  logger = loggerModule.default;
} catch (err) {
  console.warn("⚠️ secureLogger not found, using console fallback");
  logger = {
    info: console.log,
    warn: console.warn,
    error: console.error,
    intrusion: console.log,
    security: console.log
  };
}

const router = express.Router();

// ✅ CREATE UPLOADS DIRECTORY IF IT DOESN'T EXIST
const uploadsDir = "uploads/emergencies/";
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  console.log(`✅ Created directory: ${uploadsDir}`);
}

// ✅ Configure multer for photo uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${Math.round(Math.random() * 1E9)}${path.extname(file.originalname)}`;
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    if (mimetype && extname) {
      return cb(null, true);
    }
    cb(new Error("Only image files are allowed!"));
  }
});

// ✅ VALIDATION RULES FOR REPORT SUBMISSION
const validateReportSubmission = [
  body("location")
    .trim()
    .notEmpty().withMessage("Location is required")
    .isLength({ min: 2, max: 200 }).withMessage("Location must be 2-200 characters"),
  
  body("time")
    .notEmpty().withMessage("Time is required")
    .isISO8601().withMessage("Invalid date format"),
  
  body("severity")
    .notEmpty().withMessage("Severity is required")
    .isIn(["Low", "Medium", "High"]).withMessage("Severity must be Low, Medium, or High"),
  
  body("description")
    .trim()
    .notEmpty().withMessage("Description is required")
    .isLength({ min: 10, max: 1000 }).withMessage("Description must be 10-1000 characters"),
  
  body("injuries")
    .optional()
    .trim()
    .isLength({ max: 500 }).withMessage("Injuries description too long"),
  
  body("witnesses")
    .optional()
];

// ✅ VALIDATION ERROR HANDLER
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    logger.warn("Validation failed", {
      ip: req.ip,
      path: req.path,
      errors: errors.array()
    });
    
    return res.status(400).json({
      success: false,
      message: "Validation failed",
      errors: errors.array().map(err => ({
        field: err.path,
        message: err.msg
      }))
    });
  }
  
  next();
};

// ✅ POST: Submit emergency report with intrusion detection
router.post("/report", verifyToken, upload.array("photos", 5), validateReportSubmission, handleValidationErrors, async (req, res) => {
  try {
    console.log("📥 Received report submission");
    console.log("User ID:", req.user?.id);
    console.log("Request body:", req.body);
    console.log("Files:", req.files?.length || 0);
    
    const userId = req.user.id;
    const { location, time, severity, description, injuries, witnesses } = req.body;
    
    // ✅ TRACK EMERGENCY ALERT FOR FAKE DETECTION
    let isFlagged = false;
    let flagReason = "";
    let flagSeverity = "info"; // "info", "warning", "critical"
    let detectionDetails = null;
    
    if (req.intrusionDetection) {
      try {
        // Pass location and description for duplicate detection
        const detectionResult = req.intrusionDetection.track.emergencyAlert(
          userId, 
          location, 
          description
        );
        detectionDetails = detectionResult;
        
        // Determine severity based on detection results
        const alertCount = detectionResult.alertCount || 0;
        const duplicateCount = detectionResult.duplicateCount || 0;
        const similarCount = detectionResult.similarCount || 0;
        
        if (detectionResult.suspicious) {
          isFlagged = true;
          
          // Priority: Duplicates > Similar > Count
          if (duplicateCount >= 2) {
            flagSeverity = "critical";
            flagReason = `DUPLICATE ALERT: You have submitted ${duplicateCount} identical emergency reports from the same location`;
          } else if (duplicateCount >= 1) {
            flagSeverity = "warning";
            flagReason = `Duplicate report detected: You have already reported this incident`;
          } else if (similarCount >= 2) {
            flagSeverity = "warning";
            flagReason = `Multiple similar reports detected from the same location (${similarCount} similar reports)`;
          } else if (alertCount >= 5) {
            flagSeverity = "critical";
            flagReason = `EXCESSIVE REPORTS: ${alertCount} emergency alerts submitted in the last hour`;
          } else if (alertCount >= 3) {
            flagSeverity = "warning";
            flagReason = `${alertCount} emergency alerts submitted in a short time period`;
          } else {
            flagSeverity = "info";
            flagReason = "Unusual activity detected - multiple reports submitted";
          }
          
          // Log the detection result
          logger.info("Emergency alert detection check", {
            userId,
            ip: req.ip,
            suspicious: true,
            severity: flagSeverity,
            alertCount: alertCount,
            duplicateCount: duplicateCount,
            similarCount: similarCount,
            reason: flagReason
          });
          
          logger.warn(`⚠️ ${flagSeverity.toUpperCase()} ALERT FLAGGED`, {
            userId,
            ip: req.ip,
            location,
            severity,
            reason: flagReason,
            alertCount: alertCount,
            duplicates: duplicateCount,
            similar: similarCount
          });
        } else {
          logger.info("Emergency alert detection check", {
            userId,
            ip: req.ip,
            suspicious: false,
            alertCount: alertCount
          });
        }
      } catch (detectionError) {
        console.warn("⚠️ Intrusion detection error:", detectionError.message);
        // Continue even if intrusion detection fails
      }
    }
    
    // Get uploaded photo paths
    const photos = req.files ? req.files.map(file => file.path) : [];
    console.log("📸 Photos uploaded:", photos);
    
    // Parse witnesses if it's a JSON string
    let parsedWitnesses = [];
    if (witnesses) {
      try {
        parsedWitnesses = typeof witnesses === 'string' ? JSON.parse(witnesses) : witnesses;
      } catch (e) {
        console.warn("⚠️ Failed to parse witnesses:", e.message);
        parsedWitnesses = [];
      }
    }
    
    // ✅ Create emergency report object
    const emergencyReport = {
      userId,
      location,
      time,
      severity,
      description,
      injuries: injuries || "",
      witnesses: parsedWitnesses,
      photos,
      ip: req.ip,
      userAgent: req.get("user-agent"),
      flagged: isFlagged,
      createdAt: new Date()
    };
    
    console.log("✅ Emergency report created:", emergencyReport);
    
    // TODO: Save to your database
    // const savedReport = await Emergency.create(emergencyReport);
    
    logger.info("Emergency report submitted successfully", {
      userId,
      severity,
      location,
      photosCount: photos.length,
      flagged: emergencyReport.flagged
    });
    
    console.log("✅ Sending success response");
    
    // In your POST /report endpoint, replace the flagged response section with this:

if (isFlagged) {
  // Report is flagged - send warning/alert details
  const alertCount = detectionDetails?.alertCount || 0;
  const duplicateCount = detectionDetails?.duplicateCount || 0;
  const similarCount = detectionDetails?.similarCount || 0;
  
  // Determine message based on severity
  let mainMessage = "";
  if (flagSeverity === "critical") {
    mainMessage = "🚨 CRITICAL SECURITY ALERT: Account Blocked";
  } else if (flagSeverity === "warning") {
    mainMessage = "⚠️ SECURITY WARNING: Suspicious Activity Detected";
  } else {
    mainMessage = "ℹ️ SECURITY NOTICE: Multiple Reports Detected";
  }
  
  // Convert alerts array to object for frontend display
  const alertsObject = detectionDetails?.alerts 
    ? detectionDetails.alerts.reduce((acc, alert, idx) => {
        acc[idx] = alert;
        return acc;
      }, {})
    : {};
  
  res.status(flagSeverity === "critical" ? 403 : 201).json({
    success: flagSeverity !== "critical",
    blocked: flagSeverity === "critical",
    message: mainMessage,
    flagged: true,
    severity: flagSeverity,
    warning: flagReason,
    alertCount: alertCount,
    duplicateCount: duplicateCount,
    similarCount: similarCount,
    alerts: alertsObject, // Send as object, not array
    userId: userId,
    ip: req.ip,
    securityDetails: {
      reason: flagReason,
      alertCount: alertCount,
      duplicateCount: duplicateCount,
      similarCount: similarCount,
      timeWindow: "last 60 minutes",
      action: flagSeverity === "critical" 
        ? "Account has been blocked. Contact support to appeal." 
        : "Your account has been flagged for manual review by our security team.",
      timestamp: new Date().toISOString(),
      previousAlerts: alertCount
    },
    report: {
      id: emergencyReport.userId,
      location: emergencyReport.location,
      severity: emergencyReport.severity,
      timestamp: emergencyReport.createdAt,
      status: flagSeverity === "critical" ? "blocked" : "flagged"
    }
  });
} else {
  // Normal successful submission
  res.status(201).json({
    success: true,
    message: "Emergency report submitted successfully",
    flagged: false,
    severity: "success",
    report: emergencyReport
  });
}
    
  } catch (error) {
    console.error("❌ ERROR in /report endpoint:", error);
    console.error("Error stack:", error.stack);
    
    logger.error("Error submitting emergency report", {
      error: error.message,
      stack: error.stack,
      userId: req.user?.id
    });
    
    res.status(500).json({
      success: false,
      message: "Failed to submit emergency report",
      error: process.env.NODE_ENV === 'development' ? error.message : "Internal server error"
    });
  }
});

// ✅ GET: Fetch all emergency reports (admin only)
router.get("/reports", verifyToken, async (req, res) => {
  try {
    // TODO: Fetch from database
    // const reports = await Emergency.find().sort({ createdAt: -1 });
    
    logger.info("Emergency reports fetched", {
      userId: req.user.id,
      userRole: req.user.role
    });
    
    res.json({
      success: true,
      reports: [] // Replace with actual data
    });
    
  } catch (error) {
    logger.error("Error fetching emergency reports", {
      error: error.message,
      userId: req.user?.id
    });
    
    res.status(500).json({
      success: false,
      message: "Failed to fetch reports",
      error: error.message
    });
  }
});

// ✅ GET: Fetch user's own reports
router.get("/my-reports", verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;
    
    // TODO: Fetch user's reports from database
    // const reports = await Emergency.find({ userId }).sort({ createdAt: -1 });
    
    logger.info("User reports fetched", { userId });
    
    res.json({
      success: true,
      reports: [] // Replace with actual data
    });
    
  } catch (error) {
    logger.error("Error fetching user reports", {
      error: error.message,
      userId: req.user?.id
    });
    
    res.status(500).json({
      success: false,
      message: "Failed to fetch your reports",
      error: error.message
    });
  }
});

export default router;