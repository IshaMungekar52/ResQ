// backend/controllers/emergencyController.js
import logger from "../utils/logger.js";

export const createEmergencyReport = async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Validate required fields
    const validationErrors = [];
    if (!req.body.location) validationErrors.push({ field: 'location', message: 'Location is required' });
    if (!req.body.time) validationErrors.push({ field: 'time', message: 'Time is required' });
    if (!req.body.severity) validationErrors.push({ field: 'severity', message: 'Severity is required' });
    if (!req.body.description) validationErrors.push({ field: 'description', message: 'Description is required' });
    
    // Track validation errors
    if (validationErrors.length > 0) {
      const validationCheck = req.intrusionDetection.track.validationError(userId, 'missing_fields');
      
      // If account is blocked due to validation errors
      if (validationCheck.accountBlocked) {
        logger.error("🚫 ACCOUNT BLOCKED - Validation Errors", {
          userId,
          ip: req.ip,
          errorCount: validationCheck.errorCount,
          reason: validationCheck.message
        });
        
        return res.status(403).json({
          success: false,
          flagged: true,
          accountBlocked: true,
          ipBlocked: validationCheck.ipBlocked,
          blocked: true,
          severity: validationCheck.severity,
          message: validationCheck.message,
          validationErrorCount: validationCheck.errorCount,
          userId: req.user.id,
          ip: req.ip,
          securityDetails: {
            timeWindow: "last 60 minutes",
            totalValidationErrors: validationCheck.errorCount,
            ipBlockStatus: validationCheck.ipBlocked ? 'BLOCKED' : 'ACTIVE',
            accountStatus: 'SUSPENDED',
            action: 'Account suspended due to repeated validation errors',
            reason: validationCheck.message
          }
        });
      }
      
      // Return validation errors but allow retry
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: validationErrors
      });
    }
    
    // Track this emergency alert
    const detectionResult = req.intrusionDetection.track.emergencyAlert(
      userId,
      req.body.location,
      req.body.description
    );

    logger.info("Emergency alert detection check", {
      userId,
      ip: req.ip,
      suspicious: detectionResult.suspicious,
      severity: detectionResult.severity,
      alertCount: detectionResult.alertCount,
      duplicateCount: detectionResult.duplicateCount,
      similarCount: detectionResult.similarCount,
      ipBlocked: detectionResult.ipBlocked,
      accountBlocked: detectionResult.accountBlocked,
      reason: detectionResult.message
    });

    // If suspicious activity detected
    if (detectionResult.suspicious) {
      logger.warn(`⚠️ ${detectionResult.severity.toUpperCase()} ALERT FLAGGED`, {
        userId: req.user.id,
        ip: req.ip,
        location: req.body.location,
        severity: req.body.severity,
        reason: detectionResult.message,
        alertCount: detectionResult.alertCount,
        duplicates: detectionResult.duplicateCount,
        similar: detectionResult.similarCount,
        ipBlocked: detectionResult.ipBlocked,
        accountBlocked: detectionResult.accountBlocked
      });

      // IMPORTANT: Return detection data to frontend
      return res.status(200).json({
        success: true,
        flagged: true,
        severity: detectionResult.severity,
        ipBlocked: detectionResult.ipBlocked,
        accountBlocked: detectionResult.accountBlocked,
        blocked: detectionResult.ipBlocked || detectionResult.accountBlocked,
        message: detectionResult.message,
        warning: detectionResult.message,
        alertCount: detectionResult.alertCount,
        duplicateCount: detectionResult.duplicateCount,
        similarCount: detectionResult.similarCount,
        alerts: detectionResult.alerts,
        userId: req.user.id,
        ip: req.ip,
        securityDetails: {
          timeWindow: "last 60 minutes",
          previousAlerts: detectionResult.alertCount,
          ipBlockStatus: detectionResult.ipBlocked ? 'BLOCKED' : 'ACTIVE',
          accountStatus: detectionResult.accountBlocked ? 'SUSPENDED' : 'FLAGGED',
          action: detectionResult.ipBlocked 
            ? 'IP address blocked - All requests from this IP will be denied' 
            : detectionResult.accountBlocked 
              ? 'Account suspended for review' 
              : 'Warning issued',
          reason: detectionResult.message
        }
      });
    }
    
    // Log photos
    const photos = req.files?.map(f => f.path) || [];
    console.log("📸 Photos uploaded:", photos);
    
    // Create the emergency report (even if flagged)
    const emergencyReport = {
      userId,
      location: req.body.location,
      time: req.body.time,
      severity: req.body.severity,
      description: req.body.description,
      injuries: req.body.injuries || '',
      witnesses: req.body.witnesses || [],
      photos,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      flagged: detectionResult.suspicious,
      createdAt: new Date()
    };
    
    console.log("✅ Emergency report created:", emergencyReport);
    
    logger.info("Emergency report submitted successfully", {
      userId,
      severity: req.body.severity,
      location: req.body.location,
      photosCount: photos.length,
      flagged: detectionResult.suspicious
    });
    
    console.log("✅ Sending success response");
    
    // Return success response for clean submissions
    res.status(200).json({
      success: true,
      message: "Emergency report submitted successfully",
      flagged: false,
      ipBlocked: false,
      accountBlocked: false,
      userId,
      location: req.body.location,
      reportSeverity: req.body.severity,
      report: {
        id: emergencyReport.userId + '-' + Date.now(),
        createdAt: emergencyReport.createdAt
      }
    });
    
  } catch (error) {
    logger.error("Error creating emergency report", {
      error: error.message,
      stack: error.stack,
      userId: req.user?.id,
      ip: req.ip
    });
    
    res.status(500).json({
      success: false,
      message: "Failed to submit emergency report",
      error: error.message
    });
  }
};