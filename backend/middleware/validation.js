// backend/middleware/validation.js
import { body, validationResult } from "express-validator";
import sanitizeHtml from "sanitize-html";
import logger from "../utils/secureLogger.js";

// XSS Protection - Sanitize HTML content
export const sanitizeInput = (req, res, next) => {
  const sanitizeObject = (obj) => {
    for (let key in obj) {
      if (typeof obj[key] === "string") {
        // Remove potentially dangerous HTML/script tags
        obj[key] = sanitizeHtml(obj[key], {
          allowedTags: [], // No HTML tags allowed
          allowedAttributes: {},
          disallowedTagsMode: 'recursiveEscape'
        });
        
        // Trim whitespace
        obj[key] = obj[key].trim();
        
        // Remove SQL injection patterns
        obj[key] = obj[key].replace(/('|(--)|;|(\*)|(\|)|(%)|(<|>)|(\/\*))/gi, "");
      } else if (typeof obj[key] === "object" && obj[key] !== null) {
        sanitizeObject(obj[key]);
      }
    }
  };

  if (req.body) sanitizeObject(req.body);
  if (req.query) sanitizeObject(req.query);
  if (req.params) sanitizeObject(req.params);

  logger.info("Input sanitized", { 
    ip: req.ip, 
    path: req.path,
    method: req.method 
  });
  
  next();
};

// Validation rules for user registration
export const validateRegistration = [
  body("name")
    .trim()
    .notEmpty().withMessage("Name is required")
    .isLength({ min: 2, max: 100 }).withMessage("Name must be 2-100 characters")
    .matches(/^[a-zA-Z\s]+$/).withMessage("Name can only contain letters and spaces")
    .customSanitizer(value => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  
  body("email")
    .trim()
    .notEmpty().withMessage("Email is required")
    .isEmail().withMessage("Invalid email format")
    .normalizeEmail()
    .isLength({ max: 255 }).withMessage("Email too long")
    .customSanitizer(value => value.toLowerCase()),
  
  body("password")
    .notEmpty().withMessage("Password is required")
    .isLength({ min: 8, max: 128 }).withMessage("Password must be 8-128 characters")
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#^()_+=\-[\]{}|\\:;"'<>,.\/])/)
    .withMessage("Password must contain uppercase, lowercase, number, and special character"),
  
  body("phone")
    .trim()
    .notEmpty().withMessage("Phone number is required")
    .matches(/^[+]?[(]?[0-9]{1,4}[)]?[-\s\.]?[(]?[0-9]{1,4}[)]?[-\s\.]?[0-9]{1,9}$/)
    .withMessage("Invalid phone number format")
    .isLength({ min: 10, max: 15 }).withMessage("Phone must be 10-15 digits")
];

// Validation rules for login
export const validateLogin = [
  body("email")
    .trim()
    .notEmpty().withMessage("Email is required")
    .isEmail().withMessage("Invalid email format")
    .normalizeEmail(),
  
  body("password")
    .notEmpty().withMessage("Password is required")
];

// Validation rules for emergency alerts (GPS-based, real-time alerts)
export const validateEmergencyAlert = [
  body("location.latitude")
    .notEmpty().withMessage("Latitude is required")
    .isFloat({ min: -90, max: 90 }).withMessage("Invalid latitude"),
  
  body("location.longitude")
    .notEmpty().withMessage("Longitude is required")
    .isFloat({ min: -180, max: 180 }).withMessage("Invalid longitude"),
  
  body("emergencyType")
    .notEmpty().withMessage("Emergency type is required")
    .isIn(["medical", "fire", "police", "natural_disaster", "accident"])
    .withMessage("Invalid emergency type"),
  
  body("description")
    .trim()
    .notEmpty().withMessage("Description is required")
    .isLength({ min: 10, max: 500 }).withMessage("Description must be 10-500 characters")
    .customSanitizer(value => sanitizeHtml(value, { allowedTags: [], allowedAttributes: {} })),
  
  body("severity")
    .optional()
    .isIn(["low", "medium", "high", "critical"])
    .withMessage("Invalid severity level")
];

// Validation error handler
export const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    logger.warn("Validation failed", {
      ip: req.ip,
      path: req.path,
      errors: errors.array(),
      body: req.body
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