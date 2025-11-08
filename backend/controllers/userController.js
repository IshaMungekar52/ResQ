import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import Citizen from "../models/Citizen.js";
import { validationResult } from "express-validator";
import logger from "../utils/logger.js";

dotenv.config();

// In-memory storage for failed login attempts
const failedLoginAttempts = new Map();

// Configuration constants
const MAX_FAILED_ATTEMPTS = 5;
const BLOCK_TIME = 10 * 60 * 1000; // 15 minutes
const ATTEMPT_WINDOW = 30 * 60 * 1000; // 30 minutes - reset counter after this time
const PROGRESSIVE_DELAY = [0, 1000, 2000, 5000, 10000]; // Progressive delays in ms

// Cleanup old entries every hour to prevent memory leaks
setInterval(() => {
  const now = Date.now();
  for (const [email, data] of failedLoginAttempts.entries()) {
    if (data.blockedUntil < now && (now - data.lastAttempt) > ATTEMPT_WINDOW) {
      failedLoginAttempts.delete(email);
    }
  }
}, 60 * 60 * 1000);

const createToken = (id, role) => {
  return jwt.sign({ id, role }, process.env.JWT_SECRET, { expiresIn: "7d" });
};

// Helper function to get client IP (for enhanced logging)
const getClientIP = (req) => {
  return req.headers['x-forwarded-for']?.split(',')[0].trim() || 
         req.headers['x-real-ip'] || 
         req.connection.remoteAddress || 
         req.socket.remoteAddress ||
         'unknown';
};

// Helper function to apply progressive delay
const applyProgressiveDelay = (attemptCount) => {
  const delayIndex = Math.min(attemptCount - 1, PROGRESSIVE_DELAY.length - 1);
  const delay = PROGRESSIVE_DELAY[delayIndex];
  return new Promise(resolve => setTimeout(resolve, delay));
};

// Citizen registration
export const registerCitizen = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn("Registration validation failed", { errors: errors.array() });
    return res.status(400).json({ errors: errors.array() });
  }
  try {
    const { name, email, password, phone } = req.body;

    if (!name || !email || !password || !phone) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const existing = await Citizen.findOne({ email });
    if (existing) {
      logger.warn("Registration attempt with existing email", { email });
      return res.status(400).json({ message: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 12); // Increased cost factor

    const citizen = await Citizen.create({
      name,
      email,
      password: hashedPassword,
      phone,
      role: "citizen"
    });

    const token = createToken(citizen._id, "citizen");

    res.status(201).json({
      user: {
        id: citizen._id,
        name: citizen.name,
        email: citizen.email,
        role: citizen.role
      },
      token
    });
    logger.info("Citizen registered successfully", { 
      userId: citizen._id, 
      email,
      ip: getClientIP(req)
    });
  } catch (error) {
    logger.error("Error during registration", { error: error.message });
    res.status(500).json({ message: "Server error during registration" });
  }
};

// Enhanced Citizen login with advanced intrusion detection
export const loginCitizen = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn("Login validation failed", { errors: errors.array() });
    return res.status(400).json({ errors: errors.array() });
  }

  const clientIP = getClientIP(req);
  const { email, password } = req.body;
  const now = Date.now();

  try {
    // Initialize or get existing attempt data
    if (!failedLoginAttempts.has(email)) {
      failedLoginAttempts.set(email, {
        count: 0,
        blockedUntil: 0,
        lastAttempt: now,
        attempts: []
      });
    }

    const attemptData = failedLoginAttempts.get(email);

    // Reset counter if last attempt was too long ago
    if (now - attemptData.lastAttempt > ATTEMPT_WINDOW) {
      attemptData.count = 0;
      attemptData.attempts = [];
      logger.info("Failed login counter reset due to timeout", { email });
    }

    // Check if currently blocked
    if (attemptData.blockedUntil > now) {
      const remainingTime = Math.ceil((attemptData.blockedUntil - now) / 1000 / 60);
      logger.warn("Blocked login attempt - account temporarily locked", { 
        email, 
        ip: clientIP,
        remainingTime,
        totalAttempts: attemptData.count
      });
      return res.status(429).json({ 
        message: `Account temporarily locked due to multiple failed login attempts. Please try again in ${remainingTime} minute(s).`,
        remainingTime,
        locked: true
      });
    }

    // Apply progressive delay based on attempt count (rate limiting)
    if (attemptData.count > 0) {
      await applyProgressiveDelay(attemptData.count);
    }

    // Find citizen in database
    const citizen = await Citizen.findOne({ email });

    // Record this attempt
    attemptData.lastAttempt = now;
    attemptData.attempts.push({
      timestamp: now,
      ip: clientIP,
      userAgent: req.headers['user-agent'] || 'unknown'
    });

    // Keep only last 10 attempts for analysis
    if (attemptData.attempts.length > 10) {
      attemptData.attempts.shift();
    }

    if (!citizen) {
      attemptData.count++;
      
      logger.warn("Failed login attempt - user not found", { 
        email, 
        ip: clientIP,
        attemptNumber: attemptData.count,
        maxAttempts: MAX_FAILED_ATTEMPTS
      });

      if (attemptData.count >= MAX_FAILED_ATTEMPTS) {
        attemptData.blockedUntil = now + BLOCK_TIME;
        logger.error("INTRUSION DETECTED - Account locked after repeated failures", { 
          email, 
          ip: clientIP,
          totalAttempts: attemptData.count,
          blockDuration: BLOCK_TIME / 1000 / 60 + " minutes"
        });
        return res.status(429).json({ 
          message: "Too many failed login attempts. Your account has been temporarily locked for security reasons. Please try again in 15 minutes.",
          locked: true
        });
      }

      const remainingAttempts = MAX_FAILED_ATTEMPTS - attemptData.count;
      return res.status(401).json({ 
        message: "Invalid credentials",
        remainingAttempts,
        warning: remainingAttempts <= 2 ? `Warning: Only ${remainingAttempts} attempt(s) remaining before account lock.` : undefined
      });
    }

    // Verify password
    const isMatch = await bcrypt.compare(password, citizen.password);

    if (!isMatch) {
      attemptData.count++;
      
      logger.warn("Failed login attempt - invalid password", { 
        email, 
        ip: clientIP,
        userId: citizen._id,
        attemptNumber: attemptData.count,
        maxAttempts: MAX_FAILED_ATTEMPTS
      });

      if (attemptData.count >= MAX_FAILED_ATTEMPTS) {
        attemptData.blockedUntil = now + BLOCK_TIME;
        logger.error("INTRUSION DETECTED - Account locked after repeated password failures", { 
          email, 
          ip: clientIP,
          userId: citizen._id,
          totalAttempts: attemptData.count,
          blockDuration: BLOCK_TIME / 1000 / 60 + " minutes",
          attemptHistory: attemptData.attempts
        });
        return res.status(429).json({ 
          message: "Too many failed login attempts. Your account has been temporarily locked for security reasons. Please try again in 15 minutes.",
          locked: true
        });
      }

      const remainingAttempts = MAX_FAILED_ATTEMPTS - attemptData.count;
      return res.status(401).json({ 
        message: "Invalid credentials",
        remainingAttempts,
        warning: remainingAttempts <= 2 ? `Warning: Only ${remainingAttempts} attempt(s) remaining before account lock.` : undefined
      });
    }

    // Successful login - reset all counters
    const previousAttempts = attemptData.count;
    failedLoginAttempts.delete(email);

    const token = createToken(citizen._id, "citizen");

    logger.info("Successful citizen login", { 
      userId: citizen._id, 
      email,
      ip: clientIP,
      previousFailedAttempts: previousAttempts
    });

    res.json({
      user: {
        id: citizen._id,
        name: citizen.name,
        email: citizen.email,
        role: citizen.role
      },
      token,
      message: previousAttempts > 0 ? "Login successful. Previous failed attempts have been cleared." : undefined
    });

  } catch (error) {
    logger.error("Error during login", { 
      error: error.message,
      email,
      ip: clientIP
    });
    res.status(500).json({ message: "Server error during login. Please try again later." });
  }
};