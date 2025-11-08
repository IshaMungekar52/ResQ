// backend/server.js
import express from "express";
import dotenv from "dotenv";
import connectDB from "./config/db.js";
import cors from "cors";
import path from "path";
import { fileURLToPath } from "url";
import { createServer } from "http";
import { Server } from "socket.io";

// ✅ Import security middleware
import {
  sanitizeInput,
  handleValidationErrors
} from "./middleware/validation.js";

import { 
  authLimiter, 
  apiLimiter,
  securityHeaders,
  mongoSanitize,
  checkBlacklist,
  detectSuspiciousPatterns,
  parameterPollutionProtection
} from "./middleware/security.js";
import { intrusionDetectionMiddleware } from "./middleware/intrusionDetection.js";
import logger from "./utils/secureLogger.js";

// ✅ Import routes
import userRoutes from "./routes/userRoutes.js";
import responderRoutes from "./routes/responderRoutes.js";
import emergencyRoutes from "./routes/emergencyRoutes.js";
import citizenRoutes from "./routes/citizenRoutes.js";

dotenv.config();
connectDB();

const app = express();
const httpServer = createServer(app);

// ============================================
// SOCKET.IO CONFIGURATION
// ============================================
export const io = new Server(httpServer, {
  cors: {
    origin: "*",
    methods: ["GET", "POST", "PUT"],
  },
});

io.on("connection", (socket) => {
  console.log("⚡ Responder connected:", socket.id);
  logger.info("Socket.IO connection", { socketId: socket.id });

  socket.on("disconnect", () => {
    console.log("❌ Responder disconnected:", socket.id);
    logger.info("Socket.IO disconnection", { socketId: socket.id });
  });
});

// ============================================
// BASIC MIDDLEWARE (BEFORE SECURITY)
// ============================================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// Trust proxy (important for getting real IP addresses)
app.set('trust proxy', 1);

// ============================================
// SECURITY MIDDLEWARE (IN CORRECT ORDER)
// ============================================
// 1. Security headers first
app.use(securityHeaders);

// 2. Parameter pollution protection
app.use(parameterPollutionProtection);

// 3. Custom NoSQL injection sanitization
app.use(mongoSanitize);

// 4. Input sanitization (NOT validation - that's route-specific)
app.use(sanitizeInput);

// 5. Check IP blacklist
app.use(checkBlacklist);

// 6. Detect suspicious patterns
app.use(detectSuspiciousPatterns);

// 7. Intrusion detection tracking
app.use(intrusionDetectionMiddleware);

// 8. API rate limiting (general) - applied to all /api routes
app.use('/api/', apiLimiter);

logger.info("✅ All security middleware loaded successfully");

// ============================================
// STATIC FILES
// ============================================
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// ============================================
// ROUTES (WITH SECURITY)
// ============================================
// Auth-related routes with stricter rate limiting
app.use("/api/users", authLimiter, userRoutes);

// Other routes with standard API rate limiting
app.use("/api/responders", responderRoutes);
app.use("/api/emergencies", emergencyRoutes);
app.use("/api/citizens", citizenRoutes);

// Health check endpoint (no rate limit or security - for monitoring)
app.get("/", (req, res) => {
  res.json({ 
    status: "OK",
    message: "API and WebSocket server running...",
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

app.get("/health", (req, res) => {
  res.json({ 
    status: "healthy", 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    security: "active",
    intrusionDetection: "active"
  });
});

// ============================================
// ERROR HANDLING
// ============================================
// 404 handler - track potential directory scanning
app.use((req, res) => {
  // Track 404 errors for intrusion detection
  if (req.intrusionDetection) {
    req.intrusionDetection.track.notFoundError();
  }
  
  logger.warn("404 Not Found", {
    path: req.path,
    method: req.method,
    ip: req.ip,
    userAgent: req.get("user-agent")
  });
  
  res.status(404).json({ 
    error: "Not Found",
    message: "The requested resource does not exist"
  });
});

// Global error handler
app.use((err, req, res, next) => {
  logger.error("Server error", {
    error: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
    ip: req.ip
  });

  res.status(err.status || 500).json({
    error: err.name || "Internal Server Error",
    message: process.env.NODE_ENV === 'production' 
      ? "An error occurred" 
      : err.message
  });
});

// ============================================
// PROCESS ERROR HANDLERS
// ============================================
// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error("Uncaught Exception", {
    error: error.message,
    stack: error.stack
  });
  console.error("💥 Uncaught Exception:", error);
  process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (error) => {
  logger.error("Unhandled Rejection", {
    error: error.message,
    stack: error.stack
  });
  console.error("💥 Unhandled Rejection:", error);
  process.exit(1);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info("SIGTERM received, shutting down gracefully");
  httpServer.close(() => {
    logger.info("Server closed");
    process.exit(0);
  });
});

// ============================================
// START SERVER
// ============================================
const PORT = process.env.PORT || 5000;
httpServer.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════╗
║   🏥 Healthcare Server Started       ║
║   📡 Port: ${PORT}                     ║
║   🔒 Security: ACTIVE                 ║
║   🛡️  Intrusion Detection: ACTIVE     ║
║   ⚡ Socket.IO: ACTIVE                ║
╚═══════════════════════════════════════╝
  `);
  
  logger.info(`✅ Server running on port ${PORT}`);
  logger.info(`🔒 Security features active`);
  logger.info(`📊 Intrusion detection active`);
  logger.info(`⚡ Socket.IO server active`);
  logger.info(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
});