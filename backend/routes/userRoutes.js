import express from "express";
import { registerCitizen, loginCitizen } from "../controllers/userController.js";
import { body } from "express-validator";

const router = express.Router();

// Citizen Registration Route
router.post(
  "/register",
  [
    body("name").trim().notEmpty().withMessage("Name is required"),
    body("email").isEmail().withMessage("Valid email required"),
    body("password")
      .isLength({ min: 6 })
      .withMessage("Password must be at least 6 characters")
      .matches(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&^()_+=<>/\\|{}[\]-])/)
      .withMessage("Password must contain at least one letter, one number, and one special character"),
    body("phone").trim().notEmpty().withMessage("Phone is required")
  ],
  registerCitizen
);

// Citizen Login Route
router.post(
  "/login",
  [
    body("email").isEmail().withMessage("Valid email required"),
    body("password").notEmpty().withMessage("Password is required")
  ],
  loginCitizen
);

// THIS IS CRITICAL - Must have default export
export default router;