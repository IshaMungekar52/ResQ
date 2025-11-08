import React, { useState, useEffect } from "react";
import axios from "axios";
import { Link } from "react-router-dom";
import { FaUser, FaLock, FaUserShield, FaSignInAlt, FaExclamationTriangle, FaShieldAlt } from "react-icons/fa";

function LoginPage() {
  const [formData, setFormData] = useState({
    email: "",
    password: "",
    userType: "citizen",
  });

  const [loading, setLoading] = useState(false);
  const [securityAlert, setSecurityAlert] = useState(null);
  const [remainingAttempts, setRemainingAttempts] = useState(null);
  const [isLocked, setIsLocked] = useState(false);

  // Clear alerts after 10 seconds
  useEffect(() => {
    if (securityAlert && !isLocked) {
      const timer = setTimeout(() => {
        setSecurityAlert(null);
        setRemainingAttempts(null);
      }, 10000);
      return () => clearTimeout(timer);
    }
  }, [securityAlert, isLocked]);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData((prevState) => ({
      ...prevState,
      [name]: value,
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    // Clear previous alerts
    setSecurityAlert(null);
    setRemainingAttempts(null);

    setLoading(true);

    try {
      const endpoint = `http://localhost:5000/api/${formData.userType}s/login`;
      const response = await axios.post(endpoint, {
        email: formData.email,
        password: formData.password,
      });

      // Save Login Session
      localStorage.setItem("userType", formData.userType);
      localStorage.setItem("isAuthenticated", "true");
      localStorage.setItem("userData", JSON.stringify(response.data));

      // Show success message if there were previous failed attempts
      if (response.data.message) {
        setSecurityAlert({
          type: "success",
          message: response.data.message
        });
        setTimeout(() => {
          window.location.href = formData.userType === "responder" ? "/dashboard" : "/";
        }, 1500);
      } else {
        // Redirect by User Type
        window.location.href = formData.userType === "responder" ? "/dashboard" : "/";
      }

    } catch (error) {
      let errMsg = "Login failed. Please try again.";
      let alertType = "error";

      if (error.response?.status === 429) {
        // Account locked
        errMsg = error.response.data.message || "Too many failed login attempts. Your account has been temporarily locked.";
        alertType = "locked";
        setIsLocked(true);
        setRemainingAttempts(null);
        
        // Auto-refresh after lock expires (optional)
        if (error.response.data.remainingTime) {
          setTimeout(() => {
            window.location.reload();
          }, error.response.data.remainingTime * 60 * 1000);
        }
      } else if (error.response?.status === 401) {
        // Invalid credentials with attempt tracking
        errMsg = error.response.data.message || "Invalid credentials";
        
        if (error.response.data.remainingAttempts !== undefined) {
          setRemainingAttempts(error.response.data.remainingAttempts);
          
          if (error.response.data.warning) {
            alertType = "warning";
            errMsg = error.response.data.warning;
          }
        }
      } else if (error.response?.data?.message) {
        errMsg = error.response.data.message;
      } else if (error.message === "Network Error") {
        errMsg = "Cannot connect to backend. Please check your server.";
      }

      setSecurityAlert({
        type: alertType,
        message: errMsg
      });

    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <div className="page-header">
        <h1>Welcome Back</h1>
        <p>Sign in to your ResQNow account</p>
      </div>

      <div className="login-container">
        {/* Security Alert Banner */}
        {securityAlert && (
          <div className={`security-alert ${securityAlert.type}`}>
            {securityAlert.type === "locked" && <FaShieldAlt className="alert-icon" />}
            {securityAlert.type === "warning" && <FaExclamationTriangle className="alert-icon" />}
            <div className="alert-content">
              <strong>
                {securityAlert.type === "locked" && "Account Locked"}
                {securityAlert.type === "warning" && "Security Warning"}
                {securityAlert.type === "error" && "Login Failed"}
                {securityAlert.type === "success" && "Login Successful"}
              </strong>
              <p>{securityAlert.message}</p>
              {remainingAttempts !== null && (
                <div className="attempts-remaining">
                  <strong>Remaining attempts: {remainingAttempts}</strong>
                </div>
              )}
            </div>
          </div>
        )}

        <form className="login-form" onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="userType">
              <FaUserShield className="form-icon" /> I am a *
            </label>
            <select
              id="userType"
              name="userType"
              value={formData.userType}
              onChange={handleInputChange}
              required
              disabled={isLocked}
            >
              <option value="citizen">Citizen</option>
              <option value="responder">Emergency Responder</option>
            </select>
          </div>

          <div className="form-group">
            <label htmlFor="email">
              <FaUser className="form-icon" /> Email Address *
            </label>
            <input
              type="email"
              id="email"
              name="email"
              placeholder="Enter your email address"
              value={formData.email}
              onChange={handleInputChange}
              required
              disabled={isLocked}
            />
          </div>

          <div className="form-group">
            <label htmlFor="password">
              <FaLock className="form-icon" /> Password *
            </label>
            <input
              type="password"
              id="password"
              name="password"
              placeholder="Enter your password"
              value={formData.password}
              onChange={handleInputChange}
              required
              disabled={isLocked}
            />
          </div>

          <div className="form-options">
            <label className="remember-me">
              <input type="checkbox" disabled={isLocked} />
              <span>Remember me</span>
            </label>
            <Link to="/forgot-password" className="forgot-password">
              Forgot Password?
            </Link>
          </div>

          <button type="submit" className="login-btn" disabled={loading || isLocked}>
            {loading ? (
              <span>Signing In...</span>
            ) : isLocked ? (
              <span>Account Locked</span>
            ) : (
              <>
                <FaSignInAlt className="btn-icon" /> Sign In
              </>
            )}
          </button>

          <div className="signup-link">
            <p>
              Don't have an account? <Link to="/register">Sign up here</Link>
            </p>
          </div>
        </form>

        {/* Security Info */}
        <div className="security-info">
          <FaShieldAlt className="shield-icon" />
          <small>
            Protected by advanced intrusion detection. Your account will be temporarily locked after 5 failed login attempts.
          </small>
        </div>
      </div>

      <style jsx>{`
        .security-alert {
          padding: 16px 20px;
          border-radius: 8px;
          margin-bottom: 20px;
          display: flex;
          align-items: flex-start;
          gap: 12px;
          animation: slideIn 0.3s ease-out;
          box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }

        @keyframes slideIn {
          from {
            opacity: 0;
            transform: translateY(-10px);
          }
          to {
            opacity: 1;
            transform: translateY(0);
          }
        }

        .security-alert.locked {
          background: #fee;
          border: 2px solid #dc3545;
          color: #721c24;
        }

        .security-alert.warning {
          background: #fff3cd;
          border: 2px solid #ffc107;
          color: #856404;
        }

        .security-alert.error {
          background: #f8d7da;
          border: 2px solid #dc3545;
          color: #721c24;
        }

        .security-alert.success {
          background: #d4edda;
          border: 2px solid #28a745;
          color: #155724;
        }

        .alert-icon {
          font-size: 24px;
          flex-shrink: 0;
          margin-top: 2px;
        }

        .alert-content {
          flex: 1;
        }

        .alert-content strong {
          display: block;
          margin-bottom: 4px;
          font-size: 16px;
        }

        .alert-content p {
          margin: 0;
          font-size: 14px;
        }

        .attempts-remaining {
          margin-top: 8px;
          padding: 8px 12px;
          background: rgba(0,0,0,0.05);
          border-radius: 4px;
          font-size: 13px;
        }

        .security-info {
          margin-top: 20px;
          padding: 12px;
          background: #e7f3ff;
          border-radius: 6px;
          display: flex;
          align-items: center;
          gap: 10px;
          color: #004085;
        }

        .shield-icon {
          font-size: 20px;
          color: #0066cc;
        }

        .security-info small {
          font-size: 12px;
          line-height: 1.4;
        }

        .login-btn:disabled {
          opacity: 0.6;
          cursor: not-allowed;
        }

        input:disabled, select:disabled {
          background: #f5f5f5;
          cursor: not-allowed;
        }
      `}</style>
    </div>
  );
}

export default LoginPage;