import React, { useState } from "react";
import axios from "axios";
import "./Step4ReviewSubmit.css";

function Step4ReviewSubmit({ formData, updateFormData, prevStep }) {
  const [loading, setLoading] = useState(false);
  const [submitStatus, setSubmitStatus] = useState(null); // null, 'success', 'flagged', 'error'

  // --- Handle actual submission ---
  const handleSubmit = async () => {
    try {
      setLoading(true);
      setSubmitStatus(null);

      // get citizen token from localStorage
      const userData = JSON.parse(localStorage.getItem("userData") || "{}");
      const token = userData?.token;
      if (!token) {
        setSubmitStatus({
          type: 'error',
          message: 'Please login again — no token found.'
        });
        setLoading(false);
        return;
      }

      // build FormData to send files + JSON data
      const reportData = new FormData();
      reportData.append("location", formData.location);
      reportData.append("time", formData.time);
      reportData.append("severity", formData.severity);
      reportData.append("description", formData.description);
      reportData.append("injuries", formData.injuries);
      reportData.append("witnesses", JSON.stringify(formData.witnesses || []));
      if (formData.photos?.length > 0) {
        formData.photos.forEach((photo) => reportData.append("photos", photo));
      }

      // --- send to backend ---
      const res = await axios.post(
        "http://localhost:5000/api/emergencies/report",
        reportData,
        {
          headers: {
            "Content-Type": "multipart/form-data",
            Authorization: `Bearer ${token}`,
          },
        }
      );

      console.log("Response from backend:", res.data);

      // Check if report was flagged as suspicious
      if (res.data.flagged || res.data.warning) {
        setSubmitStatus({
          type: 'flagged',
          severity: res.data.severity || 'warning', // info, warning, critical
          blocked: res.data.blocked || false,
          message: res.data.message || 'Your report has been flagged for review.',
          reason: res.data.warning || res.data.securityDetails?.reason,
          details: res.data.securityDetails,
          alertCount: res.data.alertCount,
          duplicateCount: res.data.duplicateCount,
          similarCount: res.data.similarCount,
          alerts: res.data.alerts,
          userId: res.data.userId,
          ip: res.data.ip
        });
      } else {
        setSubmitStatus({
          type: 'success',
          message: 'Report submitted successfully!'
        });
        
        // Only reset form if submission was clean (not flagged)
        setTimeout(() => {
          updateFormData({
            location: "",
            time: "",
            severity: "Low",
            photos: [],
            description: "",
            injuries: "",
            witnesses: [],
          });
        }, 2000);
      }

    } catch (err) {
      console.error("❌ Error submitting report:", err.response?.data || err.message);
      setSubmitStatus({
        type: 'error',
        message: err.response?.data?.message || "Failed to submit report. Please try again.",
        errors: err.response?.data?.errors
      });
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case "Low": return "severity-low";
      case "Medium": return "severity-medium";
      case "High": return "severity-high";
      default: return "severity-low";
    }
  };

  return (
    <div className="step-container">
      <h2 className="step-title">Review & Submit</h2>

      {/* Status Messages */}
      {submitStatus && (
        <div className={`submit-status ${submitStatus.type}`}>
          {submitStatus.type === 'flagged' && (
            <div className={`flagged-alert ${submitStatus.severity}`}>
              <div className="alert-content">
                <p className="alert-message">{submitStatus.message}</p>
                
                {/* Show the specific reason */}
                {submitStatus.reason && (
                  <div className="reason-box">
                    <strong>Reason:</strong> {submitStatus.reason}
                  </div>
                )}
                
                {submitStatus.alertCount > 0 && (
                  <p className="alert-details">
                    <strong>Alert Count:</strong> {submitStatus.alertCount} reports in the last hour
                  </p>
                )}

                {submitStatus.duplicateCount > 0 && (
                  <p className="alert-details">
                    <strong>Duplicate Reports:</strong> {submitStatus.duplicateCount}
                  </p>
                )}

                {submitStatus.similarCount > 0 && (
                  <p className="alert-details">
                    <strong>Similar Reports:</strong> {submitStatus.similarCount}
                  </p>
                )}

                {/* Display all alerts from the last hour */}
                {submitStatus.alerts && Object.keys(submitStatus.alerts).length > 0 && (
                  <div className="alerts-history">
                    <h4>🚨 Recent Alert History (Last Hour)</h4>
                    <div className="alerts-list">
                      {Object.entries(submitStatus.alerts).map(([key, alert]) => (
                        <div key={key} className="alert-history-item">
                          <span className="alert-number">#{parseInt(key) + 1}</span>
                          <span className="alert-time">
                            {new Date(alert.timestamp).toLocaleTimeString()}
                          </span>
                          <span className="alert-location">{alert.location}</span>
                          <span className="alert-ip">IP: {alert.ip}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Display User ID and IP */}
                {(submitStatus.userId || submitStatus.ip) && (
                  <div className="detection-details">
                    <h4>🔍 Detection Information</h4>
                    {submitStatus.userId && (
                      <p><strong>User ID:</strong> {submitStatus.userId}</p>
                    )}
                    {submitStatus.ip && (
                      <p><strong>IP Address:</strong> {submitStatus.ip}</p>
                    )}
                  </div>
                )}
                
                {submitStatus.details && (
                  <div className="security-details">
                    <p><strong>Time Window:</strong> {submitStatus.details.timeWindow}</p>
                    <p><strong>Previous Alerts:</strong> {submitStatus.details.previousAlerts}</p>
                    <p><strong>Action Taken:</strong> {submitStatus.details.action}</p>
                    {!submitStatus.blocked && (
                      <p><strong>Next Steps:</strong> If this is a genuine emergency, please contact emergency services directly at <strong>112</strong> or your local emergency number.</p>
                    )}
                  </div>
                )}
                
                <div className={`warning-box ${submitStatus.severity}`}>
                  {submitStatus.blocked ? (
                    <>
                      <p>🚫 <strong>Account Blocked:</strong></p>
                      <ul>
                        <li>Your account has been temporarily suspended</li>
                        <li>Contact support@emergency.com to appeal</li>
                        <li>Provide valid identification and explanation</li>
                        <li>Legal action may be taken for repeated violations</li>
                      </ul>
                    </>
                  ) : (
                    <>
                      <p>⚠️ <strong>Important:</strong> Submitting fake emergency reports is illegal and may result in:</p>
                      <ul>
                        <li>Account suspension or termination</li>
                        <li>Legal action and criminal charges</li>
                        <li>Fines and penalties up to Rs.10,000</li>
                        <li>Wasting critical emergency resources</li>
                        <li>Criminal record affecting future employment</li>
                      </ul>
                    </>
                  )}
                </div>
              </div>
            </div>
          )}

          {submitStatus.type === 'success' && (
            <div className="success-alert">
              <div className="alert-icon">✅</div>
              <div className="alert-content">
                <h3>Success</h3>
                <p>{submitStatus.message}</p>
                <p>Emergency responders have been notified and will respond shortly.</p>
              </div>
            </div>
          )}

          {submitStatus.type === 'error' && (
            <div className="error-alert">
              <div className="alert-icon">❌</div>
              <div className="alert-content">
                <h3>Submission Failed</h3>
                <p>{submitStatus.message}</p>
                {submitStatus.errors && (
                  <ul className="error-list">
                    {submitStatus.errors.map((err, idx) => (
                      <li key={idx}>{err.field}: {err.message}</li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      <div className="review-section">
        <div className="review-card">
          <h3>Incident Details</h3>
          <div className="review-item">
            <span className="review-label">Location:</span>
            <span className="review-value">{formData.location || "Not provided"}</span>
          </div>
          <div className="review-item">
            <span className="review-label">Time:</span>
            <span className="review-value">{formData.time || "Not provided"}</span>
          </div>
          <div className="review-item">
            <span className="review-label">Severity:</span>
            <span className={`review-value ${getSeverityColor(formData.severity)}`}>
              {formData.severity}
            </span>
          </div>
        </div>

        <div className="review-card">
          <h3>Evidence</h3>
          <div className="review-item">
            <span className="review-label">Photo:</span>
            <span className="review-value">
              {formData.photos.length > 0 ? `${formData.photos.length} photos` : "Not provided"}
            </span>
          </div>
          <div className="review-item">
            <span className="review-label">Description:</span>
            <span className="review-value">
              {formData.description || "No description provided"}
            </span>
          </div>
        </div>

        <div className="review-card">
          <h3>Injury Assessment</h3>
          <div className="review-item">
            <span className="review-label">Injuries:</span>
            <span className="review-value">{formData.injuries || "Not provided"}</span>
          </div>
          <div className="review-item">
            <span className="review-label">Witnesses:</span>
            <span className="review-value">
              {formData.witnesses.length > 0
                ? `${formData.witnesses.length} witness(es)`
                : "Not provided"}
            </span>
          </div>
        </div>
      </div>

      <div className="step-navigation">
        <button className="nav-btn back-btn" onClick={prevStep}>
          ← Back
        </button>
        <button
          className="nav-btn submit-btn"
          onClick={handleSubmit}
          disabled={loading}
        >
          {loading ? "Submitting..." : "Submit Report"}
        </button>
      </div>
    </div>
  );
}

export default Step4ReviewSubmit;