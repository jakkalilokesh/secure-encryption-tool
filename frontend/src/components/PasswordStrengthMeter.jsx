import React, { useState, useEffect } from "react";

export default function PasswordStrengthMeter({ password }) {
  const [score, setScore] = useState(0);
  const [feedback, setFeedback] = useState([]);

  useEffect(() => {
    calculateScore();
  }, [password]);

  const calculateScore = () => {
    let newScore = 0;
    const newFeedback = [];

    // Length check
    if (password.length >= 12) {
      newScore += 20;
    } else if (password.length >= 8) {
      newScore += 10;
      newFeedback.push("Consider using at least 12 characters for better security");
    } else {
      newFeedback.push("Password too short (minimum 8 characters)");
    }

    // Character variety
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasDigit = /[0-9]/.test(password);
    const hasSpecial = /[^A-Za-z0-9]/.test(password);

    if (hasUpper) newScore += 20;
    else newFeedback.push("Add uppercase letters");

    if (hasLower) newScore += 20;
    else newFeedback.push("Add lowercase letters");

    if (hasDigit) newScore += 20;
    else newFeedback.push("Add numbers");

    if (hasSpecial) newScore += 20;
    else newFeedback.push("Add special characters (!@#$% etc.)");

    if (/(.)\1{2,}/.test(password)) {
      newScore -= 10;
      newFeedback.push("Avoid repeated characters");
    }

    // Common password patterns
    const commonPatterns = [
      'password', '123456', 'qwerty', 'admin', 'welcome',
      'letmein', 'monkey', 'dragon', 'sunshine', 'master'
    ];

    if (commonPatterns.some(pattern => password.toLowerCase().includes(pattern))) {
      newScore -= 15;
      newFeedback.push("Avoid common password patterns");
    }

    setScore(Math.max(0, Math.min(100, newScore)));
    setFeedback(newFeedback.slice(0, 3)); // Show max 3 feedback items
  };

  const getStrengthColor = () => {
    if (score >= 80) return "#0aff0a"; // Green
    if (score >= 60) return "#00ffaa"; // Light Green
    if (score >= 40) return "#ffff00"; // Yellow
    if (score >= 20) return "#ff9900"; // Orange
    return "#ff3300"; // Red
  };

  const getStrengthText = () => {
    if (score >= 80) return "Very Strong";
    if (score >= 60) return "Strong";
    if (score >= 40) return "Good";
    if (score >= 20) return "Weak";
    return "Very Weak";
  };

  return (
    <div className="mt-2">
      <div className="flex justify-between text-sm mb-1">
        <span className="text-gray-400">Password Strength</span>
        <span style={{ color: getStrengthColor() }}>
          {getStrengthText()} ({score}%)
        </span>
      </div>

      <div className="h-2 bg-gray-800 w-full rounded-full overflow-hidden">
        <div
          className="h-2 transition-all duration-500"
          style={{
            width: `${score}%`,
            backgroundColor: getStrengthColor()
          }}
        ></div>
      </div>

      {feedback.length > 0 && (
        <div className="mt-2">
          {feedback.map((msg, idx) => (
            <div key={idx} className="text-yellow-400 text-xs flex items-center">
              <span className="mr-1">•</span>
              {msg}
            </div>
          ))}
        </div>
      )}

      {score >= 80 && password.length > 0 && (
        <div className="text-green-400 text-xs mt-2">
          ✓ Strong password! Good for encryption.
        </div>
      )}
    </div>
  );
}