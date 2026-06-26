import random
import smtplib
import os
from email.message import EmailMessage
from flask import Flask, render_template, request, jsonify, session # type: ignore
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Required for session management

# Configuration — use environment variables in production
SMTP_CONFIG = {
    "server": "smtp.gmail.com",
    "port": 587,
    "email": os.getenv("SENDER_EMAIL", "sssselvin0000987@gmail.com"),
    "password": os.getenv("SENDER_APP_PASSWORD", "bacl uytq kxtb lyss")
}

OTP_EXPIRY_MINUTES = 5
OTP_LENGTH = 6


def generate_otp(length: int = OTP_LENGTH) -> str:
    """Generate a cryptographically reasonable OTP."""
    return ''.join(str(random.SystemRandom().randint(0, 9)) for _ in range(length))


def send_otp_email(to_email: str, otp: str) -> tuple[bool, str]:
    """Send OTP via email. Returns (success, message)."""
    msg = EmailMessage()
    msg['Subject'] = "🔐 Your OTP Verification Code"
    msg['From'] = SMTP_CONFIG["email"]
    msg['To'] = to_email
    msg.set_content(f"""
Your One-Time Password (OTP) is: {otp}

This code expires in {OTP_EXPIRY_MINUTES} minutes.
If you didn't request this, please ignore this email.
    """)
    
    # HTML version
    msg.add_alternative(f"""
    <html>
      <body style="font-family: Arial, sans-serif; padding: 20px;">
        <h2 style="color: #333;">OTP Verification</h2>
        <p>Your One-Time Password is:</p>
        <div style="font-size: 32px; font-weight: bold; color: #4CAF50; 
                    letter-spacing: 8px; padding: 20px; background: #f5f5f5; 
                    border-radius: 8px; text-align: center; margin: 20px 0;">
          {otp}
        </div>
        <p style="color: #666;">This code expires in {OTP_EXPIRY_MINUTES} minutes.</p>
        <p style="color: #999; font-size: 12px;">If you didn't request this, please ignore this email.</p>
      </body>
    </html>
    """, subtype='html')
    
    try:
        with smtplib.SMTP(SMTP_CONFIG["server"], SMTP_CONFIG["port"]) as server:
            server.starttls()
            server.login(SMTP_CONFIG["email"], SMTP_CONFIG["password"])
            server.send_message(msg)
        return True, "OTP sent successfully!"
    except smtplib.SMTPAuthenticationError:
        return False, "Email authentication failed. Check credentials."
    except smtplib.SMTPException as e:
        return False, f"Failed to send email: {str(e)}"
    except Exception as e:
        return False, f"Unexpected error: {str(e)}"


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/send-otp', methods=['POST'])
def send_otp():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    
    # Basic email validation
    if not email or '@' not in email or '.' not in email.split('@')[-1]:
        return jsonify({"success": False, "message": "Invalid email address"}), 400
    
    otp = generate_otp()
    success, message = send_otp_email(email, otp)
    
    if success:
        # Store OTP in session with expiry time
        session['otp'] = otp
        session['otp_email'] = email
        session['otp_expiry'] = (datetime.now() + timedelta(minutes=OTP_EXPIRY_MINUTES)).isoformat()
        session['attempts'] = 0
        return jsonify({"success": True, "message": message})
    else:
        return jsonify({"success": False, "message": message}), 500


@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    user_otp = data.get('otp', '').strip()
    
    stored_otp = session.get('otp')
    expiry = session.get('otp_expiry')
    attempts = session.get('attempts', 0)
    
    # Check if OTP exists
    if not stored_otp:
        return jsonify({"success": False, "message": "No OTP requested. Please request a new one."}), 400
    
    # Check expiry
    if datetime.now() > datetime.fromisoformat(expiry):
        session.pop('otp', None)
        return jsonify({"success": False, "message": "OTP expired. Please request a new one."}), 400
    
    # Rate limiting — max 5 attempts
    if attempts >= 5:
        session.pop('otp', None)
        return jsonify({"success": False, "message": "Too many attempts. Please request a new OTP."}), 429
    
    session['attempts'] = attempts + 1
    
    if user_otp == stored_otp:
        # Clear OTP after successful verification
        session.pop('otp', None)
        session.pop('otp_expiry', None)
        session.pop('attempts', None)
        return jsonify({"success": True, "message": "OTP verified successfully! ✅"})
    else:
        remaining = 5 - session['attempts']
        return jsonify({
            "success": False, 
            "message": f"Invalid OTP. {remaining} attempts remaining."
        }), 401


@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    email = session.get('otp_email')
    if not email:
        return jsonify({"success": False, "message": "No email in session. Start over."}), 400
    
    otp = generate_otp()
    success, message = send_otp_email(email, otp)
    
    if success:
        session['otp'] = otp
        session['otp_expiry'] = (datetime.now() + timedelta(minutes=OTP_EXPIRY_MINUTES)).isoformat()
        session['attempts'] = 0
        return jsonify({"success": True, "message": "New OTP sent!"})
    else:
        return jsonify({"success": False, "message": message}), 500


if __name__ == '__main__':
    app.run(debug=True, port=5000)
