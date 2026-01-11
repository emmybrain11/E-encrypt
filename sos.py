import smtplib
from email.mime.text import MIMEText
from datetime import datetime


class SOSManager:
    def __init__(self):
        self.emergency_types = {
            'medical': 'Medical Emergency',
            'police': 'Police Required',
            'fire': 'Fire Emergency',
            'personal': 'Personal Safety',
            'general': 'General Emergency'
        }

    def send_alert(self, contacts, emergency_type, location=None, message=""):
        """Send SOS alert to contacts"""
        alerts_sent = []

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        alert_message = f"""
        🚨 EMERGENCY ALERT 🚨

        Emergency Type: {self.emergency_types.get(emergency_type, emergency_type)}
        Time: {timestamp}

        {message}

        Location: {location if location else "Unknown"}

        This is an automated alert from E-Encrypt Pro.
        Please respond immediately.
        """

        for contact in contacts:
            if self.send_single_alert(contact, alert_message):
                alerts_sent.append(contact.get('name', 'Unknown'))

        return alerts_sent

    def send_single_alert(self, contact, message):
        """Send alert to single contact"""
        try:
            # This is a demo - in real app, send via SMS, email, etc.
            print(f"Alert sent to {contact.get('name')}: {message[:100]}...")
            return True
        except:
            return False

    def get_nearby_services(self, location, service_type='hospital'):
        """Get nearby emergency services"""
        # This would use Google Places API or similar
        # For demo, return dummy data
        return [
            {"name": "City Hospital", "distance": "1.2 km", "phone": "911"},
            {"name": "Police Station", "distance": "2.5 km", "phone": "911"},
            {"name": "Fire Department", "distance": "3.1 km", "phone": "911"}
        ]