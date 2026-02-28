# AI-Enhanced Honeypot & Behavioral Threat Detection System

This project is a cybersecurity prototype built to detect suspicious login activity using both rule-based logic and machine learning. The idea was to create a fake admin login page that captures login attempts and analyzes behavioral patterns instead of actually authenticating users.
The system records the IP address, username, and timestamp of each attempt. If repeated login attempts are detected from the same IP, a threat score increases. In addition to this rule-based detection, an Isolation Forest model is used to identify unusual behavior patterns automatically. Suspicious activity is then reflected in a real-time dashboard.

## Tech Used
Python, Flask, SQLite, Scikit-learn, Pandas

## How to Run
pip install -r requirements.txt  
python app.py  
Open http://127.0.0.1:5000/ in your browser

This project helped me understand how deterministic logic and unsupervised learning can work together in practical cybersecurity systems.
