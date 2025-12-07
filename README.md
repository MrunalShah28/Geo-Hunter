Geo-Hunter: Threat Intelligence & Forensics Dashboard

Geo-Hunter is a web-based Digital Forensics tool designed to analyze server logs (access.log) and visualize cyberattacks in real-time. It transforms raw log data into actionable Threat Intelligence by mapping attacker locations and detecting malicious signatures.

Features

  - Automated Threat Detection: Identifies SQL Injection, XSS, Path Traversal, and Scanner bots.
  - Interactive World Map: Visualizes attack origins on a global map using IP geolocation.
  - Analyst Dashboard: Displays key metrics like total threats, top attacker IPs, and threat categorization.
  - Forensic Reporting: Parses standard Apache/Nginx logs into a structured format for analysis.

Tech Stack

  - Backend: Python 3, Flask
  - Data Processing: Pandas, Regex
  - Geolocation: MaxMind GeoIP2
  - Visualization: Folium (Leaflet.js)

Installation & Setup

1.  Clone the Repository
    git clone [https://github.com/MrunalShah28/Geo-Hunter.git](https://www.google.com/search?q=https://github.com/MrunalShah28/Geo-Hunter.git)
    cd geo-hunter

2.  Set up a Virtual Environment
    python3 -m venv venv
    source venv/bin/activate

3.  Install Required Libraries
    pip install flask pandas geoip2 folium

4.  Download the Database (CRITICAL STEP)
    The geolocation database is too large to be stored on GitHub, so you must download it manually for the app to work

  - Go to the MaxMind GeoLite2 Free Download page: [https://dev.maxmind.com/geoip/geolite2-free-geolocation-data](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
  - Sign up for a free account.
  - Download the "GeoLite2 City" database (GZIP format).
  - Extract the downloaded file.
  - Find the file named "GeoLite2-City.mmdb".
  - Place this file inside the root folder of this project (the same folder where app.py is located).

Usage

1.  Start the Server:
    python app.py

2.  Open the Dashboard:
    Open your browser and navigate to [http://127.0.0.1:5000](https://www.google.com/search?q=http://127.0.0.1:5000)

3.  Run an Analysis:
  - Click the upload button and select an access.log file.
  - Click INITIATE SCAN.
  - Review the generated map and threat report.

