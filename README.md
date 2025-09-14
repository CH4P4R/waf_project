# 🛡️ SmartWAF - Web Application Firewall

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/Flask-2.3.3-green.svg)](https://flask.palletsprojects.com/)
[![Supabase](https://img.shields.io/badge/Database-Supabase-brightgreen.svg)](https://supabase.com/)
[![Security](https://img.shields.io/badge/Security-OWASP%20Top%2010-red.svg)](https://owasp.org/www-project-top-ten/)
[![Grafana](https://img.shields.io/badge/Dashboard-Grafana-orange.svg)](https://grafana.com/)
[![Real-time](https://img.shields.io/badge/Monitoring-Real--time-blue.svg)]()
[![GeoIP](https://img.shields.io/badge/Analysis-GeoIP-purple.svg)]()

**🎯 Advanced Web Application Firewall with OWASP Top 10 Detection**

SmartWAF is a modern web security system that detects, analyzes, and reports security attacks on web applications in **real-time**. Features **GeoIP analysis** and **Grafana dashboard** for comprehensive attack visualization and monitoring.

## 🚀 **Quick Start**

```bash
# Clone the repository
git clone https://github.com/[username]/smartwaf.git
cd smartwaf

# Windows automatic setup
.\start.ps1

# Manual installation
python -m venv smartwaf-env
smartwaf-env\Scripts\activate  # Windows
pip install -r requirements.txt
python app.py
```

**🌐 Access:** http://localhost:5000  
**📊 Dashboard:** http://localhost:3000

## 🎯 Project Overview

SmartWAF is designed as a comprehensive educational and research tool for web security professionals and students. It provides hands-on experience with modern cybersecurity threats and defensive mechanisms.

## 🔍 Features

### 🛡️ Attack Detection Capabilities
- **XSS (Cross-Site Scripting)** - Script injection attacks
- **SQL Injection** - Database attacks  
- **RCE (Remote Code Execution)** - Command execution attacks
- **LFI (Local File Inclusion)** - File inclusion attacks
- **CSRF (Cross-Site Request Forgery)** - Unauthorized request attacks
- **IDOR (Insecure Direct Object References)** - ID manipulation attacks
- **Directory Traversal** - Path traversal attacks
- **LDAP Injection** - LDAP query attacks
- **Sensitive Data Exposure** - Data leakage detection
- **Security Misconfiguration** - Configuration vulnerability detection

### 📊 Analysis & Reporting
- Real-time attack detection
- PostgreSQL database logging
- Grafana visual dashboard
- IP-based attacker analysis
- Endpoint security status reports
- Time-based attack trends
- **🌍 Geographic country detection and analysis**

### 🎨 Modern Interface
- Cybersecurity-themed dark UI
- Responsive design
- Real-time updates
- Filterable tables
- Interactive charts

## 🏗️ System Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│                 │    │                  │    │                 │
│   Web Client    ├───►│   SmartWAF       ├───►│   Supabase      │
│                 │    │   (Flask)        │    │ (PostgreSQL DB) │
│                 │    │  - Attack        │    │  - Attacks Log  │
│                 │    │    Detection     │    │  - Real-time    │
│                 │    │  - Logging       │    │  - Auto Scale   │
│                 │    │  - GeoIP Detect  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────┬───────┘
                                                           │
                                                           │ Direct
                                                           │ Connection
                                                ┌──────────▼───────┐
                                                │                  │
                                                │     Grafana      │
                                                │   Dashboard      │
                                                │  - Real-time     │
                                                │  - PostgreSQL    │
                                                │    Native        │
                                                │  - Country Anal. │
                                                └──────────────────┘
```

### 🔄 **Data Flow:**
1. **Client** → Sends HTTP request to SmartWAF
2. **SmartWAF** → Detects OWASP attacks
3. **SmartWAF** → **Performs country detection with GeoIP**
4. **SmartWAF** → Writes attack logs to Supabase
5. **Grafana** → Pulls data directly from Supabase (real-time)
6. **Dashboard** → Real-time security visualization + **Country analysis**

## 📋 Requirements

### System Requirements
- **Python** 3.8+ 
- **pip** package manager
- **2GB RAM** (minimum)
- **1GB Disk** space

### Service Requirements
- **Supabase** account (free tier sufficient)
- **Grafana** (separate installation required)
- **Port 5000** (Flask)
- **Port 3000** (Grafana)

## 🚀 Installation

### 1. Python Environment Setup
```bash
# Create Python virtual environment
python -m venv smartwaf-env

# Activate virtual environment
# Windows:
smartwaf-env\Scripts\activate
# Linux/Mac:
source smartwaf-env/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Supabase Setup

#### a) Create Supabase Account
1. Go to [supabase.com](https://supabase.com)
2. Create a new project
3. Copy URL and API Key from project settings

#### b) Create Database Table
Run this command in Supabase SQL Editor:

```sql
CREATE TABLE attacks (
  id SERIAL PRIMARY KEY,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  ip TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  attack_type TEXT NOT NULL,
  payload TEXT,
  user_agent TEXT
);

-- Indexes (for performance)
CREATE INDEX idx_attacks_timestamp ON attacks(timestamp);
CREATE INDEX idx_attacks_ip ON attacks(ip);
CREATE INDEX idx_attacks_type ON attacks(attack_type);
```

### 3. Environment Configuration

```bash
# On Windows:
copy env.example .env

# On Linux/Mac:
cp env.example .env

# Edit .env file
notepad .env  # Windows
nano .env     # Linux/Mac
```

**.env file example:**
```env
# Supabase Configuration
SUPABASE_URL=https://xxxxxxxxxxxxx.supabase.co
SUPABASE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xxxxx

# Flask Configuration  
FLASK_ENV=production
FLASK_DEBUG=False
```

### 4. Grafana Installation (Windows)

```bash
# Download and install Grafana
# Download Windows installer from https://grafana.com/grafana/download
# Or with Chocolatey:
choco install grafana

# Start Grafana service
net start grafana
```

### 5. Start SmartWAF Application

```bash
# Make sure virtual environment is active
smartwaf-env\Scripts\activate

# Start Flask application
python app.py
```

### 6. Grafana Dashboard Setup

#### a) Access Grafana
- URL: http://localhost:3000
- Username: `admin`
- Password: `admin` (first login)

#### b) Add Supabase Data Source
1. **Configuration > Data Sources** 
2. **Add data source > PostgreSQL**
3. Enter settings:
   ```
   Name: Supabase
   Host: db.xxxxxxxxxxxxx.supabase.co:5432
   Database: postgres
   User: postgres
   Password: [Supabase DB password]
   SSL Mode: require
   ```

#### c) Import Dashboard
1. **+ > Import**
2. Upload `smartwaf-dashboard.json` file
3. Select **Supabase** as data source
4. Click **Import**

## 📊 Usage

### Basic Usage
SmartWAF automatically analyzes all HTTP requests. For testing:

```bash
# Normal request
curl http://localhost:5000/

# XSS test
curl "http://localhost:5000/search?q=<script>alert('XSS')</script>"

# SQL Injection test  
curl "http://localhost:5000/login?user=admin&pass=admin' OR '1'='1"

# RCE test
curl "http://localhost:5000/search?cmd=ls; cat /etc/passwd"

# LFI test
curl "http://localhost:5000/file?path=../../../etc/passwd"
```

### Dashboard Usage
- **Real-time monitoring**: Updates every 30 seconds
- **Filtering**: You can filter in table columns
- **Time range**: Change time range from top right
- **Panel details**: Click panel titles to access details
- **🌍 Country analysis**: Geographic distribution in "IP Addresses by Country" panel

### Test Script Usage
```bash
# Test all attack types
python test_attacks.py

# For manual testing
curl "http://localhost:5000/search?q=<script>alert('XSS')</script>"
curl "http://localhost:5000/login?user=admin&pass=admin' OR '1'='1"
```

## 🧪 Test Scenarios

### Manual Test Payloads

#### XSS Tests
```javascript
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
javascript:alert('XSS')
<iframe src="javascript:alert('XSS')"></iframe>
```

#### SQL Injection Tests
```sql
' OR '1'='1
' UNION SELECT null,null,null--
'; DROP TABLE users--
' AND (SELECT SUBSTRING(@@version,1,1))='5'--
```

#### RCE Tests
```bash
; ls -la
&& cat /etc/passwd
| whoami
`id`
$(uname -a)
```

#### LFI Tests
```
../../../etc/passwd
..\\..\\..\\windows\\system32\\drivers\\etc\\hosts
....//....//....//etc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

## 📊 Dashboard Panels

### 📈 Main Metrics
- **Total Attacks**: Total number of attacks in the last 24 hours
- **Unique IPs**: Attacks from different IP addresses
- **Attack Types**: Number of different attack types detected
- **Hourly Average**: Average hourly attack rate

### 📊 Visualizations
- **Attack Type Distribution**: Proportional distribution with pie chart
- **Timeline**: Time-based distribution of attacks
- **Endpoint Analysis**: Most targeted endpoints
- **IP Analysis**: Most active attacker IPs
- **Detailed Logs**: Filterable attack details
- **🌍 Country Analysis**: Geographic attack distribution

## 📁 Project Structure

```
waf_project/
├── app.py                    # Main Flask application
├── requirements.txt          # Python dependencies
├── test_attacks.py          # Attack test script
├── start.ps1                # Windows startup script
├── smartwaf-dashboard.json  # Grafana dashboard configuration
├── .env                     # Environment variables
├── .gitignore              # Git ignore file
└── README.md               # Project documentation
```

## 🔧 Technical Details

### Technologies Used
- **Backend:** Flask (Python)
- **Database:** Supabase (PostgreSQL)
- **Dashboard:** Grafana
- **GeoIP:** ip-api.com service

### WAF Algorithm
1. Analyze incoming HTTP requests
2. Check OWASP Top 10 patterns
3. Log if attack is detected
4. Perform online country detection from IP address (ip-api.com)
5. Save to database

## 🔧 Troubleshooting

### Common Issues

#### 1. Supabase Connection Error
```
❌ Database logging error: connection error
```
**Solution**: Check Supabase information in `.env` file.

#### 2. Grafana Dashboard Not Loading
**Solution**: 
- Make sure Supabase data source is configured correctly
- Verify table name is `attacks`

#### 3. Port Conflict
```
Error: [Errno 10048] Only one usage of each socket address
```
**Solution**: Change port in `app.py` or close running application.

#### 4. SSL Certificate Error
**Solution**: Use `SSL Mode: require` in Supabase connection.

### Performance Optimization
- Check PostgreSQL indexes
- Clean old logs
- Optimize Grafana cache settings

## 📚 Learning Objectives

This project provides hands-on experience with:
- Web security and WAF systems
- OWASP Top 10 attack types
- Flask web framework development
- PostgreSQL database integration
- Grafana dashboard creation
- API security and attack detection

## 👨‍💻 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Environment
- **IDE:** VS Code, Cursor
- **Testing:** Chrome Browser
- **Database:** Supabase (PostgreSQL)
- **Dashboard:** Grafana

## 📚 References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [Supabase Docs](https://supabase.com/docs)
- [Grafana Documentation](https://grafana.com/docs/)
- [T-Pot Project](https://github.com/telekom-security/tpotce)

## 🤝 **Contributing**

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push your branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📊 **Screenshots**

### 🛡️ Main Dashboard
![SmartWAF Main Interface](https://via.placeholder.com/800x400/1a1a2e/00ff41?text=SmartWAF+Cyber+Security+Interface)

### 🌍 GeoIP Attack Analysis
![Geographic Attack Distribution](https://via.placeholder.com/800x400/16213e/00d4aa?text=Real-time+Geographic+Attack+Monitoring)

### 🎯 OWASP Top 10 Detection
![OWASP Attack Detection](https://via.placeholder.com/800x400/0a0a0a/ff6b6b?text=OWASP+Top+10+Attack+Detection)

## ⭐ **Star History**

[![Star History Chart](https://api.star-history.com/svg?repos=yourusername/smartwaf&type=Date)](https://star-history.com/#yourusername/smartwaf&Date)

## 📈 **Roadmap**

- [ ] 🤖 Machine Learning-based attack detection
- [ ] 📧 Email & Slack alert notifications
- [ ] 🚦 Advanced API rate limiting
- [ ] 📱 Mobile-responsive dashboard
- [ ] ☁️ Docker containerization
- [ ] 🔄 Kubernetes deployment
- [ ] 📊 Advanced analytics engine
- [ ] 🔐 Multi-tenant support

## 📄 **License**

This project is licensed under the [MIT License](LICENSE). See the LICENSE file for details.

## 🙏 **Acknowledgments**

- [OWASP](https://owasp.org/) - For security standards
- [Flask](https://flask.palletsprojects.com/) - For web framework
- [Supabase](https://supabase.com/) - For backend services
- [Grafana](https://grafana.com/) - For dashboard solution

---

**⚠️ Disclaimer:** This system is designed for educational and testing purposes. Additional security assessment should be performed before using in production environments.

**💡 Educational cybersecurity project - Open source WAF implementation**
