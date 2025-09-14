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

## 🏗️ Sistem Mimarisi

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│                 │    │                  │    │                 │
│   Web Client    ├───►│   SmartWAF       ├───►│   Supabase      │
│                 │    │   (Flask)        │    │ (PostgreSQL DB) │
│                 │    │  - Saldırı       │    │  - Attacks Log  │
│                 │    │    Tespiti       │    │  - Real-time    │
│                 │    │  - Logging       │    │  - Auto Scale   │
│                 │    │  - GeoIP Tespit  │    │                 │
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
                                                │  - Ülke Analizi  │
                                                └──────────────────┘
```

### 🔄 **Veri Akışı:**
1. **Client** → SmartWAF'a HTTP request gönderir
2. **SmartWAF** → OWASP saldırıları tespit eder
3. **SmartWAF** → **GeoIP ile ülke tespiti yapar**
4. **SmartWAF** → Supabase'e saldırı logları yazar
5. **Grafana** → Supabase'den direkt veri çeker (real-time)
6. **Dashboard** → Anlık güvenlik görselleştirmesi + **Ülke analizi**

## 📋 Gereksinimler

### Sistem Gereksinimleri
- **Python** 3.8+ 
- **pip** package manager
- **2GB RAM** (minimum)
- **1GB Disk** alanı

### Servis Gereksinimleri
- **Supabase** hesabı (ücretsiz tier yeterli)
- **Grafana** (ayrı kurulum gerekli)
- **Port 5000** (Flask)
- **Port 3000** (Grafana)

## 🚀 Kurulum

### 1. Python Environment Hazırlama
```bash
# Python virtual environment oluştur
python -m venv smartwaf-env

# Virtual environment'ı aktif et
# Windows:
smartwaf-env\Scripts\activate
# Linux/Mac:
source smartwaf-env/bin/activate

# Bağımlılıkları yükle
pip install -r requirements.txt
```

### 2. Supabase Kurulumu

#### a) Supabase Hesabı Oluştur
1. [supabase.com](https://supabase.com) adresine git
2. Yeni bir proje oluştur
3. Proje ayarlarından URL ve API Key'i kopyala

#### b) Veritabanı Tablosunu Oluştur
Supabase SQL Editor'da şu komutu çalıştır:

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

-- Index'ler (performans için)
CREATE INDEX idx_attacks_timestamp ON attacks(timestamp);
CREATE INDEX idx_attacks_ip ON attacks(ip);
CREATE INDEX idx_attacks_type ON attacks(attack_type);
```

### 3. Environment Konfigürasyonu

```bash
# Windows'da:
copy env.example .env

# Linux/Mac'te:
cp env.example .env

# .env dosyasını düzenle
notepad .env  # Windows
nano .env     # Linux/Mac
```

**.env dosyası örneği:**
```env
# Supabase Konfigürasyonu
SUPABASE_URL=https://xxxxxxxxxxxxx.supabase.co
SUPABASE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xxxxx

# Flask Konfigürasyonu  
FLASK_ENV=production
FLASK_DEBUG=False
```

### 4. Grafana Kurulumu (Windows)

```bash
# Grafana'yı indir ve kur
# https://grafana.com/grafana/download adresinden Windows installer'ı indir
# Veya Chocolatey ile:
choco install grafana

# Grafana servisini başlat
net start grafana
```

### 5. SmartWAF Uygulamasını Başlat

```bash
# Virtual environment aktif olduğundan emin ol
smartwaf-env\Scripts\activate

# Flask uygulamasını başlat
python app.py
```

### 6. Grafana Dashboard Kurulumu

#### a) Grafana'ya Erişim
- URL: http://localhost:3000
- Kullanıcı: `admin`
- Şifre: `admin` (ilk giriş)

#### b) Supabase Data Source Ekle
1. **Configuration > Data Sources** 
2. **Add data source > PostgreSQL**
3. Ayarları gir:
   ```
   Name: Supabase
   Host: db.xxxxxxxxxxxxx.supabase.co:5432
   Database: postgres
   User: postgres
   Password: [Supabase DB şifresi]
   SSL Mode: require
   ```

#### c) Dashboard Import Et
1. **+ > Import**
2. `smartwaf-dashboard.json` dosyasını yükle
3. Data source olarak **Supabase**'i seç
4. **Import** tıkla

## 📊 Kullanım

### Temel Kullanım
SmartWAF otomatik olarak tüm HTTP isteklerini analiz eder. Test için:

```bash
# Normal istek
curl http://localhost:5000/

# XSS testi
curl "http://localhost:5000/search?q=<script>alert('XSS')</script>"

# SQL Injection testi  
curl "http://localhost:5000/login?user=admin&pass=admin' OR '1'='1"

# RCE testi
curl "http://localhost:5000/search?cmd=ls; cat /etc/passwd"

# LFI testi
curl "http://localhost:5000/file?path=../../../etc/passwd"
```

### Dashboard Kullanımı
- **Real-time monitoring**: 30 saniyede bir güncellenir
- **Filtreleme**: Tablo sütunlarında filtreleme yapabilirsiniz
- **Zaman aralığı**: Sağ üstten zaman aralığını değiştirebilirsiniz
- **Panel detayları**: Panel başlıklarına tıklayarak detaylara erişin
- **🌍 Ülke analizi**: "IP Addresses by Country" panelinde coğrafi dağılım

### Test Scripti Kullanımı
```bash
# Tüm saldırı türlerini test et
python test_attacks.py

# Manuel test için
curl "http://localhost:5000/search?q=<script>alert('XSS')</script>"
curl "http://localhost:5000/login?user=admin&pass=admin' OR '1'='1"
```

## 🧪 Test Senaryoları

### Manuel Test Payload'ları

#### XSS Testleri
```javascript
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
javascript:alert('XSS')
<iframe src="javascript:alert('XSS')"></iframe>
```

#### SQL Injection Testleri
```sql
' OR '1'='1
' UNION SELECT null,null,null--
'; DROP TABLE users--
' AND (SELECT SUBSTRING(@@version,1,1))='5'--
```

#### RCE Testleri
```bash
; ls -la
&& cat /etc/passwd
| whoami
`id`
$(uname -a)
```

#### LFI Testleri
```
../../../etc/passwd
..\\..\\..\\windows\\system32\\drivers\\etc\\hosts
....//....//....//etc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

## 📊 Dashboard Panelleri

### 📈 Ana Metrikler
- **Toplam Saldırı**: Son 24 saatteki toplam saldırı sayısı
- **Benzersiz IP**: Farklı IP adreslerinden gelen saldırılar
- **Saldırı Türü**: Tespit edilen farklı saldırı türü sayısı
- **Saatlik Ortalama**: Ortalama saatlik saldırı oranı

### 📊 Görselleştirmeler
- **Saldırı Türü Dağılımı**: Pie chart ile oransal dağılım
- **Zaman Çizelgesi**: Saldırıların zamana göre dağılımı
- **Endpoint Analizi**: En çok hedeflenen endpoint'ler
- **IP Analizi**: En aktif saldırgan IP'ler
- **Detaylı Loglar**: Filtrelenebilir saldırı detayları
- **🌍 Ülke Analizi**: Coğrafi saldırı dağılımı

## 📁 Proje Yapısı

```
waf_project/
├── app.py                    # Ana Flask uygulaması
├── requirements.txt          # Python bağımlılıkları
├── test_attacks.py          # Saldırı test scripti
├── start.ps1                # Windows başlatma scripti
├── smartwaf-dashboard.json  # Grafana dashboard konfigürasyonu
├── .env                     # Environment değişkenleri
├── .gitignore              # Git ignore dosyası
└── README.md               # Proje dokümantasyonu
```

## 🔧 Teknik Detaylar

### Kullanılan Teknolojiler
- **Backend:** Flask (Python)
- **Veritabanı:** Supabase (PostgreSQL)
- **Dashboard:** Grafana
- **GeoIP:** ip-api.com servisi

### WAF Algoritması
1. Gelen HTTP isteklerini analiz et
2. OWASP Top 10 pattern'larını kontrol et
3. Saldırı tespit edilirse logla
4. IP adresinden online ülke tespiti yap (ip-api.com)
5. Veritabanına kaydet

## 🔧 Sorun Giderme

### Sık Karşılaşılan Sorunlar

#### 1. Supabase Bağlantı Hatası
```
❌ Veritabanı kayıt hatası: connection error
```
**Çözüm**: `.env` dosyasındaki Supabase bilgilerini kontrol edin.

#### 2. Grafana Dashboard Yüklenmiyor
**Çözüm**: 
- Supabase data source'u doğru yapılandırıldığından emin olun
- Tablo adının `attacks` olduğunu kontrol edin

#### 3. Port Konflikti
```
Error: [Errno 10048] Only one usage of each socket address
```
**Çözüm**: `app.py`'de port'u değiştirin veya çalışan uygulamayı kapatın.

#### 4. SSL Certificate Hatası
**Çözüm**: Supabase bağlantısında `SSL Mode: require` kullanın.

### Performans Optimizasyonu
- PostgreSQL indekslerini kontrol edin
- Eski logları temizleyin
- Grafana cache ayarlarını optimize edin

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

## 📚 Referanslar

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [Supabase Docs](https://supabase.com/docs)
- [Grafana Documentation](https://grafana.com/docs/)
- [T-Pot Project](https://github.com/telekom-security/tpotce)

## 🤝 **Katkıda Bulunma**

1. Repository'yi fork edin
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add amazing feature'`)
4. Branch'inizi push edin (`git push origin feature/amazing-feature`)
5. Pull Request açın

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

## 📄 **Lisans**

Bu proje [MIT License](LICENSE) altında lisanslanmıştır. Detaylar için LICENSE dosyasına bakın.

## 🙏 **Teşekkürler**

- [OWASP](https://owasp.org/) - Güvenlik standartları için
- [Flask](https://flask.palletsprojects.com/) - Web framework için
- [Supabase](https://supabase.com/) - Backend servisleri için
- [Grafana](https://grafana.com/) - Dashboard çözümü için

---

**⚠️ Disclaimer:** This system is designed for educational and testing purposes. Additional security assessment should be performed before using in production environments.

**💡 Educational cybersecurity project - Open source WAF implementation**
