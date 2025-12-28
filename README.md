# 🔍 AmateurOSINT - Profesyonel OSINT Araştırma Platformu

> **Açık Kaynak İstihbaratı (OSINT) için Eksiksiz, Etik ve Yasal Araştırma Platformu**

![Version](https://img.shields.io/badge/Version-1.0-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-1.28+-red)

---

## 📋 İçerik

- [Açıklama](#açıklama)
- [Özellikler](#özellikler)
- [Kurulum](#kurulum)
- [Kullanım](#kullanım)
- [Modüller](#modüller)
- [API Kaynakları](#api-kaynakları)
- [Yasal Uyarı](#yasal-uyarı)
- [Geliştirici Bilgisi](#geliştirici-bilgisi)
- [Lisans](#lisans)

---

## 🎯 Açıklama

**AmateurOSINT**, pentest profesyonelleri, güvenlik araştırmacıları ve etik hackerler için tasarlanmış **kapsamlı, profesyonel ve modüler** bir OSINT platformudur. 

Sosyal medya araştırması, domain analizi, sızıntı kontrolü, meta veri çıkarma, altyapı keşfi ve daha fazlasını **tek platform üzerinden** yapabilirsiniz.

---

## ⚡ Özellikler

### 1. **👤 Kimlik ve Sosyal Medya Haritası**
- 11+ sosyal medya platformunda username araması
  - GitHub, Twitter/X, Instagram, Reddit, Medium, Steam, TikTok, YouTube, LinkedIn, Pinterest, Twitch
- Web ayak izi analizi (DuckDuckGo entegrasyonu)
- Dijital kimlik mapping

### 2. **📧 E-posta Toplama ve Validasyon**
- Domain'den otomatik e-posta keşfi
- WHOIS kayıtlarından iletişim e-postaları
- İletişim listesi oluşturma
- Site:domain aramasıyla e-posta bulma

### 3. **🌐 Domain İstihbaratı (Eksiksiz)**
- **WHOIS Analizi**: Kaydedici, yönetici, tarihler
- **DNS Kayıtları**: A, MX, TXT, NS, CNAME, SOA
- **Alt-domain Keşfi**: Subdomain enumeration
- **ASN Bilgisi**: IP range ve otonom sistem numarası

### 4. **⚠️ Sızıntı Kontrolü ve Dark Web**
- Pastebin taraması
- GitHub sensitive data araması
- Paste site taraması
- Veri ihlali kontrolü
- Potansiyel compromise tespiti

### 5. **🛡️ Altyapı Keşfi**
- Reverse DNS lookup
- Geo-IP lokasyon analizi (interaktif harita)
- IP adres sahipliği tespiti
- ISP ve kuruluş bilgisi

### 6. **📜 SSL Sertifikası Analizi**
- crt.sh entegrasyonu
- Sertifika tarihçesi
- Wildcard ve subdomain sertifikaları
- MITRE ATT&CK compliance

### 7. **🖼️ Meta Veri Analizi (Exiftool Benzeri)**
- **Resim Analizi**:
  - EXIF veri çıkarma (Kamera, tarih, GPS)
  - Format, çözünürlük, DPI
  - Transparency, color space
  
- **PDF Analizi**:
  - Metadata (Author, Title, Subject, Keywords)
  - Sayfa sayısı, oluşturulma tarihi
  - Şifreleme durumu
  - PDF özelikleri

### 8. **📍 Coğrafi İstihbarat**
- IP geolokasyonu
- Domain lokasyonu
- Interaktif harita görselleştirmesi
- Ülke, şehir, koordinat bilgisi
- ISP ve kuruluş adı

### 9. **🔐 Şifre Güvenlik Analizi**
- Şifre gücü değerlendirmesi
- Karmaşıklık analizi
- Güvenlik önerileri
- Entropy hesaplama

### 10. **📄 Profesyonel Raporlama**
- PDF rapor oluşturma
- Tüm verileri birleştirme
- Profesyonel formatı
- İndirilebilir doküman
- Otomatik raporlama

---

## 🚀 Kurulum

### Gereksinimler

- **Python**: 3.8 veya üstü
- **pip**: Python paket yöneticisi
- **Virtualenv** (önerilir)

### Adım 1: Repository'yi Clone Et

```bash
git clone https://github.com/macallantheroot/AmateurOSINT.git
cd AmateurOSINT/ReconMail
```

### Adım 2: Virtual Environment Oluştur

```bash
# Linux/Mac
python3 -m venv .venv
source .venv/bin/activate

# Windows
python -m venv .venv
.venv\Scripts\activate
```

### Adım 3: Bağımlılıkları Yükle

```bash
pip install -r requirements.txt
```

### Adım 4: Uygulamayı Çalıştır

```bash
streamlit run main.py
```

Tarayıcıda otomatik olarak açılacak: **http://localhost:8501**

---

## 📖 Kullanım

### Kullanıcı Arayüzü

```
🔍 AmateurOSINT Professional Hub
├── 🔍 Identity & Social Mapping     [Sosyal medya taraması]
├── 📧 Email Harvesting              [E-posta toplama]
├── 🌐 Domain Intelligence           [Domain analizi]
├── ⚠️ Breach Detection              [Sızıntı kontrolü]
├── 🛡️ Infrastructure Reconnaissance [Altyapı keşfi]
├── 📜 SSL Certificates              [Sertifika analizi]
├── 🖼️ Metadata Analysis             [Meta veri çıkarma]
├── 📍 Geo-Intelligence              [Lokasyon analizi]
├── 🔐 Password Analysis             [Şifre analizi]
└── 📄 Generate Report               [Rapor oluşturma]
```

### Örnek Kullanım Senaryoları

#### **Senaryo 1: Kendi Dijital Ayak İzini Kontrol Et**
```
1. Identity & Social Mapping → Kendi @username ara
2. Email Harvesting → Açık e-postalarını bul
3. Breach Detection → Herhangi bir sızıntı var mı kontrol et
4. Generate Report → Özet PDF raporunu indir
```

#### **Senaryo 2: Kompetitor Analizi**
```
1. Domain Intelligence → Domain WHOIS bilgisi
2. Email Harvesting → İş e-postaları listesi
3. SSL Certificates → Altyapı haritası
4. Subdomain Enumeration → Alt-domainleri keşfet
5. Generate Report → Profesyonel rapor oluştur
```

#### **Senaryo 3: Kişi Analizi**
```
1. Identity & Social Mapping → Sosyal medya ara
2. Metadata Analysis → Profil resimlerini analiz et
3. Breach Detection → Sızıntı kontrolü yap
4. Geo-Intelligence → İpten konum bul
5. Generate Report → Eksiksiz profil raporu
```

---

## 🧩 Modüller Detaylı

### Identity & Social Mapping
```python
# Kullanım
osint.username_hunter("macallantheroot")

# Çıktı
Platform: GitHub → FOUND
Platform: Twitter → FOUND
Platform: Instagram → FOUND
...
```

### Email Harvesting
```python
osint.email_harvesting("example.com")
# admin@example.com, contact@example.com, ...
```

### Domain Intelligence
```python
osint.whois_lookup("example.com")
osint.dns_records("example.com")
osint.subdomain_enum("example.com")
osint.asn_lookup("example.com")
```

### Breach Detection
```python
osint.breach_check("user@example.com")
# Pastebin, GitHub, Dark Web kaynakları
```

### Infrastructure Reconnaissance
```python
osint.reverse_dns("8.8.8.8")
osint.geo_ip("example.com")
osint.web_archive("example.com")
```

### SSL Certificates
```python
osint.ssl_search("example.com")
# crt.sh'den tüm sertifikaları al
```

### Metadata Analysis
```python
meta = osint.extract_metadata(file)
# EXIF, PDF metadata, resim özellikleri
```

### Geo-Intelligence
```python
osint.geo_ip("1.1.1.1")
# Harita üzerinde göster
```

### Password Analysis
```python
osint.check_password("MyP@ssw0rd!")
# Güç: Çok Güçlü / Orta / Zayıf
```

---

## 🔌 API Kaynakları

### Ücretsiz API'ler (Kullanılan)
| API | Amaç | Limit |
|-----|------|-------|
| **DuckDuckGo** | Web araması | Sınırlandırılmış |
| **ip-api.com** | Geo-IP | 45/dakika |
| **crt.sh** | SSL sertifikaları | Sınırlandırılmış |
| **archive.org** | Web archive | - |
| **DNS Resolver** | DNS kayıtları | Sistem limiti |
| **WHOIS** | Domain bilgisi | - |

### Opsiyonel Premium API'ler
```bash
# Shodan (IP/Port taraması)
pip install shodan

# Censys (Sertifika ve host bilgisi)
pip install censys

# VirusTotal (Kötü amaçlı yazılım taraması)
pip install virustotal-python

# Hunter.io (E-posta bulma)
pip install hunter

# SecurityTrails (DNS ve IP history)
pip install securitytrails
```

---

## 📊 Performans ve Sınırlamalar

| Modül | Hız | Doğruluk | Limit |
|-------|-----|----------|-------|
| Social Media | Hızlı | Yüksek | 11 platform |
| Email Harvest | Orta | Orta-Yüksek | Site limiti |
| WHOIS Lookup | Çok Hızlı | Yüksek | - |
| DNS Records | Çok Hızlı | Yüksek | - |
| Subdomain Enum | Hızlı | Orta | Common subs |
| Geo-IP | Çok Hızlı | Yüksek | 45/dakika |
| SSL Search | Orta | Yüksek | 100-1000 |
| Breach Check | Orta | Orta | Site limiti |

---

## 🛠️ Geliştirme ve Katkı

### Proje Yapısı
```
ReconMail/
├── main.py                 # Ana uygulama
├── requirements.txt        # Bağımlılıklar
├── README.md              # Dokümantasyon
├── .venv/                 # Virtual environment
└── lib/                   # Opsiyonel kütüphaneler
```

### Kod Kalitesi
- ✅ Type hints desteği hazırlı
- ✅ Hata handling detaylı
- ✅ Async desteği planlı
- ✅ Unit tests planlı

### Planlanan Özellikler
- [ ] Async işlemler (hız artışı)
- [ ] Multi-threading tarama
- [ ] Database depolama (SQLite/PostgreSQL)
- [ ] API webhook support
- [ ] Proxy ve VPN desteği
- [ ] Tor entegrasyonu
- [ ] Machine learning anomali tespiti
- [ ] Graphical network mapping
- [ ] Bulk CSV import/export
- [ ] Scheduled tasks

---

## ⚖️ Yasal Uyarı ve Etik İlkeler

### ✅ KULLANILABİLİR

- ✅ Kendi dijital ayak izini araştır
- ✅ Kurallı kompetitor araştırması
- ✅ Yasal izin ile OSINT
- ✅ Gizlilik yasalarına uygun araştırma
- ✅ Eğitim ve araştırma amaçları
- ✅ Red team authorized pentest

### ❌ KULLANILMAZ

- ❌ Yetkisiz erişim
- ❌ Kişisel veri kötüye kullanımı
- ❌ Dolandırıcılık ve saldırı
- ❌ İllegal etkinlikler
- ❌ Stalking ve taciz
- ❌ Ticari haksız rekabet
- ❌ DDoS ve sistem saldırıları

**⚠️ KULLANIALAN SORUMLUDUR!**

Yasal sonuçlardan AmateurOSINT geliştiricileri sorumlu değildir.

---

## 📚 Referanslar ve Kaynaklar

### OSINT Bilgi Kaynağı
- 🌟 **[Awesome OSINT](https://github.com/jivoi/awesome-osint)** - Kapsamlı OSINT kaynakları listesi
  - **Bu projede yardım alınan ana kaynak**
  - Tools, resources, ve best practices

### OSINT Toplulukları
- OSINT Framework Community
- BELLINGCAT Investigative Journalists
- Privacy International
- Electronic Frontier Foundation (EFF)

### Teknik Kaynaklar
- RFC 1035 (DNS Specification)
- RFC 3986 (URI Specification)
- MITRE ATT&CK Framework
- NIST Cybersecurity Framework

### İlgili Araçlar
- Shodan, Censys, VirusTotal
- DNSdumpster, crt.sh
- Wayback Machine
- Hunter.io, Clearbit

---

## 🐛 Hata Raporlama

### Hata Bulduğunuz Zaman
1. **Hata detaylarını yazın** (screenshot, log)
2. **Adımları tekrarla** (repro steps)
3. **İşletim sistemi** (Linux/Windows/Mac)
4. **Python versiyonu** (`python --version`)
5. **Pull request** veya **Issue** açın

### Pull Request Süreci
```bash
1. Fork the repository
2. Create feature branch (git checkout -b feature/AmazingFeature)
3. Commit changes (git commit -m 'Add AmazingFeature')
4. Push to branch (git push origin feature/AmazingFeature)
5. Open Pull Request
```

---

## 👨‍💻 Geliştirici Bilgisi

**Yazar & Geliştirici**: **Macallantheroot**

- 🌐 GitHub: [@macallantheroot](https://github.com/macallantheroot)
- 🔐 Güvenlik Araştırmacısı
- 🎯 OSINT ve Pentest Uzmanı

### İletişim
- 📧 E-posta: macallantheroot@[domain]
- 🐦 Twitter: [@macallantheroot](https://twitter.com)
- 💼 LinkedIn: [Macallan](https://linkedin.com)

---

## 📄 Lisans

Bu proje **MIT Lisansı** altında yayınlanmıştır.

```
MIT License

Copyright (c) 2025 Macallantheroot

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

## 🙏 Teşekkürler

- OSINT topluluğuna
- Open source geliştiricilere
- Etik araştırmacılara
- Tüm katkıda bulunanlara

---

## 📞 Topluluk

- **GitHub Issues**: Hata ve feature requests
- **GitHub Discussions**: Fikirler ve sorular
- **Twitter**: [@macallantheroot](https://twitter.com)

---

<div align="center">

### 🔐 Etik OSINT Araştırması İçin Tasarlanmış

**AmateurOSINT v1.0**

*Güvenlik araştırmacılarının güvenliği için yapılmıştır*

⭐ Beğendiysen, README üzerinde star'ı tıkla!

</div>

---

**Son Güncelleme**: 28 Aralık 2025
