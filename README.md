<div align="center">
  <a href="#english">English</a> | <a href="#turkce">Turkce</a>
</div>

<a id="english"></a>
# AmateurOSINT
Practical OSINT workspace built with Streamlit for analysts, red teamers, and security researchers.

![Version](https://img.shields.io/badge/version-v3-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Streamlit](https://img.shields.io/badge/streamlit-1.28%2B-red)

## Overview
AmateurOSINT combines common reconnaissance workflows in one local dashboard.
You can run identity checks, domain intelligence, breach lookups, metadata analysis, and relationship graphing without jumping across many tools.

## Features
- Identity and social profile hunting
- Email harvesting and WHOIS enrichment
- Domain intelligence (WHOIS, DNS, subdomain, ASN)
- Breach detection with optional HIBP API support
- Infrastructure recon (reverse DNS, geo-IP, archive lookup)
- SSL certificate intelligence
- File metadata extraction (image/PDF)
- Password strength checks
- Bulk asynchronous scanning
- Historical storage with SQLite + SQLAlchemy
- Relationship graph visualization with NetworkX + Pyvis
- PDF report generation
- Bilingual UI support (Turkish and English)

## Installation
1. Clone the repository.
2. Create and activate a virtual environment.
3. Install dependencies.
4. Start the app.

```bash
git clone https://github.com/macallantheroot/AmateurOSINT.git
cd AmateurOSINT

python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
# source .venv/bin/activate

pip install -r requirements.txt
streamlit run main.py
```

## Configuration
The app can read API keys from a local .env file.
You can also set keys from the Settings tab inside the app.

Supported keys:
- SHODAN_API_KEY
- CENSYS_API_ID
- CENSYS_API_SECRET
- VIRUSTOTAL_API_KEY
- HIBP_API_KEY

## Data and Persistence
- Scan data is stored in a local SQLite database.
- Relationship entities and edges are persisted for graph/history views.
- Report snapshots are stored for later review.

## Legal and Ethical Notice
Use this project only on assets you own or have explicit permission to test.
The developer and contributors are not responsible for misuse.

## Contributing
Issues and pull requests are welcome.

Developer: https://github.com/MacallanTheRoot  
License: MIT

---

<a id="turkce"></a>
# AmateurOSINT
Analistler, red team uzmanlari ve guvenlik arastirmacilari icin Streamlit tabanli pratik OSINT calisma alani.

![Surum](https://img.shields.io/badge/surum-v3-blue)
![Lisans](https://img.shields.io/badge/lisans-MIT-green)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Streamlit](https://img.shields.io/badge/streamlit-1.28%2B-red)

## Genel Bakis
AmateurOSINT, yaygin kesif ve istihbarat adimlarini tek bir yerel panoda toplar.
Kimlik arama, domain analizi, sizinti kontrolu, metadata analizi ve iliski grafigi gibi adimlari tek uygulamadan yonetebilirsiniz.

## Ozellikler
- Kimlik ve sosyal profil taramasi
- E-posta toplama ve WHOIS zenginlestirme
- Domain istihbarati (WHOIS, DNS, subdomain, ASN)
- Opsiyonel HIBP API destekli sizinti kontrolu
- Altyapi kesfi (reverse DNS, geo-IP, arsiv kontrolu)
- SSL sertifika istihbarati
- Dosya metadata cikarma (resim/PDF)
- Sifre gucu analizi
- Asenkron toplu tarama
- SQLite + SQLAlchemy ile gecmis saklama
- NetworkX + Pyvis ile iliski grafigi
- PDF rapor olusturma
- Turkce ve Ingilizce arayuz destegi

## Kurulum
1. Depoyu klonlayin.
2. Sanal ortam olusturup aktif edin.
3. Bagimliliklari yukleyin.
4. Uygulamayi baslatin.

```bash
git clone https://github.com/macallantheroot/AmateurOSINT.git
cd AmateurOSINT

python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
# source .venv/bin/activate

pip install -r requirements.txt
streamlit run main.py
```

## Yapilandirma
Uygulama, API anahtarlarini yerel .env dosyasindan okuyabilir.
Ayrica ayarlar sekmesinden anahtarlari uygulama icinde kaydedebilirsiniz.

Desteklenen anahtarlar:
- SHODAN_API_KEY
- CENSYS_API_ID
- CENSYS_API_SECRET
- VIRUSTOTAL_API_KEY
- HIBP_API_KEY

## Veri ve Kalicilik
- Tarama verileri yerel SQLite veritabaninda tutulur.
- Iliski grafigi ve gecmis ekranlari icin varliklar/iliski kenarlari saklanir.
- Uretilen raporlar snapshot olarak kaydedilir.

## Yasal ve Etik Uyari
Bu projeyi yalnizca sahip oldugunuz veya acik izin aldiginiz hedeflerde kullanin.
Gelistirici ve katki saglayanlar kotuye kullanimdan sorumlu degildir.

## Katki
Issue ve pull request katkilarina aciktir.

Gelistirici: https://github.com/MacallanTheRoot  
Lisans: MIT
