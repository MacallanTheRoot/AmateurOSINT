import streamlit as st
import pandas as pd
import requests
import re
import dns.resolver
import whois
import socket
import random
import string
import time
import io
from PIL import Image
from PIL.ExifTags import TAGS
from PyPDF2 import PdfReader
from fpdf import FPDF
from duckduckgo_search import DDGS
from pyvis.network import Network
from urllib.parse import urlparse
import json

# --- 1. SESSION STATE & STATS ---
if 'stats' not in st.session_state:
    st.session_state.stats = {
        "emails": 0, "breaches": 0, "subdomains": 0, 
        "usernames": 0, "domains": 0, "ips": 0, "certificates": 0
    }
if 'report_results' not in st.session_state:
    st.session_state.report_results = {}

# --- 2. PROFESYONEL RAPORLAMA (PDF) ---
class AmateurOSINTReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'AmateurOSINT Professional Intelligence Report', 0, 1, 'C')
        self.ln(10)
    
    def chapter_title(self, title):
        self.set_font('Arial', 'B', 12)
        self.set_fill_color(230, 230, 230)
        # Türkçe karakterleri ASCII'ye dönüştür
        safe_title = title.encode('ascii', 'ignore').decode('ascii')
        self.cell(0, 10, f"Section: {safe_title}", 0, 1, 'L', True)
        self.ln(5)

    def chapter_body(self, body):
        self.set_font('Arial', '', 10)
        # Türkçe karakterleri ASCII'ye dönüştür
        safe_body = str(body).encode('ascii', 'ignore').decode('ascii')
        self.multi_cell(0, 6, safe_body)
        self.ln()

# --- 3. AMATEUROSINT CORE FRAMEWORK ---
class AmateurOSINT:
    def __init__(self):
        self.headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
        self.email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        self.domain_regex = r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}'

    # ===== MODÜLRELİ OSINT TÜRLERİ =====

    # 1. USERNAME HUNTER (@username)
    def username_hunter(self, username):
        username = username.replace('@', '').strip()
        platforms = {
            "GitHub": f"https://github.com/{username}",
            "Twitter (X)": f"https://twitter.com/{username}",
            "Instagram": f"https://instagram.com/{username}",
            "Reddit": f"https://www.reddit.com/user/{username}",
            "Medium": f"https://medium.com/@{username}",
            "Steam": f"https://steamcommunity.com/id/{username}",
            "TikTok": f"https://www.tiktok.com/@{username}",
            "YouTube": f"https://www.youtube.com/@{username}",
            "LinkedIn": f"https://linkedin.com/in/{username}",
            "Pinterest": f"https://pinterest.com/{username}",
            "Twitch": f"https://twitch.tv/{username}"
        }
        found = []
        for name, url in platforms.items():
            try:
                res = requests.get(url, timeout=3, headers=self.headers)
                if res.status_code == 200:
                    found.append({"Platform": name, "URL": url, "Status": "FOUND"})
            except: 
                pass
        return found

    # 2. EMAIL HARVESTING (E-posta Toplama)
    def email_harvesting(self, domain):
        """Domain'den bağlantılı e-postaları topla"""
        emails = set()
        try:
            with DDGS() as ddgs:
                # E-posta araması
                results = list(ddgs.text(f"site:{domain} email OR contact", max_results=10))
                for result in results:
                    found_emails = re.findall(self.email_regex, result['body'])
                    emails.update(found_emails)
                
                # WHOIS'ten e-postaları çıkar
                try:
                    w = whois.whois(domain)
                    if hasattr(w, 'admin_email'):
                        emails.add(w.admin_email)
                    if hasattr(w, 'tech_email'):
                        emails.add(w.tech_email)
                except:
                    pass
        except:
            pass
        
        return list(emails)

    # 3. SUBDOMAIN ENUMERATION (Alt-domain Keşfi)
    def subdomain_enum(self, domain):
        """Alına domainleri bul"""
        subdomains = set()
        common_subs = [
            "www", "mail", "ftp", "api", "admin", "test", "dev", "staging",
            "app", "backup", "blog", "news", "shop", "cdn", "git", "auth",
            "vpn", "ssl", "portal", "forum", "support", "help", "status"
        ]
        
        for sub in common_subs:
            try:
                hostname = f"{sub}.{domain}"
                ip = socket.gethostbyname(hostname)
                subdomains.add(frozenset([("Subdomain", hostname), ("IP", ip)]))
            except:
                pass
        
        # DuckDuckGo ile araştır
        try:
            with DDGS() as ddgs:
                results = list(ddgs.text(f"site:{domain}", max_results=5))
                for r in results:
                    urls = re.findall(r'https?://([^/]+)', r['body'])
                    for url in urls:
                        if domain in url:
                            subdomains.add(frozenset([("Subdomain", url), ("IP", "N/A")]))
        except:
            pass
        
        return [dict(s) for s in subdomains]

    # 4. BREACH SEARCH (Sızıntı Kontrolü)
    def breach_check(self, query):
        findings = []
        dorks = [
            f"site:pastebin.com '{query}'", 
            f"site:github.com '{query}' password",
            f"site:pastebin.com {query}",
            f"'{query}' breach OR leak OR exposed"
        ]
        try:
            with DDGS() as ddgs:
                for dork in dorks:
                    results = ddgs.text(dork, max_results=3)
                    for r in results:
                        findings.append({
                            "Source": "Potential Leak",
                            "URL": r['href'],
                            "Context": r['body'][:150]
                        })
            return findings
        except:
            return []

    # 5. WHOIS DETAYLI (WHOIS Analizi)
    def whois_lookup(self, domain):
        """Detaylı WHOIS bilgisi al"""
        try:
            w = whois.whois(domain)
            return {
                "Domain": w.domain,
                "Registrar": getattr(w, 'registrar', 'N/A'),
                "Creation Date": str(getattr(w, 'creation_date', 'N/A')),
                "Expiration Date": str(getattr(w, 'expiration_date', 'N/A')),
                "Admin": getattr(w, 'admin_name', 'N/A'),
                "Admin Email": getattr(w, 'admin_email', 'N/A'),
                "Tech Contact": getattr(w, 'tech_name', 'N/A'),
                "Nameservers": getattr(w, 'name_servers', 'N/A')
            }
        except Exception as e:
            return {"Error": str(e)}

    # 6. DNS RECORDS (DNS Kayıtları)
    def dns_records(self, domain):
        """Tüm DNS kayıtlarını al"""
        records = {}
        record_types = ['A', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']
        
        for rtype in record_types:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 5
                answer = resolver.resolve(domain, rtype)
                records[rtype] = [str(r) for r in answer]
            except:
                pass
        
        return records

    # 7. REVERSE DNS LOOKUP (Ters DNS)
    def reverse_dns(self, ip):
        """IP adresinin reverse DNS'ini al"""
        try:
            hostname = socket.gethostbyaddr(ip)
            return {"IP": ip, "Hostname": hostname[0], "Aliases": hostname[1]}
        except:
            return {"IP": ip, "Hostname": "N/A", "Error": "Reverse DNS başarısız"}

    # 8. GEO-IP LOCALIZATION (Coğrafi Konum)
    def geo_ip(self, target):
        try:
            ip = socket.gethostbyname(target)
            res = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
            return res if res.get('status') == 'success' else None
        except:
            return None

    # 9. WEB ARCHIVE (Wayback Machine)
    def web_archive(self, url):
        """Wayback Machine'den sayfa tarihçesi al"""
        try:
            domain = urlparse(url).netloc if "://" in url else url
            res = requests.get(f"https://archive.org/wayback/available?url={domain}", timeout=5).json()
            if res.get('archived_snapshots'):
                snapshots = res['archived_snapshots']
                if 'closest' in snapshots:
                    return {
                        "URL": snapshots['closest']['url'],
                        "Timestamp": snapshots['closest']['timestamp'],
                        "Status": snapshots['closest']['status']
                    }
            return {"Status": "No archives found"}
        except:
            return {"Error": "Archive sorgusu başarısız"}

    # 10. SSL CERTIFICATE SEARCH (SSL Sertifikası)
    def ssl_search(self, domain):
        """crt.sh üzerinden SSL sertifikalarını bul"""
        try:
            res = requests.get(f"https://crt.sh/?q={domain}&output=json", timeout=10).json()
            certs = []
            for cert in res[:10]:  # İlk 10'u al
                certs.append({
                    "Common Name": cert.get('common_name', 'N/A'),
                    "Issuer": cert.get('issuer_name', 'N/A'),
                    "Issued": cert.get('entry_timestamp', 'N/A')
                })
            return certs
        except:
            return []

    # 11. ASN & IP RANGE LOOKUP (ASN Araması)
    def asn_lookup(self, domain_or_ip):
        """ASN ve IP range bilgisi al"""
        try:
            try:
                ip = socket.gethostbyname(domain_or_ip)
            except:
                ip = domain_or_ip
            
            res = requests.get(f"http://ip-api.com/json/{ip}?fields=asn", timeout=5).json()
            if res.get('status') == 'success':
                return {
                    "IP": ip,
                    "ASN": res.get('asn', 'N/A'),
                    "ISP": res.get('isp', 'N/A'),
                    "Organization": res.get('org', 'N/A')
                }
            return {"Error": "ASN lookup başarısız"}
        except:
            return {"Error": "ASN lookup başarısız"}

    # 12. METADATA EXTRACTION (Meta Veri Çıkarma - Exiftool benzeri)
    def extract_metadata(self, file):
        """Exiftool gibi detaylı metadata çıkarma"""
        meta = {}
        file_info = {}
        
        try:
            # Dosya temel bilgileri
            file_info["File Name"] = file.name
            file_info["File Size"] = f"{file.size / 1024:.2f} KB"
            file_info["File Type"] = file.type
            
            if file.type.startswith("image"):
                try:
                    img = Image.open(file)
                    
                    # === TEMEL RESİM BİLGİSİ ===
                    meta["📷 IMAGE INFORMATION"] = {
                        "Format": img.format or "Unknown",
                        "Mode": img.mode,
                        "Width": img.width,
                        "Height": img.height,
                        "Size": f"{img.width}x{img.height}",
                        "DPI": img.info.get('dpi', 'N/A'),
                        "Is Animated": getattr(img, 'is_animated', False),
                        "Frames": img.n_frames if hasattr(img, 'n_frames') else 1
                    }
                    
                    # === EXIF VERİLERİ ===
                    exif_dict = {}
                    try:
                        exif = img.getexif()
                        if exif:
                            for tag, value in exif.items():
                                try:
                                    decoded = TAGS.get(tag, f"Tag {tag}")
                                    value_str = str(value)[:100]  # Uzun değerleri kes
                                    exif_dict[decoded] = value_str
                                except:
                                    exif_dict[f"Tag {tag}"] = str(value)[:100]
                    except:
                        pass
                    
                    if exif_dict:
                        meta["📸 EXIF DATA"] = exif_dict
                    
                    # === RESİM ÖZELLIKLERI ===
                    meta["🎨 IMAGE PROPERTIES"] = {
                        "Color Space": img.mode,
                        "Has Palette": hasattr(img, 'palette'),
                        "Has Transparency": 'transparency' in img.info,
                        "Compression": img.info.get('compression', 'N/A'),
                        "Format Description": img.info.get('description', 'N/A')
                    }
                    
                except Exception as e:
                    meta["Image Processing Error"] = str(e)
                    
            elif file.type == "application/pdf":
                try:
                    reader = PdfReader(file)
                    
                    # === PDF METADATA ===
                    pdf_meta = {}
                    if reader.metadata:
                        for k, v in reader.metadata.items():
                            pdf_meta[k.lstrip('/')] = str(v)
                    
                    if pdf_meta:
                        meta["📄 PDF METADATA"] = pdf_meta
                    
                    # === PDF BİLGİSİ ===
                    meta["📋 PDF INFORMATION"] = {
                        "Total Pages": len(reader.pages),
                        "Author": reader.metadata.get('/Author', 'N/A') if reader.metadata else 'N/A',
                        "Title": reader.metadata.get('/Title', 'N/A') if reader.metadata else 'N/A',
                        "Subject": reader.metadata.get('/Subject', 'N/A') if reader.metadata else 'N/A',
                        "Creator": reader.metadata.get('/Creator', 'N/A') if reader.metadata else 'N/A',
                        "Producer": reader.metadata.get('/Producer', 'N/A') if reader.metadata else 'N/A',
                        "Creation Date": str(reader.metadata.get('/CreationDate', 'N/A')) if reader.metadata else 'N/A',
                        "Modification Date": str(reader.metadata.get('/ModDate', 'N/A')) if reader.metadata else 'N/A',
                        "Encrypted": reader.is_encrypted
                    }
                    
                    # === İLK SAYFA BİLGİSİ ===
                    if len(reader.pages) > 0:
                        first_page = reader.pages[0]
                        page_info = {
                            "Width": first_page.mediabox.width,
                            "Height": first_page.mediabox.height,
                            "Rotation": first_page.get("/Rotate", 0),
                            "Resources": list(first_page.resources.keys()) if first_page.resources else []
                        }
                        meta["📖 FIRST PAGE"] = page_info
                    
                except Exception as e:
                    meta["PDF Processing Error"] = str(e)
            
            # === DOSYA BİLGİSİ ===
            meta["📁 FILE INFORMATION"] = file_info
            
        except Exception as e:
            meta["Critical Error"] = str(e)
        
        return meta

    # 13. PASSWORD STRENGTH (Şifre Gücü)
    def check_password(self, pwd):
        score = 0
        if len(pwd) >= 12: score += 2
        if any(c.isupper() for c in pwd): score += 1
        if any(c.isdigit() for c in pwd): score += 1
        if any(c in string.punctuation for c in pwd): score += 1
        return "Çok Güçlü" if score >= 4 else "Orta" if score >= 2 else "Zayıf"

# --- 4. ARAYÜZ TASARIMI ---
st.set_page_config(page_title="AmateurOSINT Hub", layout="wide", page_icon="🔍")
osint = AmateurOSINT()

st.title("🔍 AmateurOSINT Professional Hub")
st.markdown("*Profesyonel OSINT Araştırması İçin Kapsamlı Platform*")

# --- VISUAL DASHBOARD ---
st.markdown("### 📊 Operasyonel Dashboard")
col1, col2, col3, col4, col5, col6 = st.columns(6)
col1.metric("👤 Usernames", st.session_state.stats["usernames"])
col2.metric("⚠️ Breaches", st.session_state.stats["breaches"])
col3.metric("🌐 Subdomains", st.session_state.stats["subdomains"])
col4.metric("📧 Emails", st.session_state.stats["emails"])
col5.metric("🏢 Domains", st.session_state.stats["domains"])
col6.metric("📜 Certificates", st.session_state.stats["certificates"])
st.divider()

# --- SIDEBAR MENU ---
menu = st.sidebar.selectbox("🚀 OSINT Modülleri", [
    "🔍 Identity & Social Mapping",
    "📧 Email Harvesting",
    "🌐 Domain Intelligence",
    "⚠️ Breach Detection",
    "🛡️ Infrastructure Reconnaissance",
    "📜 SSL Certificates",
    "🖼️ Metadata Analysis",
    "📍 Geo-Intelligence",
    "🔐 Password Analysis",
    "📄 Generate Report"
])

# ===== MODÜL 1: IDENTITY & SOCIAL MAPPING =====
if menu == "🔍 Identity & Social Mapping":
    st.header("👤 Kimlik ve Sosyal Medya Haritası")
    st.markdown("Hedef kişinin sosyal medya ve çevrimiçi varlığını harita alır.")
    
    target = st.text_input("Hedef (İsim, E-posta veya @username)", placeholder="@macallantheroot")
    
    col_a, col_b, col_c = st.columns(3)
    with col_a:
        if st.button("🔎 Sosyal Medya Taraması", use_container_width=True):
            with st.spinner("Sosyal ağlar taranıyor..."):
                hits = osint.username_hunter(target)
                if hits:
                    st.session_state.stats["usernames"] += len(hits)
                    st.success(f"✅ {len(hits)} profil bulundu!")
                    st.dataframe(pd.DataFrame(hits), use_container_width=True)
                    st.session_state.report_results['Social Media Profiles'] = hits
                else:
                    st.warning("❌ Eşleşme bulunamadı.")
    
    with col_b:
        if st.button("🌐 Web İzlerini Ara", use_container_width=True):
            with st.spinner("Web taranıyor..."):
                try:
                    with DDGS() as ddgs:
                        results = list(ddgs.text(target, max_results=5))
                    if results:
                        st.success(f"✅ {len(results)} sonuç bulundu!")
                        for idx, r in enumerate(results, 1):
                            st.write(f"{idx}. **{r.get('title', 'N/A')}**")
                            st.caption(r.get('href', 'N/A'))
                        st.session_state.report_results['Web Search'] = results
                    else:
                        st.info("Sonuç bulunamadı.")
                except Exception as e:
                    st.error(f"Hata: {str(e)}")
    
    with col_c:
        if st.button("📊 Kişi Özeti", use_container_width=True):
            st.info("Web araması ve sosyal medya verilerini birleştirerek kişi profili oluştur.")

# ===== MODÜL 2: EMAIL HARVESTING =====
elif menu == "📧 Email Harvesting":
    st.header("📧 E-posta Toplama ve Validasyon")
    st.markdown("Hedef domain ile ilişkili tüm e-posta adreslerini keşfet.")
    
    domain = st.text_input("Hedef Domain", placeholder="example.com")
    
    col_x, col_y = st.columns(2)
    with col_x:
        if st.button("🔎 E-posta Ara", use_container_width=True):
            with st.spinner("E-postalar toplanıyor..."):
                emails = osint.email_harvesting(domain)
                if emails:
                    st.session_state.stats["emails"] += len(emails)
                    st.success(f"✅ {len(emails)} e-posta bulundu!")
                    for email in emails:
                        st.write(f"📧 `{email}`")
                    st.session_state.report_results['Emails Found'] = emails
                else:
                    st.warning("❌ E-posta bulunamadı.")
    
    with col_y:
        if st.button("🔍 WHOIS E-postaları", use_container_width=True):
            with st.spinner("WHOIS sorgulanıyor..."):
                emails = osint.email_harvesting(domain)
                whois_data = osint.whois_lookup(domain)
                if whois_data.get('Admin Email'):
                    st.success(f"✅ WHOIS verisi bulundu!")
                    st.json(whois_data)
                    st.session_state.report_results['WHOIS Data'] = whois_data

# ===== MODÜL 3: DOMAIN INTELLIGENCE =====
elif menu == "🌐 Domain Intelligence":
    st.header("🌐 Domain İstihbaratı ve Altyapı Analizi")
    st.markdown("Domain, DNS, WHOIS ve altyapı bilgilerini eksiksiz analiz et.")
    
    dom = st.text_input("Hedef Domain", placeholder="example.com")
    
    tabs = st.tabs(["WHOIS", "DNS Records", "Subdomains", "ASN Info"])
    
    with tabs[0]:
        if st.button("📋 WHOIS Sorgusu"):
            with st.spinner("WHOIS verileri alınıyor..."):
                whois_data = osint.whois_lookup(dom)
                st.session_state.stats["domains"] += 1
                st.json(whois_data)
                st.session_state.report_results['WHOIS Analysis'] = whois_data
    
    with tabs[1]:
        if st.button("📡 DNS Kayıtlarını Göster"):
            with st.spinner("DNS kayıtları alınıyor..."):
                dns_data = osint.dns_records(dom)
                if dns_data:
                    st.success(f"✅ {len(dns_data)} DNS kaydı bulundu!")
                    st.json(dns_data)
                    st.session_state.report_results['DNS Records'] = dns_data
                else:
                    st.warning("DNS kayıtları alınamadı.")
    
    with tabs[2]:
        if st.button("🔗 Alt-domainleri Tarama"):
            with st.spinner("Alt-domainler taranıyor..."):
                subs = osint.subdomain_enum(dom)
                if subs:
                    st.session_state.stats["subdomains"] += len(subs)
                    st.success(f"✅ {len(subs)} alt-domain bulundu!")
                    st.dataframe(pd.DataFrame(subs), use_container_width=True)
                    st.session_state.report_results['Subdomains'] = subs
    
    with tabs[3]:
        if st.button("🏢 ASN Bilgisi"):
            with st.spinner("ASN sorgulanıyor..."):
                asn = osint.asn_lookup(dom)
                st.json(asn)
                st.session_state.report_results['ASN Lookup'] = asn

# ===== MODÜL 4: BREACH DETECTION =====
elif menu == "⚠️ Breach Detection":
    st.header("⚠️ Sızıntı ve Dark Web Kontrolü")
    st.markdown("Hedefin veri ihlali veya sızıntısında olup olmadığını kontrol et.")
    
    query = st.text_input("E-posta veya Domain", placeholder="target@example.com")
    
    if st.button("🔍 Sızıntı Taraması", use_container_width=True):
        with st.spinner("Dark Web ve sızıntı kaynakları taranıyor..."):
            breaches = osint.breach_check(query)
            if breaches:
                st.session_state.stats["breaches"] += len(breaches)
                st.error(f"🚨 KRİTİK: {len(breaches)} adet olası sızıntı bulundu!")
                df = pd.DataFrame(breaches)
                st.dataframe(df, use_container_width=True)
                st.session_state.report_results['Breach Analysis'] = breaches
            else:
                st.success("✅ Temiz: Sızıntı izine rastlanmadı.")

# ===== MODÜL 5: INFRASTRUCTURE RECONNAISSANCE =====
elif menu == "🛡️ Infrastructure Reconnaissance":
    st.header("🛡️ Altyapı Keşfi ve Ters DNS")
    st.markdown("IP adresinin sahibi, reverse DNS ve lokasyon bilgisi.")
    
    ip_or_domain = st.text_input("IP Adresi veya Domain", placeholder="8.8.8.8 veya example.com")
    
    tabs = st.tabs(["Ters DNS", "Geo-IP", "Web Archive"])
    
    with tabs[0]:
        if st.button("🔄 Reverse DNS Sorgusu"):
            with st.spinner("Reverse DNS sorgulanıyor..."):
                try:
                    ip = socket.gethostbyname(ip_or_domain)
                except:
                    ip = ip_or_domain
                
                rev_dns = osint.reverse_dns(ip)
                st.json(rev_dns)
                st.session_state.report_results['Reverse DNS'] = rev_dns
    
    with tabs[1]:
        if st.button("📍 Geo-IP Haritası"):
            with st.spinner("Konum bilgisi alınıyor..."):
                geo = osint.geo_ip(ip_or_domain)
                if geo and 'lat' in geo:
                    st.success("✅ Konum bulundu!")
                    st.map(pd.DataFrame({'lat': [geo['lat']], 'lon': [geo['lon']]}))
                    st.json(geo)
                    st.session_state.report_results['Geo-Location'] = geo
                else:
                    st.error("❌ Konum bilgisi alınamadı.")
    
    with tabs[2]:
        if st.button("📜 Wayback Machine Arşivi"):
            with st.spinner("Web Archive sorgulanıyor..."):
                archive = osint.web_archive(ip_or_domain)
                st.json(archive)
                st.session_state.report_results['Web Archive'] = archive

# ===== MODÜL 6: SSL CERTIFICATES =====
elif menu == "📜 SSL Certificates":
    st.header("📜 SSL Sertifikası Analizi")
    st.markdown("Domain'in SSL sertifikaları ve tarihçesini görüntüle.")
    
    cert_domain = st.text_input("Hedef Domain", placeholder="*.example.com veya example.com")
    
    if st.button("🔎 SSL Sertifikalarını Ara", use_container_width=True):
        with st.spinner("SSL sertifikaları aranıyor..."):
            certs = osint.ssl_search(cert_domain)
            if certs:
                st.session_state.stats["certificates"] += len(certs)
                st.success(f"✅ {len(certs)} sertifika bulundu!")
                st.dataframe(pd.DataFrame(certs), use_container_width=True)
                st.session_state.report_results['SSL Certificates'] = certs
            else:
                st.warning("❌ Sertifika bulunamadı.")

# ===== MODÜL 7: METADATA ANALYSIS =====
elif menu == "🖼️ Metadata Analysis":
    st.header("🖼️ Dosya Meta Veri Analizi (Exiftool benzeri)")
    st.markdown("Resim veya PDF dosyalarından detaylı ve gizli bilgi çıkart. Exiftool benzeri kapsamlı analiz.")
    
    f = st.file_uploader("Resim veya PDF Yükle", type=["jpg", "jpeg", "png", "gif", "bmp", "tiff", "pdf"])
    if f:
        with st.spinner("Meta veriler derinlemesine analiz ediliyor..."):
            meta = osint.extract_metadata(f)
            if meta:
                st.success("✅ Dosya analiz tamamlandı!")
                
                # Kategoriye göre göster
                tabs = st.tabs(["📊 Tüm Veriler", "📁 Dosya Bilgisi", "📸 EXIF/PDF Meta", "🎨 Özellikler"])
                
                with tabs[0]:
                    st.json(meta)
                
                with tabs[1]:
                    if "📁 FILE INFORMATION" in meta:
                        st.subheader("📁 Dosya Bilgisi")
                        file_info = meta["📁 FILE INFORMATION"]
                        col1, col2, col3 = st.columns(3)
                        col1.metric("Dosya Adı", file_info.get("File Name", "N/A"))
                        col2.metric("Boyut", file_info.get("File Size", "N/A"))
                        col3.metric("Tip", file_info.get("File Type", "N/A"))
                
                with tabs[2]:
                    if "📸 EXIF DATA" in meta:
                        st.subheader("📸 EXIF Verileri")
                        exif = meta["📸 EXIF DATA"]
                        for key, value in exif.items():
                            st.write(f"**{key}:** `{value}`")
                    elif "📄 PDF METADATA" in meta:
                        st.subheader("📄 PDF Metadata")
                        pdf_meta = meta["📄 PDF METADATA"]
                        for key, value in pdf_meta.items():
                            st.write(f"**{key}:** `{value}`")
                
                with tabs[3]:
                    if "🎨 IMAGE PROPERTIES" in meta:
                        st.subheader("🎨 Resim Özellikleri")
                        props = meta["🎨 IMAGE PROPERTIES"]
                        for key, value in props.items():
                            st.write(f"**{key}:** `{value}`")
                    elif "📷 IMAGE INFORMATION" in meta:
                        st.subheader("📷 Resim Bilgisi")
                        img_info = meta["📷 IMAGE INFORMATION"]
                        col1, col2, col3, col4 = st.columns(4)
                        col1.metric("Format", img_info.get("Format", "N/A"))
                        col2.metric("Boyut", img_info.get("Size", "N/A"))
                        col3.metric("DPI", str(img_info.get("DPI", "N/A")))
                        col4.metric("Mode", img_info.get("Mode", "N/A"))
                
                st.session_state.report_results['Metadata Analysis'] = meta
            else:
                st.warning("⚠️ Dosya okunamadı veya metadata çıkarılamadı.")

# ===== MODÜL 8: GEO-INTELLIGENCE =====
elif menu == "📍 Geo-Intelligence":
    st.header("📍 Coğrafi Konum İstihbaratı")
    st.markdown("IP veya domain'in coğrafi konumunu harita üzerinde göster.")
    
    geo_target = st.text_input("IP veya Domain", placeholder="8.8.8.8 veya google.com")
    
    if st.button("🗺️ Haritada Göster", use_container_width=True):
        with st.spinner("Konum verisi yükleniyor..."):
            geo = osint.geo_ip(geo_target)
            if geo and 'lat' in geo:
                st.success("✅ Konum bulundu!")
                st.map(pd.DataFrame({'lat': [geo['lat']], 'lon': [geo['lon']]}))
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("Şehir", geo.get('city', 'N/A'))
                    st.metric("Ülke", geo.get('country', 'N/A'))
                with col2:
                    st.metric("ISP", geo.get('isp', 'N/A'))
                    st.metric("Enlem", geo.get('lat', 'N/A'))
                st.json(geo)
                st.session_state.report_results['Geo-Location'] = geo
            else:
                st.error("❌ Konum bilgisi alınamadı.")

# ===== MODÜL 9: PASSWORD ANALYSIS =====
elif menu == "🔐 Password Analysis":
    st.header("🔐 Şifre Güvenlik Analizi")
    st.markdown("Şifre gücünü analiz et ve iyileştirme önerileri al.")
    
    pwd_in = st.text_input("Analiz Edilecek Şifre", type="password")
    if pwd_in:
        strength = osint.check_password(pwd_in)
        
        col1, col2 = st.columns(2)
        with col1:
            if strength == "Çok Güçlü":
                st.success(f"🟢 {strength}")
            elif strength == "Orta":
                st.warning(f"🟡 {strength}")
            else:
                st.error(f"🔴 {strength}")
        with col2:
            st.metric("Uzunluk", len(pwd_in))
        
        st.session_state.report_results['Password Strength'] = {
            "Strength": strength,
            "Length": len(pwd_in)
        }

# ===== MODÜL 10: GENERATE REPORT =====
elif menu == "📄 Generate Report":
    st.header("📄 Profesyonel OSINT Raporu Oluştur")
    st.markdown("Tüm topladığınız verileri profesyonel PDF raporuna dönüştür.")
    
    if not st.session_state.report_results:
        st.warning("⚠️ Veritabanı boş! Önce diğer modüllerde tarama yapın.")
    else:
        st.info(f"📊 {len(st.session_state.report_results)} bölüm verileri var.")
        
        if st.button("📥 PDF Raporunu Oluştur ve İndir", use_container_width=True):
            with st.spinner("Rapor oluşturuluyor..."):
                try:
                    pdf = AmateurOSINTReport()
                    pdf.add_page()
                    
                    for k, v in st.session_state.report_results.items():
                        pdf.chapter_title(k)
                        pdf.chapter_body(str(v))
                    
                    # PDF'yi UTF-8 ile güvenli şekilde oluştur
                    pdf_bytes = pdf.output(dest='S')
                    if isinstance(pdf_bytes, str):
                        pdf_bytes = pdf_bytes.encode('utf-8', 'ignore')
                    
                    st.success("✅ Rapor hazır!")
                    st.download_button(
                        "📥 PDF Raporunu İndir",
                        pdf_bytes,
                        "AmateurOSINT_Report.pdf",
                        "application/pdf",
                        use_container_width=True
                    )
                except Exception as e:
                    st.error(f"❌ Rapor oluşturulurken hata: {str(e)}")
        
        if st.button("🗑️ Verileri Temizle", use_container_width=True):
            st.session_state.report_results.clear()
            st.rerun()

# --- FOOTER ---
st.divider()
st.markdown("**AmateurOSINT v1.0** | Etik OSINT Araştırması Platformu | *Yalnızca yasal amaçlar için kullanın* |  **github.com/macallantheroot/AmateurOSINT**")
