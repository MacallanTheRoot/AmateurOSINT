import streamlit as st
import streamlit.components.v1 as components
import pandas as pd
import networkx as nx
import json
from datetime import datetime
from time import perf_counter
from fpdf import FPDF
from ddgs import DDGS
from pyvis.network import Network
import socket
from urllib.parse import urlparse

from async_osint import AmateurOSINT
from config import get_api_key_values, load_api_keys_to_environment, save_api_key_values
from database import DatabaseManager


# --- 1. SESSION STATE & STATS ---
if "stats" not in st.session_state:
    st.session_state.stats = {
        "emails": 0,
        "breaches": 0,
        "subdomains": 0,
        "usernames": 0,
        "domains": 0,
        "ips": 0,
        "certificates": 0,
    }
if "report_results" not in st.session_state:
    st.session_state.report_results = {}
if "last_scan_id" not in st.session_state:
    st.session_state.last_scan_id = None
if "async_timeout" not in st.session_state:
    st.session_state.async_timeout = 7
if "async_concurrency" not in st.session_state:
    st.session_state.async_concurrency = 12
if "retention_days" not in st.session_state:
    st.session_state.retention_days = 30
if "scan_timings" not in st.session_state:
    st.session_state.scan_timings = []
if "max_graph_nodes" not in st.session_state:
    st.session_state.max_graph_nodes = 100
if "language" not in st.session_state:
    st.session_state.language = "tr"
if "wmn_enabled" not in st.session_state:
    st.session_state.wmn_enabled = True
if "wmn_site_limit" not in st.session_state:
    st.session_state.wmn_site_limit = 180


def _tr(tr_text, en_text):
    return tr_text if st.session_state.language == "tr" else en_text


# --- 2. PROFESYONEL RAPORLAMA (PDF) ---
class AmateurOSINTReport(FPDF):
    def header(self):
        self.set_font("Arial", "B", 15)
        self.cell(0, 10, "AmateurOSINT Professional Intelligence Report", 0, 1, "C")
        self.ln(10)

    def chapter_title(self, title):
        self.set_font("Arial", "B", 12)
        self.set_fill_color(230, 230, 230)
        safe_title = str(title).encode("ascii", "ignore").decode("ascii")
        self.cell(0, 10, f"Section: {safe_title}", 0, 1, "L", True)
        self.ln(5)

    def chapter_body(self, body):
        self.set_font("Arial", "", 10)
        safe_body = str(body).encode("ascii", "ignore").decode("ascii")
        self.multi_cell(0, 6, safe_body)
        self.ln()


# --- 3. INIT SERVICES ---
osint = AmateurOSINT()
db = DatabaseManager()

try:
    db.init_db()
except Exception as exc:
    st.warning(f"Veritabani baslatilamadi: {str(exc)}")

try:
    load_api_keys_to_environment()
except Exception as exc:
    st.warning(f"API key environment yuklenemedi: {str(exc)}")

try:
    osint.set_runtime_config(
        timeout_seconds=st.session_state.async_timeout,
        concurrent_limit=st.session_state.async_concurrency,
    )
    osint.set_wmn_config(
        enabled=st.session_state.wmn_enabled,
        site_limit=st.session_state.wmn_site_limit,
    )
except Exception as exc:
    st.warning(f"Async ayarlari baslatilamadi: {str(exc)}")


def _persist_scan(module_name, target_value, target_type, result_payload, entities=None, relationships=None, status="success"):
    try:
        scan_id = db.save_scan_result(
            module_name=module_name,
            target_value=str(target_value or "N/A"),
            target_type=target_type,
            raw_result=result_payload,
            status=status,
        )
        if not scan_id:
            st.warning("Tarama gecmisi kaydedilemedi.")
            return

        st.session_state.last_scan_id = scan_id
        if entities:
            ref_map = db.save_entities(scan_result_id=scan_id, entities=entities)
            if relationships and ref_map:
                db.save_relationships(relationships=relationships, ref_to_id=ref_map)
    except Exception as exc:
        st.warning(f"Kayit hatasi: {str(exc)}")


def _time_scan(module_name, scan_callable, *args):
    started = perf_counter()
    result = scan_callable(*args)
    elapsed = perf_counter() - started

    timing_entry = {
        "module": module_name,
        "seconds": round(elapsed, 3),
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
    }
    st.session_state.scan_timings.append(timing_entry)
    st.session_state.scan_timings = st.session_state.scan_timings[-100:]
    return result, elapsed


def _graph_color_map():
    return {
        "Domain": "#1f77b4",
        "IP": "#2ca02c",
        "Email": "#d62728",
        "Username": "#9467bd",
        "Subdomain": "#0ea5e9",
        "ASN": "#f59e0b",
        "Country": "#22c55e",
        "City": "#14b8a6",
        "SocialProfile": "#ff7f0e",
        "LeakReference": "#e377c2",
        "Query": "#8c564b",
    }


def _build_person_summary(target: str) -> str:
    social_profiles = st.session_state.report_results.get("Social Media Profiles", [])
    web_results = st.session_state.report_results.get("Web Search", [])

    if not social_profiles and not web_results:
        return _tr(
            "### Kisi Ozeti\n\nYeterli veri yok. Once Sosyal Medya Taramasi ve Web Izlerini Ara adimlarini calistirin.",
            "### Person Summary\n\nInsufficient data. Run Social Media Scan and Web Footprint Search first.",
        )

    profile_count = len(social_profiles) if isinstance(social_profiles, list) else 0
    web_count = len(web_results) if isinstance(web_results, list) else 0

    platform_lines = []
    if isinstance(social_profiles, list):
        for item in social_profiles[:10]:
            platform = item.get("Platform", "N/A")
            url = item.get("URL", "N/A")
            platform_lines.append(f"- {platform}: {url}")

    domains = []
    web_lines = []
    if isinstance(web_results, list):
        for item in web_results[:8]:
            href = str(item.get("href", ""))
            title = str(item.get("title", "N/A"))
            body = str(item.get("body", ""))[:180]
            domain = urlparse(href).netloc if href else ""
            if domain:
                domains.append(domain)
            web_lines.append(f"- {title} ({href})\\n  - {body}")

    unique_domains = sorted(set(domains))
    domain_preview = ", ".join(unique_domains[:8]) if unique_domains else "N/A"

    risk_keywords = ["breach", "leak", "pastebin", "password", "exposed", "compromised"]
    risk_hits = 0
    if isinstance(web_results, list):
        for item in web_results:
            corpus = f"{item.get('title', '')} {item.get('body', '')}".lower()
            if any(keyword in corpus for keyword in risk_keywords):
                risk_hits += 1

    summary = [
        _tr("### Kisi Ozeti", "### Person Summary"),
        _tr(f"**Hedef:** {target or 'N/A'}", f"**Target:** {target or 'N/A'}"),
        _tr(f"**Bulunan Sosyal Profil Sayisi:** {profile_count}", f"**Social Profiles Found:** {profile_count}"),
        _tr(f"**Ilgili Web Sonuc Sayisi:** {web_count}", f"**Relevant Web Results:** {web_count}"),
        _tr(f"**Gozlenen Domainler:** {domain_preview}", f"**Observed Domains:** {domain_preview}"),
        _tr(f"**Risk Isareti Tasiyan Sonuc Sayisi:** {risk_hits}", f"**Results With Risk Indicators:** {risk_hits}"),
        "",
        _tr("#### Sosyal Medya Profilleri", "#### Social Profiles"),
        "\n".join(platform_lines) if platform_lines else _tr("- Profil verisi yok", "- No profile data"),
        "",
        _tr("#### Web Ayak Izleri", "#### Web Footprints"),
        "\n".join(web_lines) if web_lines else _tr("- Web ayak izi verisi yok", "- No web footprint data"),
    ]
    return "\n".join(summary)


def _report_value_to_text(value):
    if isinstance(value, pd.DataFrame):
        return value.to_csv(index=False)
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value, indent=2, ensure_ascii=True)
        except Exception:
            return str(value)
    return str(value)


def _localize_report_section_title(key: str) -> str:
    raw_key = str(key or "").strip()
    key_lc = raw_key.lower()

    section_map = {
        "social media profiles": ("Sosyal Medya Profilleri", "Social Media Profiles"),
        "sosyal medya profilleri": ("Sosyal Medya Profilleri", "Social Media Profiles"),
        "web search": ("Web Arama Sonuclari", "Web Search Results"),
        "web arama sonuclari": ("Web Arama Sonuclari", "Web Search Results"),
        "person summary": ("Kisi Ozeti", "Person Summary"),
        "kisi ozeti": ("Kisi Ozeti", "Person Summary"),
        "emails found": ("Bulunan E-postalar", "Emails Found"),
        "bulunan e-postalar": ("Bulunan E-postalar", "Emails Found"),
        "whois data": ("WHOIS Verisi", "WHOIS Data"),
        "whois verisi": ("WHOIS Verisi", "WHOIS Data"),
        "whois analysis": ("WHOIS Analizi", "WHOIS Analysis"),
        "whois analizi": ("WHOIS Analizi", "WHOIS Analysis"),
        "dns records": ("DNS Kayitlari", "DNS Records"),
        "dns kayitlari": ("DNS Kayitlari", "DNS Records"),
        "subdomains": ("Alt Domainler", "Subdomains"),
        "alt domainler": ("Alt Domainler", "Subdomains"),
        "asn lookup": ("ASN Sorgusu", "ASN Lookup"),
        "asn sorgusu": ("ASN Sorgusu", "ASN Lookup"),
        "breach analysis": ("Sizinti Analizi", "Breach Analysis"),
        "sizinti analizi": ("Sizinti Analizi", "Breach Analysis"),
        "reverse dns": ("Ters DNS", "Reverse DNS"),
        "ters dns": ("Ters DNS", "Reverse DNS"),
        "geo-location": ("Geo-Konum", "Geo-Location"),
        "geo-konum": ("Geo-Konum", "Geo-Location"),
        "web archive": ("Web Arsivi", "Web Archive"),
        "web arsivi": ("Web Arsivi", "Web Archive"),
        "ssl certificates": ("SSL Sertifikalari", "SSL Certificates"),
        "ssl sertifikalari": ("SSL Sertifikalari", "SSL Certificates"),
        "metadata analysis": ("Metadata Analizi", "Metadata Analysis"),
        "metadata analizi": ("Metadata Analizi", "Metadata Analysis"),
        "password strength": ("Sifre Guclulugu", "Password Strength"),
        "sifre guclulugu": ("Sifre Guclulugu", "Password Strength"),
    }

    if key_lc.startswith("bulk "):
        suffix = raw_key[5:].strip().replace("_", " ").title()
        return _tr(f"Toplu Tarama - {suffix}", f"Bulk Scan - {suffix}")

    if key_lc in section_map:
        tr_title, en_title = section_map[key_lc]
        return _tr(tr_title, en_title)

    return raw_key


def _build_localized_report_snapshot(report_results: dict) -> dict:
    if not isinstance(report_results, dict):
        return {}

    snapshot = {}
    for key, value in report_results.items():
        snapshot[_localize_report_section_title(str(key))] = value
    return snapshot


def _load_bulk_targets(uploaded_file, target_column):
    if not uploaded_file:
        return []

    file_name = str(uploaded_file.name).lower()
    targets = []

    try:
        if file_name.endswith(".txt"):
            raw_text = uploaded_file.getvalue().decode("utf-8", errors="ignore")
            targets = [line.strip() for line in raw_text.splitlines() if line.strip()]
        elif file_name.endswith(".csv"):
            csv_df = pd.read_csv(uploaded_file)
            if target_column and target_column in csv_df.columns:
                targets = [str(item).strip() for item in csv_df[target_column].dropna().tolist()]
            elif len(csv_df.columns) > 0:
                first_column = csv_df.columns[0]
                targets = [str(item).strip() for item in csv_df[first_column].dropna().tolist()]
    except Exception:
        return []

    deduped = []
    seen = set()
    for target in targets:
        if target and target not in seen:
            deduped.append(target)
            seen.add(target)
    return deduped


def _build_geo_entities(target, geo_result):
    if not isinstance(geo_result, dict):
        return [], []

    root_type = "IP" if all(char.isdigit() or char == "." for char in str(target)) else "Domain"
    entities = [
        {
            "ref": "target",
            "entity_type": root_type,
            "entity_value": str(target),
            "metadata": {"source": "geo_ip"},
        }
    ]
    relationships = []

    country = geo_result.get("country")
    city = geo_result.get("city")
    ip_value = geo_result.get("query") or geo_result.get("ip")

    if ip_value and root_type != "IP":
        entities.append(
            {
                "ref": "resolved_ip",
                "entity_type": "IP",
                "entity_value": str(ip_value),
                "metadata": geo_result,
            }
        )
        relationships.append(
            {
                "source_ref": "target",
                "target_ref": "resolved_ip",
                "relation_type": "resolves_to",
            }
        )

    if country:
        entities.append(
            {
                "ref": "country",
                "entity_type": "Country",
                "entity_value": str(country),
                "metadata": {},
            }
        )
        relationships.append(
            {
                "source_ref": "target",
                "target_ref": "country",
                "relation_type": "located_in",
            }
        )

    if city:
        entities.append(
            {
                "ref": "city",
                "entity_type": "City",
                "entity_value": str(city),
                "metadata": {},
            }
        )
        relationships.append(
            {
                "source_ref": "country" if country else "target",
                "target_ref": "city",
                "relation_type": "contains_city",
            }
        )

    return entities, relationships


def _build_entities_for_scan(scan_kind, target, result):
    if scan_kind == "username_hunter":
        return _build_username_entities(target, result if isinstance(result, list) else [])
    if scan_kind == "email_harvesting":
        return _build_email_entities(target, result if isinstance(result, list) else [])
    if scan_kind == "breach_check":
        return _build_breach_entities(target, result if isinstance(result, list) else [])
    if scan_kind == "geo_ip":
        return _build_geo_entities(target, result)
    return [], []


def _build_username_entities(target, hits):
    entities = [
        {
            "ref": "target",
            "entity_type": "Username",
            "entity_value": str(target),
            "metadata": {"source": "identity_scan"},
        }
    ]
    relationships = []

    for idx, hit in enumerate(hits, start=1):
        ref = f"profile_{idx}"
        entities.append(
            {
                "ref": ref,
                "entity_type": "SocialProfile",
                "entity_value": hit.get("URL", "N/A"),
                "metadata": hit,
            }
        )
        relationships.append(
            {
                "source_ref": "target",
                "target_ref": ref,
                "relation_type": "found_on",
            }
        )

    return entities, relationships


def _build_email_entities(domain, emails):
    entities = [
        {
            "ref": "target",
            "entity_type": "Domain",
            "entity_value": str(domain),
            "metadata": {"source": "email_harvest"},
        }
    ]
    relationships = []

    for idx, email in enumerate(emails, start=1):
        ref = f"email_{idx}"
        entities.append(
            {
                "ref": ref,
                "entity_type": "Email",
                "entity_value": str(email),
                "metadata": {},
            }
        )
        relationships.append(
            {
                "source_ref": "target",
                "target_ref": ref,
                "relation_type": "has_email",
            }
        )

    return entities, relationships


def _build_breach_entities(query, breaches):
    entities = [
        {
            "ref": "target",
            "entity_type": "Query",
            "entity_value": str(query),
            "metadata": {"source": "breach_check"},
        }
    ]
    relationships = []

    for idx, breach in enumerate(breaches, start=1):
        ref = f"leak_{idx}"
        entities.append(
            {
                "ref": ref,
                "entity_type": "LeakReference",
                "entity_value": breach.get("URL", "N/A"),
                "metadata": breach,
            }
        )
        relationships.append(
            {
                "source_ref": "target",
                "target_ref": ref,
                "relation_type": "mentioned_in",
            }
        )

    return entities, relationships


def _build_subdomain_entities(domain, subdomains):
    entities = [
        {
            "ref": "target_domain",
            "entity_type": "Domain",
            "entity_value": str(domain),
            "metadata": {"source": "subdomain_enum"},
        }
    ]
    relationships = []

    for idx, item in enumerate(subdomains, start=1):
        sub_ref = f"sub_{idx}"
        ip_ref = f"ip_{idx}"
        subdomain = item.get("Subdomain", "N/A")
        ip_address = item.get("IP", "N/A")

        entities.append(
            {
                "ref": sub_ref,
                "entity_type": "Subdomain",
                "entity_value": str(subdomain),
                "metadata": item,
            }
        )
        relationships.append(
            {
                "source_ref": "target_domain",
                "target_ref": sub_ref,
                "relation_type": "contains_subdomain",
            }
        )

        if ip_address and ip_address != "N/A":
            entities.append(
                {
                    "ref": ip_ref,
                    "entity_type": "IP",
                    "entity_value": str(ip_address),
                    "metadata": {"source": "dns_resolution"},
                }
            )
            relationships.append(
                {
                    "source_ref": sub_ref,
                    "target_ref": ip_ref,
                    "relation_type": "resolves_to",
                }
            )

    return entities, relationships


def _build_asn_entities(domain, asn_data):
    entities = [
        {
            "ref": "target_domain",
            "entity_type": "Domain",
            "entity_value": str(domain),
            "metadata": {"source": "asn_lookup"},
        }
    ]
    relationships = []

    ip_value = asn_data.get("IP")
    asn_value = asn_data.get("ASN")
    isp_value = asn_data.get("ISP")

    if ip_value:
        entities.append(
            {
                "ref": "asn_ip",
                "entity_type": "IP",
                "entity_value": str(ip_value),
                "metadata": asn_data,
            }
        )
        relationships.append(
            {
                "source_ref": "target_domain",
                "target_ref": "asn_ip",
                "relation_type": "resolves_to",
            }
        )

    if asn_value:
        entities.append(
            {
                "ref": "asn_number",
                "entity_type": "ASN",
                "entity_value": str(asn_value),
                "metadata": {"ISP": isp_value},
            }
        )
        if ip_value:
            relationships.append(
                {
                    "source_ref": "asn_ip",
                    "target_ref": "asn_number",
                    "relation_type": "announced_by",
                }
            )

    return entities, relationships


def _render_graph(graph_data, allowed_groups=None, max_nodes=100):
    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])

    if allowed_groups:
        allowed_set = set(allowed_groups)
        nodes = [node for node in nodes if node.get("group") in allowed_set]
        allowed_ids = {node["id"] for node in nodes}
        edges = [edge for edge in edges if edge.get("from") in allowed_ids and edge.get("to") in allowed_ids]

    if not nodes:
        st.warning(_tr("Graf olusturmak icin yeterli varlik bulunamadi.", "Not enough entities to build a graph."))
        return

    original_node_count = len(nodes)
    original_edge_count = len(edges)

    try:
        safe_limit = max(1, int(max_nodes))
    except Exception:
        safe_limit = 100

    if len(nodes) > safe_limit:
        graph_for_degree = nx.Graph()
        for node in nodes:
            graph_for_degree.add_node(node["id"])
        for edge in edges:
            graph_for_degree.add_edge(edge.get("from"), edge.get("to"))

        degree_map = dict(graph_for_degree.degree())
        node_map = {node["id"]: node for node in nodes}

        priority_groups = {"Domain", "Username", "Query", "Email", "IP"}
        priority_nodes = sorted(
            [node for node in nodes if node.get("group") in priority_groups],
            key=lambda item: item.get("id", 0),
        )
        priority_ids = {node["id"] for node in priority_nodes}

        direct_neighbor_ids = set()
        for edge in edges:
            src = edge.get("from")
            dst = edge.get("to")
            if src in priority_ids:
                direct_neighbor_ids.add(dst)
            if dst in priority_ids:
                direct_neighbor_ids.add(src)

        direct_neighbors = [node_map[node_id] for node_id in direct_neighbor_ids if node_id in node_map and node_id not in priority_ids]
        direct_neighbors = sorted(direct_neighbors, key=lambda item: degree_map.get(item["id"], 0), reverse=True)

        other_nodes = [
            node for node in nodes
            if node["id"] not in priority_ids and node["id"] not in direct_neighbor_ids
        ]
        other_nodes = sorted(
            other_nodes,
            key=lambda item: (degree_map.get(item["id"], 0), -int(item.get("id", 0))),
            reverse=True,
        )

        selected_nodes = []
        selected_ids = set()

        for bucket in [priority_nodes, direct_neighbors, other_nodes]:
            for node in bucket:
                node_id = node["id"]
                if node_id in selected_ids:
                    continue
                selected_nodes.append(node)
                selected_ids.add(node_id)
                if len(selected_nodes) >= safe_limit:
                    break
            if len(selected_nodes) >= safe_limit:
                break

        nodes = selected_nodes
        edges = [
            edge for edge in edges
            if edge.get("from") in selected_ids and edge.get("to") in selected_ids
        ]

        st.caption(
            _tr(
                f"Performans icin grafik kisaltildi: dugum {original_node_count} -> {len(nodes)}, kenar {original_edge_count} -> {len(edges)}",
                f"Graph truncated for performance: nodes {original_node_count} -> {len(nodes)}, edges {original_edge_count} -> {len(edges)}",
            )
        )

    try:
        nx_graph = nx.DiGraph()
        for node in nodes:
            nx_graph.add_node(
                node["id"],
                label=node.get("label", "N/A"),
                group=node.get("group", "Unknown"),
                title=node.get("title", ""),
            )

        for edge in edges:
            nx_graph.add_edge(
                edge["from"],
                edge["to"],
                label=edge.get("label", "related_to"),
            )

        color_map = _graph_color_map()

        net = Network(height="680px", width="100%", directed=True, bgcolor="#0f172a", font_color="#f8fafc")
        net.barnes_hut()

        for node_id, attrs in nx_graph.nodes(data=True):
            group = attrs.get("group", "Unknown")
            net.add_node(
                node_id,
                label=attrs.get("label", "N/A"),
                title=attrs.get("title", ""),
                color=color_map.get(group, "#64748b"),
                shape="dot",
                size=16,
            )

        for source, target, attrs in nx_graph.edges(data=True):
            net.add_edge(source, target, label=attrs.get("label", "related_to"))

        html_content = net.generate_html(notebook=False)
        components.html(html_content, height=700, scrolling=True)
    except Exception as exc:
        st.error(_tr(f"Graf olusturma hatasi: {str(exc)}", f"Graph generation error: {str(exc)}"))


# --- 4. ARAYUZ TASARIMI ---
st.set_page_config(page_title="AmateurOSINT Hub", layout="wide", page_icon="🔍")
st.title(_tr("🔍 AmateurOSINT Profesyonel Hub", "🔍 AmateurOSINT Professional Hub"))
st.markdown(_tr("*Profesyonel OSINT Arastirmasi Icin Kapsamli Platform*", "*Comprehensive Platform for Professional OSINT Research*"))

# --- VISUAL DASHBOARD ---
st.markdown(_tr("### 📊 Operasyonel Dashboard", "### 📊 Operational Dashboard"))
col1, col2, col3, col4, col5, col6 = st.columns(6)
col1.metric(_tr("👤 Kullanici Adlari", "👤 Usernames"), st.session_state.stats["usernames"])
col2.metric(_tr("⚠️ Sizintilar", "⚠️ Breaches"), st.session_state.stats["breaches"])
col3.metric(_tr("🌐 Alt Domainler", "🌐 Subdomains"), st.session_state.stats["subdomains"])
col4.metric(_tr("📧 E-postalar", "📧 Emails"), st.session_state.stats["emails"])
col5.metric(_tr("🏢 Domainler", "🏢 Domains"), st.session_state.stats["domains"])
col6.metric(_tr("📜 Sertifikalar", "📜 Certificates"), st.session_state.stats["certificates"])
st.divider()

with st.expander(_tr("⚡ Tarama Performansi", "⚡ Scan Performance"), expanded=False):
    timing_df = pd.DataFrame(st.session_state.scan_timings)
    if not timing_df.empty:
        latest = timing_df.iloc[-1]
        avg_latency = timing_df["seconds"].mean()
        col_perf1, col_perf2 = st.columns(2)
        col_perf1.metric(_tr("Son Tarama", "Last Scan"), f"{latest['module']} ({latest['seconds']}s)")
        col_perf2.metric(_tr("Ortalama Gecikme", "Average Latency"), f"{avg_latency:.2f}s")
        st.dataframe(timing_df.tail(15), use_container_width=True)
    else:
        st.info(_tr("Tarama calistirdiktan sonra performans verisi gorunecek.", "Performance data will appear after running scans."))

# --- SIDEBAR MENU ---
with st.sidebar.expander(_tr("Async Runtime Ayarlari", "Async Runtime Settings"), expanded=False):
    timeout_value = st.number_input(_tr("HTTP zaman asimi (saniye)", "HTTP timeout (seconds)"), min_value=2, max_value=30, value=st.session_state.async_timeout)
    concurrency_value = st.number_input(_tr("Maksimum eszamanli istek", "Max concurrent requests"), min_value=1, max_value=50, value=st.session_state.async_concurrency)
    wmn_enabled_value = st.toggle(_tr("WMN kontrollerini etkinlestir", "Enable WMN checks"), value=st.session_state.wmn_enabled)
    wmn_site_limit_value = st.slider(_tr("WMN site kapsami", "WMN site coverage"), min_value=0, max_value=500, value=st.session_state.wmn_site_limit, step=10)
    if st.button(_tr("Async Ayarlarini Uygula", "Apply Async Settings"), use_container_width=True):
        try:
            st.session_state.async_timeout = int(timeout_value)
            st.session_state.async_concurrency = int(concurrency_value)
            st.session_state.wmn_enabled = bool(wmn_enabled_value)
            st.session_state.wmn_site_limit = int(wmn_site_limit_value)
            osint.set_runtime_config(
                timeout_seconds=st.session_state.async_timeout,
                concurrent_limit=st.session_state.async_concurrency,
            )
            osint.set_wmn_config(
                enabled=st.session_state.wmn_enabled,
                site_limit=st.session_state.wmn_site_limit,
            )
            st.sidebar.success(_tr("Runtime ayarlari guncellendi.", "Runtime settings updated."))
        except Exception as exc:
            st.sidebar.warning(_tr(f"Ayarlar uygulanamadi: {str(exc)}", f"Could not apply settings: {str(exc)}"))

st.sidebar.selectbox(
    _tr("Dil", "Language"),
    options=["tr", "en"],
    format_func=lambda item: "Turkce" if item == "tr" else "English",
    key="language",
)

with st.sidebar.expander("Data Retention", expanded=False):
    retention_value = st.number_input(
        _tr("Veriyi saklama suresi (gun)", "Keep data for days"),
        min_value=1,
        max_value=3650,
        value=st.session_state.retention_days,
    )
    if st.button(_tr("Eski Verileri Temizle", "Cleanup Old Data"), use_container_width=True):
        try:
            st.session_state.retention_days = int(retention_value)
            result = db.cleanup_old_scans(st.session_state.retention_days)
            st.sidebar.success(
                _tr(
                    (
                        f"Silinen taramalar={result.get('scans_deleted', 0)}, "
                        f"varliklar={result.get('entities_deleted', 0)}, "
                        f"iliskiler={result.get('relationships_deleted', 0)}"
                    ),
                    (
                        f"Deleted scans={result.get('scans_deleted', 0)}, "
                        f"entities={result.get('entities_deleted', 0)}, "
                        f"relationships={result.get('relationships_deleted', 0)}"
                    ),
                )
            )
        except Exception as exc:
            st.sidebar.warning(_tr(f"Temizleme basarisiz: {str(exc)}", f"Cleanup failed: {str(exc)}"))

menu_items = [
    ("identity", "🔍 Kimlik ve Sosyal Haritalama", "🔍 Identity & Social Mapping"),
    ("email", "📧 E-posta Toplama", "📧 Email Harvesting"),
    ("domain", "🌐 Domain Istihbarati", "🌐 Domain Intelligence"),
    ("breach", "⚠️ Sizinti Tespiti", "⚠️ Breach Detection"),
    ("infra", "🛡️ Altyapi Kesfi", "🛡️ Infrastructure Reconnaissance"),
    ("ssl", "📜 SSL Sertifikalari", "📜 SSL Certificates"),
    ("metadata", "🖼️ Metadata Analizi", "🖼️ Metadata Analysis"),
    ("geo", "📍 Geo-Istihbarat", "📍 Geo-Intelligence"),
    ("password", "🔐 Sifre Analizi", "🔐 Password Analysis"),
    ("bulk", "📦 Toplu Tarama", "📦 Bulk Scan"),
    ("graph", "🕸️ Iliski Grafigi ve Gecmis", "🕸️ Relationship Graph & History"),
    ("settings", "⚙️ Ayarlar ve API Anahtarlari", "⚙️ Settings & API Keys"),
    ("report", "📄 Rapor Olustur", "📄 Generate Report"),
]

menu_key = st.sidebar.selectbox(
    _tr("🚀 OSINT Modulleri", "🚀 OSINT Modules"),
    options=[item[0] for item in menu_items],
    format_func=lambda key: next((item[1] if st.session_state.language == "tr" else item[2] for item in menu_items if item[0] == key), key),
)

# ===== MODUL 1: IDENTITY & SOCIAL MAPPING =====
if menu_key == "identity":
    st.header(_tr("👤 Kimlik ve Sosyal Medya Haritasi", "👤 Identity & Social Media Mapping"))
    st.markdown(_tr("Hedef kisinin sosyal medya ve cevrimici varligini haritala.", "Map the target's social media and online footprint."))

    target = st.text_input(_tr("Hedef (Isim, E-posta veya @username)", "Target (Name, Email, or @username)"), placeholder="@macallantheroot")

    col_a, col_b, col_c = st.columns(3)
    with col_a:
        if st.button(_tr("🔎 Sosyal Medya Taramasi", "🔎 Social Media Scan"), use_container_width=True):
            with st.spinner(_tr("Sosyal aglar taraniyor (async)...", "Scanning social platforms (async)...")):
                try:
                    hits, elapsed = _time_scan("username_hunter", osint.username_hunter, target)
                    st.caption(f"Completed in {elapsed:.2f} seconds")
                    if hits:
                        st.session_state.stats["usernames"] += len(hits)
                        st.success(_tr(f"✅ {len(hits)} profil bulundu!", f"✅ {len(hits)} profiles found!"))
                        st.dataframe(pd.DataFrame(hits), use_container_width=True)
                        st.session_state.report_results["Social Media Profiles"] = hits

                        entities, relationships = _build_username_entities(target, hits)
                        _persist_scan(
                            module_name="username_hunter",
                            target_value=target,
                            target_type="username",
                            result_payload=hits,
                            entities=entities,
                            relationships=relationships,
                        )
                    else:
                        st.warning(_tr("❌ Eslesme bulunamadi.", "❌ No matches found."))
                except Exception as exc:
                    st.error(_tr(f"Sosyal medya taramasi hatasi: {str(exc)}", f"Social media scan error: {str(exc)}"))

    with col_b:
        if st.button(_tr("🌐 Web Izlerini Ara", "🌐 Search Web Footprints"), use_container_width=True):
            with st.spinner(_tr("Web taraniyor...", "Searching the web...")):
                try:
                    clean_target = str(target or "").strip()
                    if not clean_target:
                        st.warning(_tr("Lutfen once bir hedef girin.", "Please enter a target first."))
                        raise ValueError("empty target")

                    dork_query = f'"{clean_target}" OR inurl:{clean_target}' if " " not in clean_target else f'"{clean_target}"'
                    with DDGS() as ddgs:
                        results = list(ddgs.text(dork_query, max_results=8))
                    if results:
                        st.success(_tr(f"✅ {len(results)} sonuc bulundu!", f"✅ {len(results)} results found!"))
                        for idx, result in enumerate(results, 1):
                            st.write(f"{idx}. **{result.get('title', 'N/A')}**")
                            st.caption(result.get("href", "N/A"))
                        st.session_state.report_results["Web Search"] = results
                    else:
                        st.info(_tr("Sonuc bulunamadi.", "No results found."))
                except Exception as exc:
                    if str(exc) != "empty target":
                        st.error(_tr(f"Hata: {str(exc)}", f"Error: {str(exc)}"))

    with col_c:
        if st.button(_tr("📊 Kisi Ozeti", "📊 Person Summary"), use_container_width=True):
            try:
                summary_md = _build_person_summary(target)
                st.markdown(summary_md)
                st.session_state.report_results["Person Summary"] = summary_md
            except Exception as exc:
                st.error(_tr(f"Kisi ozeti olusturulamadi: {str(exc)}", f"Could not generate person summary: {str(exc)}"))

# ===== MODUL 2: EMAIL HARVESTING =====
elif menu_key == "email":
    st.header(_tr("📧 E-posta Toplama ve Validasyon", "📧 Email Harvesting and Validation"))
    st.markdown(_tr("Hedef domain ile iliskili tum e-posta adreslerini kesfet.", "Discover all email addresses related to the target domain."))

    domain = st.text_input(_tr("Hedef Domain", "Target Domain"), placeholder="example.com")

    col_x, col_y = st.columns(2)
    with col_x:
        if st.button(_tr("🔎 E-posta Ara", "🔎 Find Emails"), use_container_width=True):
            with st.spinner(_tr("E-postalar toplaniyor (async)...", "Collecting emails (async)...")):
                try:
                    emails, elapsed = _time_scan("email_harvesting", osint.email_harvesting, domain)
                    st.caption(f"Completed in {elapsed:.2f} seconds")
                    if emails:
                        st.session_state.stats["emails"] += len(emails)
                        st.success(_tr(f"✅ {len(emails)} e-posta bulundu!", f"✅ {len(emails)} emails found!"))
                        for email in emails:
                            st.write(f"📧 `{email}`")
                        st.session_state.report_results["Emails Found"] = emails

                        entities, relationships = _build_email_entities(domain, emails)
                        _persist_scan(
                            module_name="email_harvesting",
                            target_value=domain,
                            target_type="domain",
                            result_payload=emails,
                            entities=entities,
                            relationships=relationships,
                        )
                    else:
                        st.warning(_tr("❌ E-posta bulunamadi.", "❌ No emails found."))
                except Exception as exc:
                    st.error(_tr(f"E-posta toplama hatasi: {str(exc)}", f"Email harvesting error: {str(exc)}"))

    with col_y:
        if st.button(_tr("🔍 WHOIS E-postalari", "🔍 WHOIS Emails"), use_container_width=True):
            with st.spinner(_tr("WHOIS sorgulaniyor...", "Querying WHOIS...")):
                try:
                    whois_data = osint.whois_lookup(domain)
                    if whois_data.get("Admin Email"):
                        st.success(_tr("✅ WHOIS verisi bulundu!", "✅ WHOIS data found!"))
                        st.json(whois_data)
                        st.session_state.report_results["WHOIS Data"] = whois_data
                    else:
                        st.warning(_tr("WHOIS kaydi bulunamadi.", "WHOIS record not found."))
                except Exception as exc:
                    st.error(_tr(f"WHOIS hatasi: {str(exc)}", f"WHOIS error: {str(exc)}"))

# ===== MODUL 3: DOMAIN INTELLIGENCE =====
elif menu_key == "domain":
    st.header(_tr("🌐 Domain Istihbarati ve Altyapi Analizi", "🌐 Domain Intelligence and Infrastructure Analysis"))
    st.markdown(_tr("Domain, DNS, WHOIS ve altyapi bilgilerini eksiksiz analiz et.", "Analyze domain, DNS, WHOIS, and infrastructure details end-to-end."))

    dom = st.text_input(_tr("Hedef Domain", "Target Domain"), placeholder="example.com")
    tabs = st.tabs([_tr("WHOIS", "WHOIS"), _tr("DNS Kayitlari", "DNS Records"), _tr("Alt Domainler", "Subdomains"), _tr("ASN Bilgisi", "ASN Info")])

    with tabs[0]:
        if st.button(_tr("📋 WHOIS Sorgusu", "📋 WHOIS Query")):
            with st.spinner(_tr("WHOIS verileri aliniyor...", "Fetching WHOIS data...")):
                try:
                    whois_data = osint.whois_lookup(dom)
                    st.session_state.stats["domains"] += 1
                    st.json(whois_data)
                    st.session_state.report_results["WHOIS Analysis"] = whois_data
                except Exception as exc:
                    st.error(_tr(f"WHOIS hatasi: {str(exc)}", f"WHOIS error: {str(exc)}"))

    with tabs[1]:
        if st.button(_tr("📡 DNS Kayitlarini Goster", "📡 Show DNS Records")):
            with st.spinner(_tr("DNS kayitlari aliniyor...", "Fetching DNS records...")):
                try:
                    dns_data = osint.dns_records(dom)
                    if dns_data:
                        st.success(_tr(f"✅ {len(dns_data)} DNS kaydi bulundu!", f"✅ {len(dns_data)} DNS records found!"))
                        st.json(dns_data)
                        st.session_state.report_results["DNS Records"] = dns_data
                    else:
                        st.warning(_tr("DNS kayitlari alinamadi.", "Could not fetch DNS records."))
                except Exception as exc:
                    st.error(_tr(f"DNS hatasi: {str(exc)}", f"DNS error: {str(exc)}"))

    with tabs[2]:
        if st.button(_tr("🔗 Alt-domainleri Tarama", "🔗 Scan Subdomains")):
            with st.spinner(_tr("Alt-domainler taraniyor...", "Scanning subdomains...")):
                try:
                    subs = osint.subdomain_enum(dom)
                    if subs:
                        st.session_state.stats["subdomains"] += len(subs)
                        st.success(_tr(f"✅ {len(subs)} alt-domain bulundu!", f"✅ {len(subs)} subdomains found!"))
                        st.dataframe(pd.DataFrame(subs), use_container_width=True)
                        st.session_state.report_results["Subdomains"] = subs

                        entities, relationships = _build_subdomain_entities(dom, subs)
                        _persist_scan(
                            module_name="subdomain_enum",
                            target_value=dom,
                            target_type="domain",
                            result_payload=subs,
                            entities=entities,
                            relationships=relationships,
                        )
                    else:
                        st.warning(_tr("Alt-domain bulunamadi.", "No subdomains found."))
                except Exception as exc:
                    st.error(_tr(f"Subdomain hatasi: {str(exc)}", f"Subdomain error: {str(exc)}"))

    with tabs[3]:
        if st.button(_tr("🏢 ASN Bilgisi", "🏢 ASN Information")):
            with st.spinner(_tr("ASN sorgulaniyor...", "Querying ASN...")):
                try:
                    asn = osint.asn_lookup(dom)
                    st.json(asn)
                    st.session_state.report_results["ASN Lookup"] = asn

                    entities, relationships = _build_asn_entities(dom, asn)
                    _persist_scan(
                        module_name="asn_lookup",
                        target_value=dom,
                        target_type="domain",
                        result_payload=asn,
                        entities=entities,
                        relationships=relationships,
                    )
                except Exception as exc:
                    st.error(_tr(f"ASN hatasi: {str(exc)}", f"ASN error: {str(exc)}"))

# ===== MODUL 4: BREACH DETECTION =====
elif menu_key == "breach":
    st.header(_tr("⚠️ Sizinti ve Dark Web Kontrolu", "⚠️ Breach and Dark Web Check"))
    st.markdown(_tr("Hedefin veri ihlali veya sizintisinda olup olmadigini kontrol et.", "Check whether the target appears in breaches or leaks."))

    query = st.text_input(_tr("E-posta veya Domain", "Email or Domain"), placeholder="target@example.com")

    if st.button(_tr("🔍 Sizinti Taramasi", "🔍 Breach Scan"), use_container_width=True):
        with st.spinner(_tr("Dark Web ve sizinti kaynaklari taraniyor (async)...", "Scanning dark web and leak sources (async)...")):
            try:
                breaches, elapsed = _time_scan("breach_check", osint.breach_check, query)
                st.caption(f"Completed in {elapsed:.2f} seconds")
                if breaches:
                    st.session_state.stats["breaches"] += len(breaches)
                    st.error(_tr(f"🚨 KRITIK: {len(breaches)} adet olasi sizinti bulundu!", f"🚨 CRITICAL: {len(breaches)} potential leak entries found!"))
                    st.dataframe(pd.DataFrame(breaches), use_container_width=True)
                    st.session_state.report_results["Breach Analysis"] = breaches

                    entities, relationships = _build_breach_entities(query, breaches)
                    _persist_scan(
                        module_name="breach_check",
                        target_value=query,
                        target_type="query",
                        result_payload=breaches,
                        entities=entities,
                        relationships=relationships,
                    )
                else:
                    st.success(_tr("✅ Temiz: Sizinti izine rastlanmadi.", "✅ Clean: No leak evidence found."))
            except Exception as exc:
                st.error(_tr(f"Sizinti taramasi hatasi: {str(exc)}", f"Breach scan error: {str(exc)}"))

# ===== MODUL 5: INFRASTRUCTURE RECONNAISSANCE =====
elif menu_key == "infra":
    st.header(_tr("🛡️ Altyapi Kesfi ve Ters DNS", "🛡️ Infrastructure Recon and Reverse DNS"))
    st.markdown(_tr("IP adresinin sahibi, reverse DNS ve lokasyon bilgisi.", "Inspect owner, reverse DNS, and location data of an IP/domain."))

    ip_or_domain = st.text_input(_tr("IP Adresi veya Domain", "IP Address or Domain"), placeholder="8.8.8.8 or example.com")
    tabs = st.tabs([_tr("Ters DNS", "Reverse DNS"), _tr("Geo-IP", "Geo-IP"), _tr("Web Arsivi", "Web Archive")])

    with tabs[0]:
        if st.button(_tr("🔄 Reverse DNS Sorgusu", "🔄 Reverse DNS Query")):
            with st.spinner(_tr("Reverse DNS sorgulaniyor...", "Querying reverse DNS...")):
                try:
                    try:
                        ip = socket.gethostbyname(ip_or_domain)
                    except Exception:
                        ip = ip_or_domain

                    rev_dns = osint.reverse_dns(ip)
                    st.json(rev_dns)
                    st.session_state.report_results["Reverse DNS"] = rev_dns
                except Exception as exc:
                    st.error(_tr(f"Reverse DNS hatasi: {str(exc)}", f"Reverse DNS error: {str(exc)}"))

    with tabs[1]:
        if st.button(_tr("📍 Geo-IP Haritasi", "📍 Geo-IP Map")):
            with st.spinner(_tr("Konum bilgisi aliniyor...", "Fetching location data...")):
                try:
                    geo = osint.geo_ip(ip_or_domain)
                    if geo and "lat" in geo:
                        st.success(_tr("✅ Konum bulundu!", "✅ Location found!"))
                        st.map(pd.DataFrame({"lat": [geo["lat"]], "lon": [geo["lon"]]}))
                        st.json(geo)
                        st.session_state.report_results["Geo-Location"] = geo
                    else:
                        st.error(_tr("❌ Konum bilgisi alinamadi.", "❌ Could not retrieve location."))
                except Exception as exc:
                    st.error(_tr(f"Geo-IP hatasi: {str(exc)}", f"Geo-IP error: {str(exc)}"))

    with tabs[2]:
        if st.button(_tr("📜 Wayback Machine Arsivi", "📜 Wayback Archive")):
            with st.spinner(_tr("Web Archive sorgulaniyor...", "Querying web archive...")):
                try:
                    archive = osint.web_archive(ip_or_domain)
                    st.json(archive)
                    st.session_state.report_results["Web Archive"] = archive
                except Exception as exc:
                    st.error(_tr(f"Archive hatasi: {str(exc)}", f"Archive error: {str(exc)}"))

# ===== MODUL 6: SSL CERTIFICATES =====
elif menu_key == "ssl":
    st.header(_tr("📜 SSL Sertifikasi Analizi", "📜 SSL Certificate Analysis"))
    st.markdown(_tr("Domain'in SSL sertifikalari ve tarihcesini goruntule.", "Inspect SSL certificates and certificate history for the domain."))

    cert_domain = st.text_input(_tr("Hedef Domain", "Target Domain"), placeholder="*.example.com or example.com")

    if st.button(_tr("🔎 SSL Sertifikalarini Ara", "🔎 Search SSL Certificates"), use_container_width=True):
        with st.spinner(_tr("SSL sertifikalari araniyor...", "Searching SSL certificates...")):
            try:
                certs = osint.ssl_search(cert_domain)
                if certs:
                    st.session_state.stats["certificates"] += len(certs)
                    st.success(_tr(f"✅ {len(certs)} sertifika bulundu!", f"✅ {len(certs)} certificates found!"))
                    st.dataframe(pd.DataFrame(certs), use_container_width=True)
                    st.session_state.report_results["SSL Certificates"] = certs
                else:
                    st.warning(_tr("❌ Sertifika bulunamadi.", "❌ No certificates found."))
            except Exception as exc:
                st.error(_tr(f"SSL hatasi: {str(exc)}", f"SSL error: {str(exc)}"))

# ===== MODUL 7: METADATA ANALYSIS =====
elif menu_key == "metadata":
    st.header(_tr("🖼️ Dosya Meta Veri Analizi", "🖼️ File Metadata Analysis"))
    st.markdown(_tr("Resim veya PDF dosyalarindan detayli ve gizli bilgi cikart.", "Extract detailed and hidden information from image/PDF files."))

    uploaded_file = st.file_uploader(_tr("Resim veya PDF Yukle", "Upload Image or PDF"), type=["jpg", "jpeg", "png", "gif", "bmp", "tiff", "pdf"])
    if uploaded_file:
        with st.spinner(_tr("Meta veriler analiz ediliyor...", "Analyzing metadata...")):
            try:
                meta = osint.extract_metadata(uploaded_file)
                if meta:
                    st.success(_tr("✅ Dosya analiz tamamlandi!", "✅ File analysis completed!"))
                    tabs = st.tabs([_tr("📊 Tum Veriler", "📊 All Data"), _tr("📁 Dosya Bilgisi", "📁 File Info"), _tr("📸 EXIF/PDF Meta", "📸 EXIF/PDF Meta"), _tr("🎨 Ozellikler", "🎨 Properties")])

                    with tabs[0]:
                        st.json(meta)

                    with tabs[1]:
                        if "📁 FILE INFORMATION" in meta:
                            st.subheader(_tr("📁 Dosya Bilgisi", "📁 File Information"))
                            file_info = meta["📁 FILE INFORMATION"]
                            col1, col2, col3 = st.columns(3)
                            col1.metric(_tr("Dosya Adi", "File Name"), file_info.get("File Name", "N/A"))
                            col2.metric(_tr("Boyut", "Size"), file_info.get("File Size", "N/A"))
                            col3.metric(_tr("Tip", "Type"), file_info.get("File Type", "N/A"))

                    with tabs[2]:
                        if "📸 EXIF DATA" in meta:
                            st.subheader(_tr("📸 EXIF Verileri", "📸 EXIF Data"))
                            for key, value in meta["📸 EXIF DATA"].items():
                                st.write(f"**{key}:** `{value}`")
                        elif "📄 PDF METADATA" in meta:
                            st.subheader(_tr("📄 PDF Metadata", "📄 PDF Metadata"))
                            for key, value in meta["📄 PDF METADATA"].items():
                                st.write(f"**{key}:** `{value}`")

                    with tabs[3]:
                        if "🎨 IMAGE PROPERTIES" in meta:
                            st.subheader(_tr("🎨 Resim Ozellikleri", "🎨 Image Properties"))
                            for key, value in meta["🎨 IMAGE PROPERTIES"].items():
                                st.write(f"**{key}:** `{value}`")
                        elif "📷 IMAGE INFORMATION" in meta:
                            st.subheader(_tr("📷 Resim Bilgisi", "📷 Image Information"))
                            img_info = meta["📷 IMAGE INFORMATION"]
                            col1, col2, col3, col4 = st.columns(4)
                            col1.metric("Format", img_info.get("Format", "N/A"))
                            col2.metric(_tr("Boyut", "Size"), img_info.get("Size", "N/A"))
                            col3.metric("DPI", str(img_info.get("DPI", "N/A")))
                            col4.metric("Mode", img_info.get("Mode", "N/A"))

                    st.session_state.report_results["Metadata Analysis"] = meta
                else:
                    st.warning(_tr("⚠️ Dosya okunamadi veya metadata cikarilamadi.", "⚠️ File could not be read or metadata could not be extracted."))
            except Exception as exc:
                st.error(_tr(f"Metadata hatasi: {str(exc)}", f"Metadata error: {str(exc)}"))

# ===== MODUL 8: GEO-INTELLIGENCE =====
elif menu_key == "geo":
    st.header(_tr("📍 Cografi Konum Istihbarati", "📍 Geo-Intelligence"))
    st.markdown(_tr("IP veya domain'in cografi konumunu harita uzerinde goster.", "Display IP/domain geolocation on a map."))

    geo_target = st.text_input(_tr("IP veya Domain", "IP or Domain"), placeholder="8.8.8.8 or google.com")

    if st.button(_tr("🗺️ Haritada Goster", "🗺️ Show on Map"), use_container_width=True):
        with st.spinner(_tr("Konum verisi yukleniyor...", "Loading geolocation data...")):
            try:
                geo = osint.geo_ip(geo_target)
                if geo and "lat" in geo:
                    st.success(_tr("✅ Konum bulundu!", "✅ Location found!"))
                    st.map(pd.DataFrame({"lat": [geo["lat"]], "lon": [geo["lon"]]}))
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric(_tr("Sehir", "City"), geo.get("city", "N/A"))
                        st.metric(_tr("Ulke", "Country"), geo.get("country", "N/A"))
                    with col2:
                        st.metric("ISP", geo.get("isp", "N/A"))
                        st.metric(_tr("Enlem", "Latitude"), geo.get("lat", "N/A"))
                    st.json(geo)
                    st.session_state.report_results["Geo-Location"] = geo
                else:
                    st.error(_tr("❌ Konum bilgisi alinamadi.", "❌ Could not retrieve location."))
            except Exception as exc:
                st.error(_tr(f"Geo istihbarat hatasi: {str(exc)}", f"Geo intelligence error: {str(exc)}"))

# ===== MODUL 9: PASSWORD ANALYSIS =====
elif menu_key == "password":
    st.header(_tr("🔐 Sifre Guvenlik Analizi", "🔐 Password Security Analysis"))
    st.markdown(_tr("Sifre gucunu analiz et ve iyilestirme onerileri al.", "Analyze password strength and get improvement guidance."))

    pwd_in = st.text_input(_tr("Analiz Edilecek Sifre", "Password to Analyze"), type="password")
    if pwd_in:
        strength = osint.check_password(pwd_in)
        strength_display = {
            "Çok Güçlü": _tr("Cok Guclu", "Very Strong"),
            "Orta": _tr("Orta", "Medium"),
            "Zayıf": _tr("Zayif", "Weak"),
        }.get(strength, str(strength))

        col1, col2 = st.columns(2)
        with col1:
            if strength == "Çok Güçlü":
                st.success(f"🟢 {strength_display}")
            elif strength == "Orta":
                st.warning(f"🟡 {strength_display}")
            else:
                st.error(f"🔴 {strength_display}")
        with col2:
            st.metric(_tr("Uzunluk", "Length"), len(pwd_in))

        st.session_state.report_results["Password Strength"] = {
            "Strength": strength,
            "Length": len(pwd_in),
        }

# ===== MODUL 10: BULK SCAN =====
elif menu_key == "bulk":
    st.header(_tr("📦 Coklu Hedef Taramasi", "📦 Bulk Target Scan"))
    st.markdown(_tr("TXT veya CSV dosyasindan birden fazla hedefi asenkron tarayin ve tum sonuclari kaydedin.", "Run asynchronous scans against multiple targets from TXT/CSV and store all results."))

    scan_mode = st.selectbox(
        _tr("Toplu tarama profili", "Bulk scan profile"),
        [
            "Domain -> Email Harvesting",
            "Email -> Breach Check",
            "IP/Domain -> Geo-IP",
            "Username -> Social Scan",
        ],
    )

    uploaded_file = st.file_uploader(_tr("TXT veya CSV yukleyin", "Upload TXT or CSV"), type=["txt", "csv"])
    target_column = st.text_input(_tr("CSV hedef kolonu (opsiyonel)", "CSV target column (optional)"), placeholder="target")

    scan_mapping = {
        "Domain -> Email Harvesting": ("email_harvesting", "domain"),
        "Email -> Breach Check": ("breach_check", "email"),
        "IP/Domain -> Geo-IP": ("geo_ip", "ip_or_domain"),
        "Username -> Social Scan": ("username_hunter", "username"),
    }
    scan_kind, target_type = scan_mapping[scan_mode]

    if st.button(_tr("🚀 Toplu Taramayi Baslat", "🚀 Start Bulk Scan"), use_container_width=True):
        targets = _load_bulk_targets(uploaded_file, target_column)
        if not targets:
            st.warning(_tr("Islenecek hedef bulunamadi. Lutfen gecerli bir TXT/CSV dosyasi yukleyin.", "No targets found. Please upload a valid TXT/CSV file."))
        else:
            with st.spinner(_tr(f"{len(targets)} hedef asenkron olarak taraniyor...", f"Scanning {len(targets)} targets asynchronously...")):
                try:
                    bulk_results, elapsed = _time_scan(
                        f"bulk_{scan_kind}",
                        osint.bulk_scan_targets,
                        scan_kind,
                        targets,
                    )
                    st.caption(_tr(f"Toplu tarama {elapsed:.2f} saniyede tamamlandi", f"Bulk scan completed in {elapsed:.2f} seconds"))

                    if not bulk_results:
                        st.warning(_tr("Toplu taramada sonuc donmedi.", "Bulk scan returned no results."))
                    else:
                        success_count = 0
                        error_count = 0
                        summary_rows = []

                        for item in bulk_results:
                            target = item.get("target", "N/A")
                            status = item.get("status", "error")
                            result_payload = item.get("result")

                            if status == "success":
                                success_count += 1
                                entities, relationships = _build_entities_for_scan(scan_kind, target, result_payload)
                            else:
                                error_count += 1
                                entities, relationships = [], []

                            _persist_scan(
                                module_name=scan_kind,
                                target_value=target,
                                target_type=target_type,
                                result_payload={
                                    "status": status,
                                    "result": result_payload,
                                    "error": item.get("error"),
                                },
                                entities=entities,
                                relationships=relationships,
                                status=status,
                            )

                            summary_rows.append(
                                {
                                    "target": target,
                                    "status": status,
                                    "result_size": len(result_payload) if isinstance(result_payload, list) else 1,
                                    "error": item.get("error", ""),
                                }
                            )

                        st.success(_tr(f"Toplu tarama tamamlandi. Basarili: {success_count}, Hatali: {error_count}", f"Bulk scan completed. Success: {success_count}, Error: {error_count}"))
                        st.dataframe(pd.DataFrame(summary_rows), use_container_width=True)
                        st.session_state.report_results[f"Bulk {scan_kind}"] = summary_rows
                except Exception as exc:
                    st.error(_tr(f"Toplu tarama hatasi: {str(exc)}", f"Bulk scan error: {str(exc)}"))

# ===== MODUL 11: RELATIONSHIP GRAPH & HISTORY =====
elif menu_key == "graph":
    st.header(_tr("🕸️ Iliski Grafigi ve Tarama Gecmisi", "🕸️ Relationship Graph and Scan History"))
    st.markdown(_tr("Kaydedilmis taramalari inceleyin ve varlik iliskilerini interaktif grafikte gorun.", "Review saved scans and inspect entity relationships in an interactive graph."))

    try:
        history = db.get_recent_scans(limit=100)
    except Exception as exc:
        history = []
        st.error(_tr(f"Gecmis yuklenemedi: {str(exc)}", f"Could not load history: {str(exc)}"))

    if history:
        st.subheader(_tr("📚 Son Taramalar", "📚 Recent Scans"))
        history_df = pd.DataFrame(history)

        filter_col1, filter_col2 = st.columns(2)
        with filter_col1:
            module_filter = st.multiselect(
                _tr("Modulleri filtrele", "Filter modules"),
                options=sorted(history_df["module"].dropna().unique().tolist()),
                default=[],
            )
        with filter_col2:
            target_filter = st.text_input(_tr("Hedef icerigi filtrele", "Filter target contains"), placeholder="example.com")

        filtered_df = history_df.copy()
        if module_filter:
            filtered_df = filtered_df[filtered_df["module"].isin(module_filter)]
        if target_filter:
            filtered_df = filtered_df[
                filtered_df["target"].astype(str).str.contains(target_filter, case=False, na=False)
            ]

        st.dataframe(filtered_df, use_container_width=True)

        try:
            csv_bytes = filtered_df.to_csv(index=False).encode("utf-8")
            st.download_button(
                _tr("Gecmisi CSV olarak indir", "Download History CSV"),
                csv_bytes,
                "scan_history.csv",
                "text/csv",
                use_container_width=True,
            )
        except Exception as exc:
            st.warning(_tr(f"CSV disa aktarma hatasi: {str(exc)}", f"CSV export failed: {str(exc)}"))

        options = [_tr("Son Birlesik", "Latest Combined")] + [str(item["scan_id"]) for item in filtered_df.to_dict("records")]
        selected_scan = st.selectbox(_tr("Graf kaynagi", "Graph source"), options=options)
        st.session_state.max_graph_nodes = st.slider(
            _tr("Render edilecek maksimum dugum", "Max Nodes to Render"),
            min_value=20,
            max_value=1000,
            value=st.session_state.max_graph_nodes,
            step=10,
        )

        preview_scan_id = None if selected_scan == _tr("Son Birlesik", "Latest Combined") else int(selected_scan)
        try:
            preview_graph_data = db.get_graph_data(scan_id=preview_scan_id)
            available_groups = sorted({node.get("group", "Unknown") for node in preview_graph_data.get("nodes", [])})
        except Exception:
            available_groups = []

        if available_groups:
            selected_groups = st.multiselect(
                _tr("Gorunen dugum tipleri", "Visible node types"),
                options=available_groups,
                default=available_groups,
            )
        else:
            selected_groups = []

        color_map = _graph_color_map()
        if selected_groups:
            legend = [f"{group}: {color_map.get(group, '#64748b')}" for group in selected_groups]
            st.caption(_tr("Graf aciklamasi", "Graph legend"))
            st.caption(" | ".join(legend))

        col_g1, col_g2 = st.columns(2)
        with col_g1:
            if st.button(_tr("🧠 Iliski Grafigini Uret", "🧠 Generate Relationship Graph"), use_container_width=True):
                scan_id = None if selected_scan == _tr("Son Birlesik", "Latest Combined") else int(selected_scan)
                try:
                    graph_data = db.get_graph_data(scan_id=scan_id)
                    _render_graph(
                        graph_data,
                        allowed_groups=selected_groups,
                        max_nodes=st.session_state.max_graph_nodes,
                    )
                except Exception as exc:
                    st.error(_tr(f"Graf verisi alinamadi: {str(exc)}", f"Could not read graph data: {str(exc)}"))

        with col_g2:
            if st.button(_tr("🧾 Secili Taramayi Goster", "🧾 Show Selected Scan"), use_container_width=True):
                if selected_scan == _tr("Son Birlesik", "Latest Combined"):
                    st.info(_tr("Bu secenek birden fazla kaydin grafik kombinasyonunu gosterir.", "This option shows a combined graph from multiple records."))
                else:
                    try:
                        payload = db.get_scan_payload(int(selected_scan))
                        if payload:
                            st.json(payload)
                        else:
                            st.warning(_tr("Secili kayitta gosterilecek veri yok.", "No payload available for selected scan."))
                    except Exception as exc:
                        st.error(_tr(f"Tarama verisi okunamadi: {str(exc)}", f"Could not read scan payload: {str(exc)}"))
    else:
        st.warning(_tr("Gecmis kaydi bulunamadi. Once async tarama modullerinden birini calistirin.", "No history found. Run one of the async scan modules first."))

# ===== MODUL 12: SETTINGS & API KEYS =====
elif menu_key == "settings":
    st.header(_tr("⚙️ Ayarlar ve API Anahtarlari", "⚙️ Settings & API Keys"))
    st.markdown(_tr("Shodan, Censys ve VirusTotal API anahtarlarini .env dosyasina kalici kaydedin.", "Persist Shodan, Censys and VirusTotal API keys into the .env file."))

    current_keys = get_api_key_values()

    with st.form("api_key_settings_form"):
        shodan_key = st.text_input("Shodan API Key", value=current_keys.get("SHODAN_API_KEY", ""), type="password")
        censys_id = st.text_input("Censys API ID", value=current_keys.get("CENSYS_API_ID", ""), type="password")
        censys_secret = st.text_input("Censys API Secret", value=current_keys.get("CENSYS_API_SECRET", ""), type="password")
        virustotal_key = st.text_input("VirusTotal API Key", value=current_keys.get("VIRUSTOTAL_API_KEY", ""), type="password")
        hibp_key = st.text_input("HIBP API Key", value=current_keys.get("HIBP_API_KEY", ""), type="password")

        submitted = st.form_submit_button(_tr("API Anahtarlarini Kaydet", "Save API Keys"), use_container_width=True)
        if submitted:
            api_payload = {
                "SHODAN_API_KEY": shodan_key,
                "CENSYS_API_ID": censys_id,
                "CENSYS_API_SECRET": censys_secret,
                "VIRUSTOTAL_API_KEY": virustotal_key,
                "HIBP_API_KEY": hibp_key,
            }
            if save_api_key_values(api_payload):
                st.success(_tr("API anahtarlari .env dosyasina kaydedildi ve ortama yuklendi.", "API key values saved to .env and loaded into environment."))
            else:
                st.error(_tr("API anahtarlari kaydedilemedi.", "API key values could not be saved."))

    configured = sum(1 for value in current_keys.values() if str(value).strip())
    st.info(_tr(f"Yapilandirilmis gizli anahtarlar: {configured}/{len(current_keys)}", f"Configured secrets: {configured}/{len(current_keys)}"))

    st.subheader(_tr("WMN Kapsam Ayarlari", "WMN Coverage Settings"))
    wmn_enabled = st.toggle(_tr("WMN kontrollerini etkinlestir", "Enable WMN checks"), value=st.session_state.wmn_enabled)
    wmn_site_limit = st.slider(_tr("WMN site kapsami", "WMN site coverage"), min_value=0, max_value=500, value=st.session_state.wmn_site_limit, step=10)
    if st.button(_tr("WMN Ayarlarini Kaydet", "Save WMN Settings"), use_container_width=True):
        try:
            st.session_state.wmn_enabled = bool(wmn_enabled)
            st.session_state.wmn_site_limit = int(wmn_site_limit)
            osint.set_wmn_config(
                enabled=st.session_state.wmn_enabled,
                site_limit=st.session_state.wmn_site_limit,
            )
            st.success(_tr("WMN ayarlari guncellendi.", "WMN settings updated."))
        except Exception as exc:
            st.error(_tr(f"WMN ayari guncellenemedi: {str(exc)}", f"WMN settings could not be updated: {str(exc)}"))

# ===== MODUL 13: GENERATE REPORT =====
elif menu_key == "report":
    st.header(_tr("📄 Profesyonel OSINT Raporu Olustur", "📄 Generate Professional OSINT Report"))
    st.markdown(_tr("Tum topladiginiz verileri profesyonel PDF raporuna donustur.", "Convert all collected findings into a professional PDF report."))

    if not st.session_state.report_results:
        st.warning(_tr("⚠️ Veri yok! Once diger modullerde tarama yapin.", "⚠️ No data yet! Run scans in other modules first."))
    else:
        st.info(_tr(f"📊 {len(st.session_state.report_results)} bolum verisi var.", f"📊 {len(st.session_state.report_results)} sections are ready."))

        if st.button(_tr("📥 PDF Raporunu Olustur ve Indir", "📥 Build and Download PDF Report"), use_container_width=True):
            with st.spinner(_tr("Rapor olusturuluyor...", "Generating report...")):
                try:
                    pdf = AmateurOSINTReport()
                    pdf.add_page()
                    report_title = _tr("AmateurOSINT Profesyonel Istihbarat Raporu", "AmateurOSINT Professional Intelligence Report")
                    pdf.set_title(report_title)

                    created_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
                    pdf.chapter_title(_tr("Rapor Ozeti", "Report Summary"))
                    pdf.chapter_body(
                        _tr(
                            f"Uretim Zamani: {created_at}\nDil: Turkce\nBolum Sayisi: {len(st.session_state.report_results)}",
                            f"Generated At: {created_at}\nLanguage: English\nSection Count: {len(st.session_state.report_results)}",
                        )
                    )

                    for key, value in st.session_state.report_results.items():
                        pdf.chapter_title(_localize_report_section_title(key))
                        pdf.chapter_body(_report_value_to_text(value))

                    raw_pdf = pdf.output(dest="S")
                    if isinstance(raw_pdf, str):
                        pdf_bytes = raw_pdf.encode("latin-1", "replace")
                    elif isinstance(raw_pdf, (bytes, bytearray)):
                        pdf_bytes = bytes(raw_pdf)
                    else:
                        pdf_bytes = bytes(str(raw_pdf), "latin-1", errors="replace")

                    if len(pdf_bytes) < 200:
                        raise ValueError("PDF content is unexpectedly small")

                    try:
                        localized_snapshot = _build_localized_report_snapshot(st.session_state.report_results)
                        db.save_report_snapshot(
                            title=report_title,
                            content=localized_snapshot,
                        )
                    except Exception as exc:
                        st.warning(_tr(f"Rapor gecmise kaydedilemedi: {str(exc)}", f"Could not save report snapshot: {str(exc)}"))

                    st.success(_tr("✅ Rapor hazir!", "✅ Report is ready!"))
                    st.download_button(
                        _tr("📥 PDF Raporunu Indir", "📥 Download PDF Report"),
                        pdf_bytes,
                        "AmateurOSINT_Report.pdf",
                        "application/pdf",
                        use_container_width=True,
                    )
                except Exception as exc:
                    st.error(_tr(f"❌ Rapor olusturulurken hata: {str(exc)}", f"❌ Error generating report: {str(exc)}"))

        if st.button(_tr("🗑️ Verileri Temizle", "🗑️ Clear Report Data"), use_container_width=True):
            st.session_state.report_results.clear()
            st.rerun()

# --- FOOTER ---
st.divider()
st.markdown(
    _tr(
        "**AmateurOSINT v2.0 MVP** | Etik OSINT Arastirmasi Platformu | *Yalnizca yasal amaclar icin kullanin* | **github.com/macallantheroot/AmateurOSINT**",
        "**AmateurOSINT v2.0 MVP** | Ethical OSINT Research Platform | *Use for legal purposes only* | **github.com/macallantheroot/AmateurOSINT**",
    )
)
