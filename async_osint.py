import asyncio
import json
import os
import random
import re
import socket
import string
import threading
import time
from typing import Any, Dict, List
from urllib.parse import quote, urlparse

import aiohttp
import dns.resolver
import requests
import whois
from bs4 import BeautifulSoup
from PIL import Image
from PIL.ExifTags import TAGS
from PyPDF2 import PdfReader
from ddgs import DDGS


class AmateurOSINT:
    def __init__(self):
        self.headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_0) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
        ]
        self.email_regex = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        self.domain_regex = r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}"
        self.request_timeout = aiohttp.ClientTimeout(total=7)
        self.concurrent_limit = 12
        self.wmn_data_url = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
        self.wmn_enabled = True
        self.wmn_site_limit = 180
        self._wmn_sites_cache: List[Dict[str, Any]] = []
        self._wmn_cache_ts = 0.0

    def set_runtime_config(self, timeout_seconds: int, concurrent_limit: int) -> None:
        try:
            safe_timeout = max(2, int(timeout_seconds))
            safe_limit = max(1, int(concurrent_limit))
            self.request_timeout = aiohttp.ClientTimeout(total=safe_timeout)
            self.concurrent_limit = safe_limit
        except Exception:
            # Keep previous values if invalid input is provided.
            pass

    def set_wmn_config(self, enabled: bool, site_limit: int) -> None:
        try:
            self.wmn_enabled = bool(enabled)
            self.wmn_site_limit = max(0, int(site_limit))
        except Exception:
            pass

    async def _dispatch_scan_kind(self, scan_kind: str, target: str):
        if scan_kind == "username_hunter":
            return await self.username_hunter_async(target)
        if scan_kind == "email_harvesting":
            return await self.email_harvesting_async(target)
        if scan_kind == "breach_check":
            return await self.breach_check_async(target)
        if scan_kind == "whois_lookup":
            return await asyncio.to_thread(self.whois_lookup, target)
        if scan_kind == "geo_ip":
            return await asyncio.to_thread(self.geo_ip, target)
        if scan_kind == "asn_lookup":
            return await asyncio.to_thread(self.asn_lookup, target)
        raise ValueError(f"Unsupported scan kind: {scan_kind}")

    async def bulk_scan_targets_async(self, scan_kind: str, targets: List[str]) -> List[Dict[str, Any]]:
        clean_targets = [str(target).strip() for target in targets if str(target).strip()]
        if not clean_targets:
            return []

        sem = asyncio.Semaphore(self.concurrent_limit)

        async def worker(target: str) -> Dict[str, Any]:
            async with sem:
                try:
                    result = await self._dispatch_scan_kind(scan_kind=scan_kind, target=target)
                    return {
                        "target": target,
                        "scan_kind": scan_kind,
                        "status": "success",
                        "result": result,
                    }
                except Exception as exc:
                    return {
                        "target": target,
                        "scan_kind": scan_kind,
                        "status": "error",
                        "error": str(exc),
                        "result": None,
                    }

        tasks = [worker(target) for target in clean_targets]
        return await asyncio.gather(*tasks)

    def bulk_scan_targets(self, scan_kind: str, targets: List[str]) -> List[Dict[str, Any]]:
        try:
            return self._run_async(self.bulk_scan_targets_async(scan_kind=scan_kind, targets=targets))
        except Exception:
            return []

    def _run_async(self, coro):
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)

        result: Dict[str, Any] = {}
        error: Dict[str, Exception] = {}

        def runner():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result["value"] = loop.run_until_complete(coro)
            except Exception as exc:
                error["value"] = exc
            finally:
                loop.close()

        thread = threading.Thread(target=runner)
        thread.start()
        thread.join()

        if "value" in error:
            raise error["value"]
        return result.get("value")

    def _request_headers(self) -> Dict[str, str]:
        headers = dict(self.headers)
        headers["User-Agent"] = random.choice(self.user_agents)
        headers["Accept-Language"] = "en-US,en;q=0.9"
        return headers

    async def _safe_get_page(self, session: aiohttp.ClientSession, url: str, sem: asyncio.Semaphore) -> Dict[str, Any]:
        async with sem:
            try:
                async with session.get(url, headers=self._request_headers(), timeout=self.request_timeout, allow_redirects=True) as response:
                    text = await response.text(errors="ignore")
                    return {
                        "status": response.status,
                        "text": text,
                        "final_url": str(response.url),
                    }
            except Exception:
                return {
                    "status": 0,
                    "text": "",
                    "final_url": url,
                }

    def _verify_username_profile(self, platform: str, username: str, page: Dict[str, Any]) -> bool:
        status = int(page.get("status", 0))
        html_text = str(page.get("text", ""))
        final_url = str(page.get("final_url", "")).lower()
        username_lc = username.lower()

        if status >= 400 or not html_text:
            return False

        soup = BeautifulSoup(html_text, "html.parser")
        title = soup.title.get_text(" ", strip=True).lower() if soup.title else ""
        text_lc = soup.get_text(" ", strip=True).lower()

        meta_values = []
        for tag in soup.find_all("meta"):
            content = str(tag.get("content", "")).strip().lower()
            if content:
                meta_values.append(content)
        canonical_links = [
            str(tag.get("href", "")).strip().lower()
            for tag in soup.find_all("link", attrs={"rel": lambda rel: rel and "canonical" in str(rel).lower()})
            if str(tag.get("href", "")).strip()
        ]
        combined_meta = " ".join(meta_values + canonical_links)

        common_negative = [
            "page not found",
            "doesn't exist",
            "this account doesn",
            "sorry, this page isn't available",
            "not available",
            "error 404",
            "not found",
        ]
        if any(marker in text_lc or marker in title for marker in common_negative):
            return False

        if platform == "GitHub":
            if "/users/" in final_url:
                return False
            return username_lc in title or f"/{username_lc}" in final_url

        if platform == "Twitter (X)":
            twitter_negative = [
                "this account doesn",
                "account suspended",
                "account doesn",
                "log in to x",
            ]
            if any(marker in text_lc or marker in title for marker in twitter_negative):
                return False
            if "/i/flow/login" in final_url:
                return False
            return (
                f"@{username_lc}" in title
                or f"/{username_lc}" in final_url
                or f"@{username_lc}" in combined_meta
            )

        if platform == "Instagram":
            insta_negative = [
                "sorry, this page isn't available",
                "page isn\'t available",
                "login • instagram",
            ]
            if any(marker in text_lc or marker in title for marker in insta_negative):
                return False
            return (
                f"@{username_lc}" in title
                or f"/{username_lc}" in final_url
                or f"@{username_lc}" in combined_meta
                or f"username={username_lc}" in combined_meta
            )

        if platform == "TikTok":
            tiktok_negative = [
                "couldn't find this account",
                "couldn\'t find this account",
                "page not available",
                "this page is not available",
            ]
            if any(marker in text_lc or marker in title for marker in tiktok_negative):
                return False
            return (
                f"/@{username_lc}" in final_url
                or f"@{username_lc}" in title
                or f"/@{username_lc}" in combined_meta
            )

        if platform == "Reddit":
            if "nobody on reddit goes by that name" in text_lc:
                return False
            return f"u/{username_lc}" in title or f"/user/{username_lc}" in final_url

        return username_lc in title or f"/{username_lc}" in final_url

    async def _fetch_wmn_sites(self) -> List[Dict[str, Any]]:
        now = time.time()
        if self._wmn_sites_cache and (now - self._wmn_cache_ts) < 3600:
            return self._wmn_sites_cache

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.wmn_data_url, headers=self._request_headers(), timeout=self.request_timeout) as response:
                    if response.status != 200:
                        return self._wmn_sites_cache

                    payload_text = await response.text(errors="ignore")
                    payload = json.loads(payload_text)
                    sites = payload.get("sites", [])
                    normalized = []
                    for site in sites:
                        if not isinstance(site, dict):
                            continue
                        if site.get("valid") is False:
                            continue
                        uri_check = str(site.get("uri_check", "")).strip()
                        if not uri_check or "{account}" not in uri_check:
                            continue
                        normalized.append(site)

                    self._wmn_sites_cache = normalized
                    self._wmn_cache_ts = now
                    return normalized
        except Exception:
            return self._wmn_sites_cache

    def _wmn_account_found(self, site: Dict[str, Any], status: int, body_text: str, final_url: str, username: str) -> bool:
        body_lc = body_text.lower()
        final_url_lc = final_url.lower()
        username_lc = username.lower()

        e_code = site.get("e_code")
        m_code = site.get("m_code")
        e_string = str(site.get("e_string", "")).lower().strip()
        m_string = str(site.get("m_string", "")).lower().strip()

        if isinstance(m_code, int) and status == m_code:
            return False
        if m_string and m_string in body_lc:
            return False

        code_match = isinstance(e_code, int) and status == e_code
        if e_code is None:
            code_match = status > 0 and status < 400

        if e_string:
            if e_string not in body_lc:
                return False
            return code_match

        if code_match:
            return (
                f"/{username_lc}" in final_url_lc
                or f"@{username_lc}" in body_lc
                or username_lc in body_lc
            )

        return False

    async def _wmn_check_site(
        self,
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        site: Dict[str, Any],
        username: str,
    ) -> Dict[str, str] | None:
        uri_check = str(site.get("uri_check", "")).strip()
        if not uri_check:
            return None

        account_value = quote(username, safe="")
        url = uri_check.replace("{account}", account_value)
        headers = self._request_headers()
        site_headers = site.get("headers")
        if isinstance(site_headers, dict):
            headers.update({str(k): str(v) for k, v in site_headers.items()})

        post_body = str(site.get("post_body", "") or "")
        if post_body:
            post_body = post_body.replace("{account}", account_value)

        async with sem:
            try:
                if post_body:
                    async with session.post(
                        url,
                        data=post_body,
                        headers=headers,
                        timeout=self.request_timeout,
                        allow_redirects=True,
                    ) as response:
                        body_text = await response.text(errors="ignore")
                        final_url = str(response.url)
                        status = int(response.status)
                else:
                    async with session.get(
                        url,
                        headers=headers,
                        timeout=self.request_timeout,
                        allow_redirects=True,
                    ) as response:
                        body_text = await response.text(errors="ignore")
                        final_url = str(response.url)
                        status = int(response.status)
            except Exception:
                return None

        if not self._wmn_account_found(site=site, status=status, body_text=body_text, final_url=final_url, username=username):
            return None

        pretty_url = str(site.get("uri_pretty", "") or "").replace("{account}", username)
        resolved_url = pretty_url or final_url or url
        return {
            "Platform": str(site.get("name", "Unknown")),
            "URL": resolved_url,
            "Status": "FOUND (WMN)",
        }

    async def username_hunter_async(self, username: str) -> List[Dict[str, str]]:
        username = username.replace("@", "").strip()
        if not username:
            return []

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
            "Twitch": f"https://twitch.tv/{username}",
        }

        sem = asyncio.Semaphore(self.concurrent_limit)
        async with aiohttp.ClientSession() as session:
            checks = [
                self._safe_get_page(session=session, url=url, sem=sem)
                for url in platforms.values()
            ]
            pages = await asyncio.gather(*checks, return_exceptions=True)

        found: List[Dict[str, str]] = []
        for (platform, url), page in zip(platforms.items(), pages):
            if isinstance(page, Exception):
                continue
            if self._verify_username_profile(platform=platform, username=username, page=page):
                found.append({"Platform": platform, "URL": url, "Status": "FOUND"})

        wmn_sites = await self._fetch_wmn_sites() if self.wmn_enabled and self.wmn_site_limit > 0 else []
        if wmn_sites:
            limited_sites = wmn_sites[: self.wmn_site_limit]
            sem = asyncio.Semaphore(self.concurrent_limit)
            async with aiohttp.ClientSession() as session:
                tasks = [
                    self._wmn_check_site(session=session, sem=sem, site=site, username=username)
                    for site in limited_sites
                ]
                wmn_results = await asyncio.gather(*tasks, return_exceptions=True)

            for item in wmn_results:
                if isinstance(item, dict):
                    found.append(item)

        deduped: List[Dict[str, str]] = []
        seen = set()
        for hit in found:
            platform = str(hit.get("Platform", "")).strip().lower()
            url = str(hit.get("URL", "")).strip().lower()
            key = (platform, url)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(hit)
        return deduped

    def _ddg_text_search(self, query: str, max_results: int) -> List[Dict[str, Any]]:
        try:
            with DDGS() as ddgs:
                return list(ddgs.text(query, max_results=max_results))
        except Exception:
            return []

    async def _ddg_text_search_async(self, query: str, max_results: int) -> List[Dict[str, Any]]:
        return await asyncio.to_thread(self._ddg_text_search, query, max_results)

    async def email_harvesting_async(self, domain: str) -> List[str]:
        emails = set()
        if not domain:
            return []

        normalized_domain = domain.strip().lower()
        if normalized_domain.startswith("http://") or normalized_domain.startswith("https://"):
            normalized_domain = urlparse(normalized_domain).netloc

        async def scrape_page(url: str, session: aiohttp.ClientSession, sem: asyncio.Semaphore) -> None:
            page = await self._safe_get_page(session=session, url=url, sem=sem)
            html_text = str(page.get("text", ""))
            if not html_text:
                return

            soup = BeautifulSoup(html_text, "html.parser")
            text_blob = soup.get_text(" ", strip=True)
            emails.update(re.findall(self.email_regex, text_blob))
            emails.update(re.findall(self.email_regex, html_text))

            for anchor in soup.find_all("a", href=True):
                href = str(anchor.get("href", ""))
                if href.lower().startswith("mailto:"):
                    candidate = href.split("mailto:", 1)[-1].split("?")[0].strip()
                    if candidate:
                        emails.add(candidate)

        candidate_urls = [
            f"https://{normalized_domain}",
            f"https://{normalized_domain}/contact",
            f"http://{normalized_domain}",
            f"http://{normalized_domain}/contact",
        ]

        try:
            sem = asyncio.Semaphore(4)
            async with aiohttp.ClientSession() as session:
                tasks = [scrape_page(url=url, session=session, sem=sem) for url in candidate_urls]
                await asyncio.gather(*tasks, return_exceptions=True)
        except Exception:
            pass

        try:
            search_results = await self._ddg_text_search_async(
                f'site:{normalized_domain} "{normalized_domain}" (email OR contact OR "@{normalized_domain}")',
                max_results=10,
            )
            for result in search_results:
                body = str(result.get("body", ""))
                title = str(result.get("title", ""))
                href = str(result.get("href", ""))
                found_emails = re.findall(self.email_regex, body)
                emails.update(found_emails)
                emails.update(re.findall(self.email_regex, title))
                emails.update(re.findall(self.email_regex, href))
        except Exception:
            pass

        try:
            w = await asyncio.to_thread(whois.whois, normalized_domain)
            admin_email = getattr(w, "admin_email", None)
            tech_email = getattr(w, "tech_email", None)
            registrant_email = getattr(w, "registrant_email", None)

            if admin_email:
                if isinstance(admin_email, list):
                    emails.update(admin_email)
                else:
                    emails.add(str(admin_email))
            if tech_email:
                if isinstance(tech_email, list):
                    emails.update(tech_email)
                else:
                    emails.add(str(tech_email))
            if registrant_email:
                if isinstance(registrant_email, list):
                    emails.update(registrant_email)
                else:
                    emails.add(str(registrant_email))
        except Exception:
            pass

        return sorted(
            {
                email.lower()
                for email in emails
                if isinstance(email, str)
                and "@" in email
                and " " not in email
                and len(email) <= 254
            }
        )

    async def _hibp_lookup_async(self, account: str, api_key: str) -> List[Dict[str, str]]:
        endpoint = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(account, safe='')}?truncateResponse=false"
        headers = self._request_headers()
        headers["hibp-api-key"] = api_key
        headers["Accept"] = "application/json"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(endpoint, headers=headers, timeout=self.request_timeout) as response:
                    if response.status == 404:
                        return []
                    if response.status != 200:
                        return []

                    payload = await response.json()
                    findings = []
                    for item in payload[:15]:
                        findings.append(
                            {
                                "Source": "HIBP",
                                "URL": f"https://haveibeenpwned.com/PwnedWebsites#{item.get('Name', 'N/A')}",
                                "Context": (
                                    f"{item.get('Name', 'N/A')} | BreachDate={item.get('BreachDate', 'N/A')} | "
                                    f"PwnCount={item.get('PwnCount', 'N/A')}"
                                ),
                            }
                        )
                    return findings
        except Exception:
            return []

    async def breach_check_async(self, query: str) -> List[Dict[str, str]]:
        findings: List[Dict[str, str]] = []
        if not query:
            return findings

        hibp_key = os.getenv("HIBP_API_KEY", "").strip()
        if hibp_key and "@" in query:
            try:
                findings.extend(await self._hibp_lookup_async(account=query.strip(), api_key=hibp_key))
            except Exception:
                pass

        dorks = [
            f'site:pastebin.com "{query}"',
            f'site:github.com "{query}" (password OR api_key OR secret)',
            f'"{query}" ext:txt OR ext:csv OR ext:json password',
            f'"{query}" (breach OR leak OR exposed)',
        ]

        tasks = [self._ddg_text_search_async(dork, max_results=3) for dork in dorks]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                continue
            for item in result:
                findings.append(
                    {
                        "Source": "Potential Leak",
                        "URL": str(item.get("href", "N/A")),
                        "Context": str(item.get("body", ""))[:150],
                    }
                )

        deduped: List[Dict[str, str]] = []
        seen_urls = set()
        for entry in findings:
            key = entry.get("URL", "")
            if key in seen_urls:
                continue
            seen_urls.add(key)
            deduped.append(entry)
        return deduped

    def username_hunter(self, username: str) -> List[Dict[str, str]]:
        try:
            return self._run_async(self.username_hunter_async(username))
        except Exception:
            return []

    def email_harvesting(self, domain: str) -> List[str]:
        try:
            return self._run_async(self.email_harvesting_async(domain))
        except Exception:
            return []

    def breach_check(self, query: str) -> List[Dict[str, str]]:
        try:
            return self._run_async(self.breach_check_async(query))
        except Exception:
            return []

    def subdomain_enum(self, domain: str) -> List[Dict[str, str]]:
        subdomains = set()
        common_subs = [
            "www", "mail", "ftp", "api", "admin", "test", "dev", "staging",
            "app", "backup", "blog", "news", "shop", "cdn", "git", "auth",
            "vpn", "ssl", "portal", "forum", "support", "help", "status",
        ]

        for sub in common_subs:
            try:
                hostname = f"{sub}.{domain}"
                ip = socket.gethostbyname(hostname)
                subdomains.add(frozenset([("Subdomain", hostname), ("IP", ip)]))
            except Exception:
                pass

        try:
            results = self._ddg_text_search(f"site:{domain}", max_results=5)
            for item in results:
                urls = re.findall(r"https?://([^/]+)", str(item.get("body", "")))
                for url in urls:
                    if domain in url:
                        subdomains.add(frozenset([("Subdomain", url), ("IP", "N/A")]))
        except Exception:
            pass

        return [dict(entry) for entry in subdomains]

    def whois_lookup(self, domain: str) -> Dict[str, Any]:
        try:
            w = whois.whois(domain)
            return {
                "Domain": w.domain,
                "Registrar": getattr(w, "registrar", "N/A"),
                "Creation Date": str(getattr(w, "creation_date", "N/A")),
                "Expiration Date": str(getattr(w, "expiration_date", "N/A")),
                "Admin": getattr(w, "admin_name", "N/A"),
                "Admin Email": getattr(w, "admin_email", "N/A"),
                "Tech Contact": getattr(w, "tech_name", "N/A"),
                "Nameservers": getattr(w, "name_servers", "N/A"),
            }
        except Exception as exc:
            return {"Error": str(exc)}

    def dns_records(self, domain: str) -> Dict[str, List[str]]:
        records: Dict[str, List[str]] = {}
        record_types = ["A", "MX", "TXT", "NS", "CNAME", "SOA"]

        for rtype in record_types:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 5
                answer = resolver.resolve(domain, rtype)
                records[rtype] = [str(item) for item in answer]
            except Exception:
                pass

        return records

    def reverse_dns(self, ip: str) -> Dict[str, Any]:
        try:
            hostname = socket.gethostbyaddr(ip)
            return {"IP": ip, "Hostname": hostname[0], "Aliases": hostname[1]}
        except Exception:
            return {"IP": ip, "Hostname": "N/A", "Error": "Reverse DNS başarısız"}

    def geo_ip(self, target: str) -> Dict[str, Any]:
        try:
            ip = socket.gethostbyname(target)
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
            return response if response.get("status") == "success" else {}
        except Exception:
            return {}

    def web_archive(self, url: str) -> Dict[str, Any]:
        try:
            domain = urlparse(url).netloc if "://" in url else url
            response = requests.get(f"https://archive.org/wayback/available?url={domain}", timeout=5).json()
            snapshots = response.get("archived_snapshots", {})
            if "closest" in snapshots:
                closest = snapshots["closest"]
                return {
                    "URL": closest.get("url", "N/A"),
                    "Timestamp": closest.get("timestamp", "N/A"),
                    "Status": closest.get("status", "N/A"),
                }
            return {"Status": "No archives found"}
        except Exception:
            return {"Error": "Archive sorgusu başarısız"}

    def ssl_search(self, domain: str) -> List[Dict[str, str]]:
        try:
            response = requests.get(f"https://crt.sh/?q={domain}&output=json", timeout=10).json()
            certs = []
            for cert in response[:10]:
                certs.append(
                    {
                        "Common Name": cert.get("common_name", "N/A"),
                        "Issuer": cert.get("issuer_name", "N/A"),
                        "Issued": cert.get("entry_timestamp", "N/A"),
                    }
                )
            return certs
        except Exception:
            return []

    def asn_lookup(self, domain_or_ip: str) -> Dict[str, Any]:
        try:
            try:
                ip = socket.gethostbyname(domain_or_ip)
            except Exception:
                ip = domain_or_ip

            response = requests.get(f"http://ip-api.com/json/{ip}?fields=asn,isp,org,status", timeout=5).json()
            if response.get("status") == "success":
                return {
                    "IP": ip,
                    "ASN": response.get("asn", "N/A"),
                    "ISP": response.get("isp", "N/A"),
                    "Organization": response.get("org", "N/A"),
                }
            return {"Error": "ASN lookup başarısız"}
        except Exception:
            return {"Error": "ASN lookup başarısız"}

    def extract_metadata(self, file) -> Dict[str, Any]:
        meta: Dict[str, Any] = {}
        file_info: Dict[str, Any] = {}

        try:
            file_info["File Name"] = file.name
            file_info["File Size"] = f"{file.size / 1024:.2f} KB"
            file_info["File Type"] = file.type

            if file.type.startswith("image"):
                try:
                    img = Image.open(file)
                    meta["📷 IMAGE INFORMATION"] = {
                        "Format": img.format or "Unknown",
                        "Mode": img.mode,
                        "Width": img.width,
                        "Height": img.height,
                        "Size": f"{img.width}x{img.height}",
                        "DPI": img.info.get("dpi", "N/A"),
                        "Is Animated": getattr(img, "is_animated", False),
                        "Frames": img.n_frames if hasattr(img, "n_frames") else 1,
                    }

                    exif_dict: Dict[str, Any] = {}
                    try:
                        exif = img.getexif()
                        if exif:
                            for tag, value in exif.items():
                                decoded = TAGS.get(tag, f"Tag {tag}")
                                exif_dict[decoded] = str(value)[:100]
                    except Exception:
                        pass

                    if exif_dict:
                        meta["📸 EXIF DATA"] = exif_dict

                    meta["🎨 IMAGE PROPERTIES"] = {
                        "Color Space": img.mode,
                        "Has Palette": hasattr(img, "palette"),
                        "Has Transparency": "transparency" in img.info,
                        "Compression": img.info.get("compression", "N/A"),
                        "Format Description": img.info.get("description", "N/A"),
                    }
                except Exception as exc:
                    meta["Image Processing Error"] = str(exc)
            elif file.type == "application/pdf":
                try:
                    reader = PdfReader(file)
                    pdf_meta: Dict[str, str] = {}
                    if reader.metadata:
                        for key, value in reader.metadata.items():
                            pdf_meta[key.lstrip("/")] = str(value)
                    if pdf_meta:
                        meta["📄 PDF METADATA"] = pdf_meta

                    meta["📋 PDF INFORMATION"] = {
                        "Total Pages": len(reader.pages),
                        "Author": reader.metadata.get("/Author", "N/A") if reader.metadata else "N/A",
                        "Title": reader.metadata.get("/Title", "N/A") if reader.metadata else "N/A",
                        "Subject": reader.metadata.get("/Subject", "N/A") if reader.metadata else "N/A",
                        "Creator": reader.metadata.get("/Creator", "N/A") if reader.metadata else "N/A",
                        "Producer": reader.metadata.get("/Producer", "N/A") if reader.metadata else "N/A",
                        "Creation Date": str(reader.metadata.get("/CreationDate", "N/A")) if reader.metadata else "N/A",
                        "Modification Date": str(reader.metadata.get("/ModDate", "N/A")) if reader.metadata else "N/A",
                        "Encrypted": reader.is_encrypted,
                    }

                    if len(reader.pages) > 0:
                        first_page = reader.pages[0]
                        meta["📖 FIRST PAGE"] = {
                            "Width": float(first_page.mediabox.width),
                            "Height": float(first_page.mediabox.height),
                            "Rotation": first_page.get("/Rotate", 0),
                        }
                except Exception as exc:
                    meta["PDF Processing Error"] = str(exc)

            meta["📁 FILE INFORMATION"] = file_info
        except Exception as exc:
            meta["Critical Error"] = str(exc)

        return meta

    def check_password(self, pwd: str) -> str:
        score = 0
        if len(pwd) >= 12:
            score += 2
        if any(char.isupper() for char in pwd):
            score += 1
        if any(char.isdigit() for char in pwd):
            score += 1
        if any(char in string.punctuation for char in pwd):
            score += 1
        return "Çok Güçlü" if score >= 4 else "Orta" if score >= 2 else "Zayıf"
