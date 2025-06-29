import argparse
import concurrent.futures
import difflib
import hashlib
import random
import signal
import sys
import time
import uuid
from collections import deque
from os.path import splitext
from urllib.parse import urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

try:
    import ssdeep
    HAS_SSDEEP = True
except ImportError:
    HAS_SSDEEP = False

try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False

init(autoreset=True)
found = set()
start_time = time.time()

COMMON_PATHS = [
    ".env", ".env.backup", ".env.dev", ".env.local", ".env.example",
    "config.php", "config.json", "config.ini", "config.py", "settings.py", "settings.ini",
    "parameters.yml", "app.yml", "local.xml", "web.config", ".user.ini", "php.ini",
    "id_rsa", "id_dsa", "private.key", "server.key", "key.pem", "cert.pem",
    "server.pfx", "server.p12",
    "database.sql", "db.sql", "dump.sql", "backup.sql",
    "backup.zip", "backup.tar.gz", "site_backup.tar.gz", "db.bak", "db.backup",
    "logs/error.log", "debug.log", "error_log",
    ".git/config", ".git/HEAD", ".gitignore", ".gitattributes",
    ".htpasswd", ".htaccess",
    "Dockerfile", "docker-compose.yml", ".bash_history", ".zsh_history",
    "composer.lock", "composer.json", "package.json", "yarn.lock",
    ".DS_Store", "Thumbs.db",
    "phpinfo.php", "phpinfo", "info.php", "test.php", "admin.php",
    "log/", "logs/", "backup/", "db/", "old/", "admin/", "api/", "uploads/", "sql/", "download/", "phpMyAdmin/", "phpmyadmin/", "Vpn/", "manual/", "mailman/", "mailman/listinfo",
]

EXCLUDED_KEYWORDS = ["css", "js", "img", "font", "icon", "static"]
INDICATORS = ["phpinfo", "sql", "ssh-rsa", "root:", "mysql", "BEGIN RSA"]

def print_banner():
    print(f"""
{Fore.CYAN}{Style.BRIGHT}   ____                 __   _           __  _       __
  / __/__  ___ ______/ /  (_)__  ___  / /_(_)___ _/ /____
 _\ \/ _ \/ _ `/ __/ _ \/ / _ \/ _ \/ __/ / __ `/ __/ -_)
/___/ .__/\_,_/_/ /_//_/_/\___/_//_/\__/_/\_,_/\__/\__/
   /_/    by Conffinder - Sensitive File Scanner - Author: Kazusa - Version: v1.1{Style.RESET_ALL}
""")
    if not HAS_SSDEEP:
        print(f"{Fore.YELLOW}[!] 未偵測到 ssdeep，將使用 difflib 比對{Style.RESET_ALL}")
    if not HAS_MAGIC:
        print(f"{Fore.YELLOW}[!] 未偵測到 python-magic，將略過 magic bytes 判斷{Style.RESET_ALL}")

def normalize_url(url):
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path.rstrip("/"), "", "", ""))

def strip_html(html):
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style"]):
        tag.decompose()
    return soup.get_text(" ", strip=True)

def fuzzy_similarity(a, b):
    if HAS_SSDEEP:
        return ssdeep.compare(a, b) >= 90
    return difflib.SequenceMatcher(None, a, b).ratio() >= 0.9

def get_baselines(base_url, headers):
    paths = [f"/{uuid.uuid4().hex}_404", "/", "/index.php"]
    results = []
    for p in paths:
        try:
            r = requests.get(urljoin(base_url, p), headers=headers, timeout=6)
            results.append({"text": r.text, "ssdeep": ssdeep.hash(r.text) if HAS_SSDEEP else None})
        except:
            results.append({"text": "", "ssdeep": None})
    return results

def scan_single(path, base_url, headers, baselines, debug):
    target = urljoin(base_url.rstrip("/") + "/", path)
    try:
        head = requests.head(target, headers=headers, timeout=6, allow_redirects=False)
        if head.status_code in (404, 410): return
        if 300 <= head.status_code < 400:
            loc = head.headers.get("Location", "")
            if loc.endswith(('/', 'index.php', 'index.html')):
                if debug:
                    print(f"{Fore.LIGHTBLACK_EX}[-] 跳轉首頁排除: {target}{Style.RESET_ALL}")
                return
        r = requests.get(target, headers=headers, timeout=6)
        if r.status_code in (404, 410): return

        if r.status_code == 403:
            print(f"{Fore.MAGENTA}[!!] 403 Forbidden（可能存在受限）: {target}{Style.RESET_ALL}")
            found.add((target, "403"))
            return

        for b in baselines:
            if fuzzy_similarity(strip_html(r.text), strip_html(b["text"])):
                if debug:
                    print(f"{Fore.LIGHTBLACK_EX}[-] 假頁面排除: {target}{Style.RESET_ALL}")
                return

        ctype = r.headers.get("Content-Type", "").lower()
        is_sensitive = any(ind in r.text.lower() for ind in INDICATORS)

        if HAS_MAGIC:
            try:
                mime = magic.from_buffer(r.content[:1024], mime=True)
                if mime.startswith("application"):
                    is_sensitive = True
            except: pass

        if is_sensitive or "text" in ctype or len(r.content) > 200:
            print(f"{Fore.GREEN}[!!] 發現敏感檔案: {target}{Style.RESET_ALL}")
            found.add((target, "normal"))
    except Exception as e:
        if debug:
            print(f"{Fore.LIGHTBLACK_EX}[-] 錯誤跳過: {target} | {e}{Style.RESET_ALL}")

def extract_links(html, base, depth, max_depth):
    if max_depth is not None and depth >= max_depth:
        return set()
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for tag in soup.find_all("a", href=True):
        href = tag['href']
        if any(x in href for x in EXCLUDED_KEYWORDS): continue
        full = urljoin(base, href)
        if full.startswith("http"):
            links.add(full.rstrip("/") + "/")
    return links

def scan_site(base_url, threads=4, delay=(0, 0), cookies=None, debug=False, max_depth=2, allow_subdomain=False, follow_root_only=False):
    headers = {"User-Agent": "Mozilla/5.0"}
    if cookies:
        headers["Cookie"] = cookies
    baselines = get_baselines(base_url, headers)
    queue = deque([(base_url, 0)])
    visited = set()
    scanned_dirs = set()
    while queue:
        url, depth = queue.popleft()
        norm = normalize_url(url)
        if norm in visited:
            continue
        visited.add(norm)
        print(f"{Fore.YELLOW}[~] 掃描目錄: {url}{Style.RESET_ALL}")
        try:
            r = requests.get(url, headers=headers, timeout=6)
            new_links = extract_links(r.text, url, depth, max_depth)
            base_host = urlparse(base_url).hostname
            for lk in new_links:
                parsed = urlparse(lk)
                if follow_root_only and parsed.hostname != base_host:
                    continue
                if not allow_subdomain and parsed.hostname != base_host:
                    continue
                if normalize_url(lk) not in visited:
                    queue.append((lk, depth + 1))
        except:
            pass
        if norm not in scanned_dirs:
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
                tasks = [ex.submit(scan_single, p, url, headers, baselines, debug) for p in COMMON_PATHS]
                for t in concurrent.futures.as_completed(tasks):
                    t.result()
            scanned_dirs.add(norm)

def main():
    print_banner()
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", dest="url", required=True)
    parser.add_argument("-t", dest="threads", type=int, default=4)
    parser.add_argument("-d", dest="debug", action="store_true")
    parser.add_argument("-min", dest="min_delay", type=float, default=0)
    parser.add_argument("-max", dest="max_delay", type=float, default=0)
    parser.add_argument("-c", dest="cookies", help="Cookie")
    parser.add_argument("-dp", dest="depth", type=int, default=2)
    parser.add_argument("-sd", dest="subdomain_scope", action="store_true", help="允許掃描子網域")
    parser.add_argument("-fr", dest="follow_root_only", action="store_true", help="僅追蹤主網域來源")
    args = parser.parse_args()

    def stop(sig, frm):
        print(f"\n{Fore.RED}[!] 中斷掃描，列出已發現:{Style.RESET_ALL}")
        for f, ftype in sorted(found):
            color = Fore.MAGENTA if ftype == "403" else Fore.GREEN
            print(f"   └─ {color}{f}{Style.RESET_ALL}")
        sys.exit(0)

    signal.signal(signal.SIGINT, stop)
    scan_site(
        base_url=args.url,
        threads=args.threads,
        delay=(args.min_delay, args.max_delay),
        cookies=args.cookies,
        debug=args.debug,
        max_depth=args.depth,
        allow_subdomain=args.subdomain_scope,
        follow_root_only=args.follow_root_only
    )
    print("\n" + "=" * 50)
    if found:
        print(f"[*] 共發現 {len(found)} 筆敏感資料及路徑：")
        for f, ftype in sorted(found):
            color = Fore.MAGENTA if ftype == "403" else Fore.GREEN
            print(f"   └─ {color}{f}{Style.RESET_ALL}")
    else:
        print("[-] 未發現敏感項目")

if __name__ == "__main__":
    main()

