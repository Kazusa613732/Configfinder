# Python script: 檢測目標網站是否暴露敏感檔案 (.env, .git, phpinfo 等)

import requests
import argparse
from urllib.parse import urljoin

COMMON_PATHS = [
    # 環境設定
    ".env", ".env.backup", ".env.dev", ".env.local", ".env.example",
    "config.php", "config.json", "config.ini", "settings.py", "settings.ini",
    "parameters.yml", "app.yml", "local.xml",

    # 憑證與金鑰
    "id_rsa", "id_dsa", "private.key", "server.key", "key.pem", "cert.pem",
    "server.pfx", "server.p12",

    # 資料庫與備份
    "database.sql", "db.sql", "dump.sql", "backup.sql",
    "backup.zip", "backup.tar.gz", "site_backup.tar.gz", "db.bak", "db.backup",
    "logs/error.log", "debug.log", "error_log",

    # .git & 隱藏檔
    ".git/config", ".git/HEAD", ".gitignore", ".gitattributes",
    ".htpasswd", ".htaccess",

    # 系統與開發工具
    "Dockerfile", "docker-compose.yml", ".bash_history", ".zsh_history",
    "composer.lock", "composer.json", "package.json", "yarn.lock",
    ".DS_Store", "Thumbs.db",

    # 測試與資訊
    "phpinfo.php", "phpinfo", "info.php", "test.php",

    # 目錄索引（會偵測 Index of）
    "logs/", "backup/", "db/", "old/", "admin/", "api/", "uploads/"
]

import concurrent.futures

def scan_sensitive_files(base_url, min_delay, max_delay, threads, max_depth=3, subdomain_scope=True, cookies=None, debug=False, follow_root_only=False):
    baseline_size = None
    from urllib.parse import urlparse
    from bs4 import BeautifulSoup
    from collections import deque

    from urllib.parse import urlparse, urlunparse
    def normalize_url(url):
        parsed = urlparse(url)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip('/'), '', '', ''))

    scanned_paths = set()
    visited = set()
    queue = deque([(base_url, 0)])

    def extract_links(html, base):
        soup = BeautifulSoup(html, 'html.parser')
        from urllib.parse import urlparse
        base_host = urlparse(base).netloc
        links = set()
        for tag in soup.find_all('a', href=True):
            href = tag['href']
            if href.startswith('/') or base in href:
                full_url = urljoin(base, href)
                if follow_root_only and urlparse(full_url).netloc != base_host:
                    continue
                if not subdomain_scope:
                    if urlparse(full_url).hostname != urlparse(base).hostname:
                        continue
                else:
                    if urlparse(full_url).netloc != urlparse(base).netloc:
                        continue
                    links.add(full_url.rstrip('/') + '/')
        return links
    def scan_single_path(idx, path, base_url, user_agents, min_delay, max_delay):
        import time
        headers = {"User-Agent": random.choice(user_agents)}
        delay = random.uniform(min_delay, max_delay)
        if delay > 0:
            print(f"[延遲] 等待 {delay:.2f} 秒...")
            time.sleep(delay)
        progress = (idx / len(COMMON_PATHS)) * 100
        print(f"{Fore.BLUE}[→] 掃描進度: {idx}/{len(COMMON_PATHS)} ({progress:.2f}%) - {path}{Style.RESET_ALL}")
        target_url = urljoin(base_url.rstrip('/') + '/', path)
        try:
            if cookies:
                headers["Cookie"] = cookies
            resp = requests.get(target_url, headers=headers, timeout=5, allow_redirects=True)
            if resp.status_code == 200:
                size_diff = abs(len(resp.content) - baseline_size) if baseline_size else 9999
                if size_diff < 50:
                    if debug:
                        print(f"{Fore.LIGHTBLACK_EX}[-] 回應大小與 baseline 相同（diff={size_diff}），排除: {target_url}{Style.RESET_ALL}")
                    return None
                content_type = resp.headers.get("Content-Type", "").lower()
                indicators = ["phpinfo", "sql", "ssh-rsa", "root:", "mysql", "BEGIN RSA PRIVATE KEY"]
                ext_map = {
                    '.env': 'text/plain', '.json': 'application/json', '.ini': 'text/plain', '.yml': 'text/plain', '.xml': 'application/xml',
                    '.sql': 'application/sql', '.log': 'text/plain', '.php': 'text/html',
                    '.zip': 'application/zip', '.gz': 'application/gzip', '.bak': 'application/octet-stream',
                    '.key': 'application/octet-stream', '.pem': 'application/x-pem-file', '.pfx': 'application/x-pkcs12', '.p12': 'application/x-pkcs12',
                    '.lock': 'text/plain', '.history': 'text/plain', '.db': 'application/octet-stream',
                    '.dockerfile': 'text/plain'
                }
                import os
                _, ext = os.path.splitext(path.lower())
                expected_ct = ext_map.get(ext, '')
                size_diff = abs(len(resp.content) - baseline_size) if baseline_size else 9999
                if size_diff < 50:
                    if debug:
                        print(f"{Fore.LIGHTBLACK_EX}[-] 回應大小與 baseline 相同（diff={size_diff}），排除: {target_url}{Style.RESET_ALL}")
                    return None

                is_sensitive = (
                    expected_ct in content_type or
                    any(kw in resp.text.lower() for kw in indicators) or
                    any(ct in content_type for ct in ["application/zip", "application/sql", "text/plain"]) or
                    len(resp.content) > 200
                )
                if is_sensitive:
                    debug_reason = f"[Match] ext={ext} → expect={expected_ct}, actual={content_type}, size={len(resp.content)}"
                    if debug:
                        print(f"[92m[!!] 發現機敏檔案: {target_url} ({debug_reason})[0m")
                    else:
                        print(f"[92m[!!] 發現機敏檔案: {target_url}[0m")
                return target_url
        except requests.RequestException:
            pass
        return None
    import random

    try:
        with open('user_agents.txt', 'r', encoding='utf-8') as f:
            user_agents = [ua.strip() for ua in f if ua.strip()]
    except FileNotFoundError:
        print("[!] 找不到 user_agents.txt，請確認檔案是否存在")
        user_agents = ["Mozilla/5.0 (Scanner)"]

    # 遞迴爬網址並掃描每層目錄
    found = []
    print(f"[*] 開始掃描: {base_url}")
        # 建立 baseline 回應大小
    try:
        headers = {"User-Agent": random.choice(user_agents)}
        if cookies:
            headers["Cookie"] = cookies
        baseline_resp = requests.get(base_url.rstrip('/') + "/nonexistent_baseline_404_test", headers=headers, timeout=5)
        baseline_size = len(baseline_resp.content)
    except Exception:
        baseline_size = None

    while queue:
        current_url, depth = queue.popleft()
        norm_url = normalize_url(current_url)
        if norm_url in visited:
            continue
        visited.add(norm_url)
        print(f"{Fore.YELLOW}[~] 掃描中目錄: {current_url}{Style.RESET_ALL}")
        try:
            headers = {"User-Agent": random.choice(user_agents)}
            if cookies:
                headers["Cookie"] = cookies
            resp = requests.get(current_url, headers=headers, timeout=5)
            links = extract_links(resp.text, current_url)
            for link in links:
                link_norm = normalize_url(link)
                if link_norm not in visited and all(link_norm != normalize_url(q[0]) for q in queue):
                    queue.append((link, depth + 1))
        except requests.RequestException:
            continue

        if current_url not in scanned_paths:
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                futures = [executor.submit(scan_single_path, idx + 1, path, current_url, user_agents, min_delay, max_delay) for idx, path in enumerate(COMMON_PATHS)]
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        found.append(result)
            scanned_paths.add(current_url)
        if not any(f.startswith(current_url) for f in found):
            print(f"{Fore.LIGHTBLACK_EX}[-] 未發現敏感檔案{Style.RESET_ALL}")
    
    
    if not found:
        print("[-] 未發現敏感檔案")
    else:
        print(f"[*] 共發現 {len(found)} 個可疑檔案")
        print("[*] 可疑檔案列表：")
        for item in found:
            print(f"   └─ {item}")

import sys
import time
from colorama import init, Fore, Style

def print_banner():
    init(autoreset=True)
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}   ____                 __   _           __  _       __     
  / __/__  ___ ______/ /  (_)__  ___  / /_(_)___ _/ /____ 
 _\ \/ _ \/ _ `/ __/ _ \/ / _ \/ _ \/ __/ / __ `/ __/ -_)/
/___/ .__/\_,_/_/ /_//_/_/\___/_//_/\__/_/\_,_/\__/\__/ 
   /_/   by Conffinder - Sensitive File Scanner - Author: Kazusa - Version: v1.0
{Style.RESET_ALL}"""
    print(banner)
    time.sleep(0.3)

def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="敏感設定檔與資訊洩漏掃描工具",
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-d', dest='debug', action='store_true', help='開啟 debug 模式（顯示偵測依據）')
    parser.add_argument('-u', dest='url', metavar='URL', required=True, help='目標網站根目錄')
    parser.add_argument('-min', dest='min_delay', type=float, default=0, help='最小延遲秒數')
    parser.add_argument('-max', dest='max_delay', type=float, default=0, help='最大延遲秒數')
    parser.add_argument('-t', '--threads', type=int, default=1, help='同時執行的請求數')
    parser.add_argument('-sd', dest='subdomain_scope', action='store_true', help='允許掃描子網域')
    parser.add_argument('-c', dest='cookie', type=str, help='自訂 Cookie（登入狀態）')
    parser.add_argument('-fr', dest='follow_root_only', action='store_true', help='只掃描主網域來源（避免跳轉到 CDN 或外站）')
    args = parser.parse_args()
    scan_sensitive_files(
        base_url=args.url,
        min_delay=args.min_delay,
        max_delay=args.max_delay,
        threads=args.threads,
        subdomain_scope=args.subdomain_scope,
        cookies=args.cookie,
        debug=args.debug,
        follow_root_only=args.follow_root_only
    )

if __name__ == "__main__":
    main()
