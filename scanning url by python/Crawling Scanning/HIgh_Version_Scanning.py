import requests
import json
import csv
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

class WebVulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.scanned_urls = set()
        self.vulnerable_urls = []
        self.payloads = {
            'sql_injection': [
                "' OR 1=1--",
                "' OR '1'='1",
                "1' UNION SELECT 1,2,3--"
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>"
            ],
            'command_injection': [
                "; ls",
                "&& whoami",
                "| id"
            ]
        }

    def validate_url(self):
        """Validasi URL target"""
        try:
            response = requests.head(self.target_url, timeout=5)
            return response.status_code == 200
        except requests.RequestException:
            return False

    def crawl(self, url=None):
        """Crawling website untuk menemukan URL internal"""
        if url is None:
            url = self.target_url

        if url in self.scanned_urls:
            return
        
        self.scanned_urls.add(url)
        
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for link in soup.find_all('a', href=True):
                absolute_link = urljoin(url, link['href'])
                
                # hanya cuman crawl url pada domain yang sama saja
                if urlparse(absolute_link).netloc == urlparse(self.target_url).netloc:
                    if absolute_link not in self.scanned_urls:
                        self.crawl(absolute_link)
        
        except requests.RequestException as e:
            print(f"Error crawling {url}: {e}")

    def test_sql_injection(self, url, params):
        """Menguji SQL Injection"""
        vulnerabilities = []
        
        for key, value in params.items():
            for payload in self.payloads['sql_injection']:
                test_params = params.copy()
                test_params[key] = payload
                
                try:
                    response = requests.get(url, params=test_params)
                    
                    # Cek indikasi kerentanan SQL Injection
                    if any(error in response.text for error in ['SQL syntax', 'MySQL', 'Warning', 'error in your SQL syntax']):
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'url': url,
                            'parameter': key,
                            'payload': payload
                        })
                except requests.RequestException:
                    pass
        
        return vulnerabilities

    def test_xss(self, url, params):
        """Menguji Cross-Site Scripting (XSS)"""
        vulnerabilities = []
        
        for key, value in params.items():
            for payload in self.payloads['xss']:
                test_params = params.copy()
                test_params[key] = payload
                
                try:
                    response = requests.get(url, params=test_params)
                    
                    # meng ecek apakah payload dieksekusi/muncul di respon
                    if payload in response.text:
                        vulnerabilities.append({
                            'type': 'XSS',
                            'url': url,
                            'parameter': key,
                            'payload': payload
                        })
                except requests.RequestException:
                    pass
        
        return vulnerabilities

    def scan(self):
        """Melakukan scanning keseluruhan"""
        if not self.validate_url():
            print("URL tidak valid atau tidak dapat diakses")
            return

        # crawling
        self.crawl()

        # scanning untuk setiap url
        for url in self.scanned_urls:
            # Dapatkan parameter dari URL
            parsed_url = urlparse(url)
            params = dict([p.split('=') for p in parsed_url.query.split('&')]) if parsed_url.query else {}

            # pengujian kerentanan
            sql_vuln = self.test_sql_injection(url, params)
            xss_vuln = self.test_xss(url, params)

            self.vulnerable_urls.extend(sql_vuln)
            self.vulnerable_urls.extend(xss_vuln)

    def save_report(self, format='json'):
        """Menyimpan laporan hasil scanning"""
        filename = f'vulnerability_report.{format}'

        if format == 'json':
            with open(filename, 'w') as f:
                json.dump(self.vulnerable_urls, f, indent=2)
        elif format == 'csv':
            with open(filename, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['type', 'url', 'parameter', 'payload'])
                writer.writeheader()
                writer.writerows(self.vulnerable_urls)
        else:
            with open(filename, 'w') as f:
                for vuln in self.vulnerable_urls:
                    f.write(f"Type: {vuln['type']}\n")
                    f.write(f"URL: {vuln['url']}\n")
                    f.write(f"Parameter: {vuln['parameter']}\n")
                    f.write(f"Payload: {vuln['payload']}\n\n")


def main():
    try:
        target_url = input("Masukkan URL website untuk pengujian (contoh: http://example.com): ")
        
        
        if not target_url.startswith(('http://', 'https://')):
            print("URL harus dimulai dengan http:// atau https://")
            return

        scanner = WebVulnerabilityScanner(target_url)
        scanner.scan()
        scanner.save_report(format='json')
        
        print("Proses scanning selesai.")
        print("Vulnerabilities found:")
        for vuln in scanner.vulnerable_urls:
            print(f"- {vuln['type']} in {vuln['url']} (Parameter: {vuln['parameter']})")

    except Exception as e:
        print(f"Terjadi kesalahan: {e}")
 
if __name__ == "__main__":
    main()

# Proses lebih kompleks dan Beresiko untuk mengalami Freeze!
# Proses lebih kompleks -> Berhenti otomatis dan proses di berhentikan saat Device mengalami penurunan peforma!