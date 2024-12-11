import requests
import json
import csv
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

class WebVulnerabilityScanner:
    def __init__(self, target_url, max_pages=10):  # batasi jumlah halaman
        self.target_url = target_url
        self.scanned_urls = set()
        self.vulnerable_urls = []
        self.max_pages = max_pages  # batasan halaman
        self.payloads = {
            'sql_injection': [
                "' OR 1=1--",
                "' OR '1'='1"
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>"
            ]
        }

    def validate_url(self):
        try:
            response = requests.head(self.target_url, timeout=3)  # kurangi timeout
            return response.status_code == 200
        except requests.RequestException:
            return False

    def crawl(self, url=None):
        if url is None:
            url = self.target_url

        # Batasi jumlah halaman yang di-crawl
        if len(self.scanned_urls) >= self.max_pages:
            return

        if url in self.scanned_urls:
            return
        
        self.scanned_urls.add(url)
        print(f"Crawling: {url}")  # tracking
        
        try:
            response = requests.get(url, timeout=5)  # timeout
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for link in soup.find_all('a', href=True)[:5]:  # jumlah link
                absolute_link = urljoin(url, link['href'])
                
                if urlparse(absolute_link).netloc == urlparse(self.target_url).netloc:
                    if absolute_link not in self.scanned_urls:
                        self.crawl(absolute_link)
        
        except requests.RequestException as e:
            print(f"Error crawling {url}: {e}")

    def test_sql_injection(self, url, params):
        vulnerabilities = []
        
        for key, value in params.items():
            for payload in self.payloads['sql_injection']:
                test_params = params.copy()
                test_params[key] = payload
                
                try:
                    response = requests.get(url, params=test_params, timeout=3)
                    
                    if any(error in response.text for error in ['SQL syntax', 'MySQL', 'Warning']):
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
        vulnerabilities = []
        
        for key, value in params.items():
            for payload in self.payloads['xss']:
                test_params = params.copy()
                test_params[key] = payload
                
                try:
                    response = requests.get(url, params=test_params, timeout=3)
                    
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
        if not self.validate_url():
            print("URL tidak valid atau tidak dapat diakses")
            return

        print(f"Memulai scanning pada {self.target_url}")
        
        # crawling
        self.crawl()

        print(f"Total URL yang di-crawl: {len(self.scanned_urls)}")

        # scanning setiap url
        for url in list(self.scanned_urls):  # buat menghindari error iterator
            parsed_url = urlparse(url)
            params = dict([p.split('=') for p in parsed_url.query.split('&')]) if parsed_url.query else {}

            print(f"Menguji URL: {url}")
            
            sql_vuln = self.test_sql_injection(url, params)
            xss_vuln = self.test_xss(url, params)

            self.vulnerable_urls.extend(sql_vuln)
            self.vulnerable_urls.extend(xss_vuln)

    def save_report(self, format='json'):
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
    target_url = input("Masukkan URL website untuk scanning: ")
    scanner = WebVulnerabilityScanner(target_url, max_pages=10)  # batasi 10 halaman saja
    scanner.scan()
    scanner.save_report(format='json')
    
    print("\nVulnerabilities found:")
    for vuln in scanner.vulnerable_urls:
        print(f"- {vuln['type']} in {vuln['url']} (Parameter: {vuln['parameter']})")

if __name__ == "__main__":
    main()

# Berhenti otomatis dan proses di berhentikan saat Device mengalami penurunan peforma!
