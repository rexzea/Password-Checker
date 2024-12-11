import urllib.request
import urllib.parse
import html.parser
import ssl
import re
import socket
from datetime import datetime, timedelta

class PhishingDetector:
    def __init__(self, url):
        self.url = url
        self.risk_score = 0
        self.risk_details = []

    def analyze_url_structure(self):
        parsed_url = urllib.parse.urlparse(self.url)
        
        # cek panjang URL
        if len(self.url) > 100:
            self.risk_score += 20
            self.risk_details.append("URL terlalu panjang")

        # cek karakter spesial
        special_chars = re.findall(r'[@%#]', self.url)
        if special_chars:
            self.risk_score += 15
            self.risk_details.append(f"Mengandung karakter spesial: {special_chars}")

        # cek domain mirip dengan situs populer
        popular_domains = ['facebook', 'google', 'twitter', 'linkedin', 'bank']
        for domain in popular_domains:
            if domain in parsed_url.netloc.lower():
                self.risk_score += 25
                self.risk_details.append(f"Domain mirip dengan {domain}")

        # cek TLD tidak umum
        tld = parsed_url.netloc.split('.')[-1]
        uncommon_tlds = ['tk', 'ml', 'ga', 'cf', 'gq']
        if tld in uncommon_tlds:
            self.risk_score += 30
            self.risk_details.append(f"TLD tidak umum: {tld}")

    def fetch_page_content(self):
        try:
            # menonaktifkan verifikasi SSL 
            context = ssl._create_unverified_context()
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
            }
            req = urllib.request.Request(self.url, headers=headers)
            
            with urllib.request.urlopen(req, context=context) as response:
                html_content = response.read().decode('utf-8')
                
                # memeriksa kode status
                if response.status != 200:
                    self.risk_score += 10
                    self.risk_details.append(f"Kode status tidak normal: {response.status}")
                
                return html_content
        except Exception as e:
            self.risk_score += 50
            self.risk_details.append(f"Gagal mengambil halaman: {str(e)}")
            return None

    def check_ssl_certificate(self):
        try:
            parsed_url = urllib.parse.urlparse(self.url)
            hostname = parsed_url.netloc
            
            #  membuat koneksi SSL
            with socket.create_connection((hostname, 443)) as sock:
                context = ssl.create_default_context()
                with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                    # kalau berhasil membuat koneksi SSL, kurangi risiko
                    self.risk_score -= 10
                    self.risk_details.append("Koneksi SSL valid")
        except Exception as e:
            self.risk_score += 30
            self.risk_details.append(f"Masalah dengan koneksi SSL: {str(e)}")

    def simple_html_analysis(self, html_content):
        if html_content:
            # mencri input form yg berpotensi mencuri data
            form_keywords = ['login', 'password', 'email', 'kredensial']
            for keyword in form_keywords:
                if keyword.lower() in html_content.lower():
                    self.risk_score += 20
                    self.risk_details.append(f"Mengandung form dengan kata kunci berisiko: {keyword}")

            # mendeteksi script yang mencurigakan
            if '<script' in html_content and 'document.cookie' in html_content:
                self.risk_score += 25
                self.risk_details.append("Terdeteksi script yang berpotensi mencuri data")

    def classify_risk(self):
        if self.risk_score <= 20:
            return "Aman"
        elif 20 < self.risk_score <= 50:
            return "Waspada"
        elif 50 < self.risk_score <= 80:
            return "Mencurigakan"
        else:
            return "Phishing Berbahaya"

    def detect(self):
        self.analyze_url_structure()
        self.check_ssl_certificate()
        
        html_content = self.fetch_page_content()
        if html_content:
            self.simple_html_analysis(html_content)

        return {
            "url": self.url,
            "risk_score": self.risk_score,
            "risk_details": self.risk_details,
            "risk_status": self.classify_risk()
        }

def main():
    # contoh penggunaan
    url_to_check = input("Masukkan URL untuk diperiksa: ")
    detector = PhishingDetector(url_to_check)
    result = detector.detect()
    
    print("\n--- Hasil Deteksi Phishing ---")
    print(f"URL: {result['url']}")
    print(f"Skor Risiko: {result['risk_score']}")
    print(f"Status Risiko: {result['risk_status']}")
    print("\nDetail Risiko:")
    for detail in result['risk_details']:
        print(f"- {detail}")

if __name__ == "__main__":
    main()

# Berhenti otomatis dan proses di berhentikan saat Device mengalami penurunan peforma!
