import requests
from bs4 import BeautifulSoup
import tldextract
import difflib
import re
import ssl
import socket
from urllib.parse import urlparse
import whois
from datetime import datetime

class PhishingDetector:
    def __init__(self, url):
        self.url = url
        self.risk_score = 0
        self.risk_details = []

    def analyze_url_structure(self):
        """Menganalisis struktur URL untuk mendeteksi potensi phishing"""
        parsed_url = urlparse(self.url)
        extracted = tldextract.extract(self.url)

        # cek panjang URL
        if len(self.url) > 100:
            self.risk_score += 20
            self.risk_details.append("URL terlalu panjang")

        # cek karakter spesial
        special_chars = re.findall(r'[@%#]', self.url)
        if special_chars:
            self.risk_score += 15
            self.risk_details.append(f"Mengandung karakter spesial: {special_chars}")

        # cek domain yang mirip dengan situs terkenal lain
        popular_domains = ['facebook', 'google', 'twitter', 'linkedin', 'bank']
        for domain in popular_domains:
            if domain in extracted.domain.lower():
                self.risk_score += 25
                self.risk_details.append(f"Domain mirip dengan {domain}")

        # cek tld yang tidak umum
        uncommon_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
        if extracted.suffix in uncommon_tlds:
            self.risk_score += 30
            self.risk_details.append(f"TLD tidak umum: {extracted.suffix}")

    def fetch_page_content(self):
        """Mengambil konten halaman web"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(self.url, headers=headers, timeout=10)
            
            # kode status
            if response.status_code != 200:
                self.risk_score += 10
                self.risk_details.append(f"Kode status tidak normal: {response.status_code}")

            return BeautifulSoup(response.text, 'html.parser')
        except requests.exceptions.RequestException as e:
            self.risk_score += 50
            self.risk_details.append(f"Gagal mengambil halaman: {str(e)}")
            return None

    def check_ssl_certificate(self):
        """Memeriksa sertifikat SSL"""
        try:
            hostname = urlparse(self.url).netloc
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                    cert = secure_sock.getpeercert()
                    
                    # Periksa tanggal kedaluwarsa
                    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry_date - datetime.now()).days
                    
                    if days_until_expiry < 30:
                        self.risk_score += 20
                        self.risk_details.append("Sertifikat SSL akan segera kedaluwarsa")
        except Exception as e:
            self.risk_score += 30
            self.risk_details.append(f"Masalah dengan sertifikat SSL: {str(e)}")

    def analyze_whois_data(self):
        """Menganalisis informasi domain"""
        try:
            domain = urlparse(self.url).netloc
            w = whois.whois(domain)
            
            # umur domain
            if isinstance(w.creation_date, list):
                creation_date = w.creation_date[0]
            else:
                creation_date = w.creation_date
            
            domain_age = (datetime.now() - creation_date).days
            
            if domain_age < 180:  # kurang dari 6 bulan
                self.risk_score += 25
                self.risk_details.append("Domain relatif baru")
        except Exception as e:
            self.risk_score += 15
            self.risk_details.append(f"Gagal mengambil data WHOIS: {str(e)}")

    def classify_risk(self):
        """Mengklasifikasikan tingkat risiko"""
        if self.risk_score <= 20:
            return "Aman"
        elif 20 < self.risk_score <= 50:
            return "Waspada"
        elif 50 < self.risk_score <= 80:
            return "Mencurigakan"
        else:
            return "Phishing Berbahaya"

    def detect(self):
        """Proses utama deteksi phishing"""
        self.analyze_url_structure()
        self.check_ssl_certificate()
        self.analyze_whois_data()
        soup = self.fetch_page_content()

        

        return {
            "url": self.url,
            "risk_score": self.risk_score,
            "risk_details": self.risk_details,
            "risk_status": self.classify_risk()
        }

def main():
    # penggunaan
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

# Proses lebih kompleks -> Berhenti otomatis dan proses di berhentikan saat Device mengalami penurunan peforma!