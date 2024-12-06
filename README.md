# 🔍 Simple URL Checker

## 📝 Deskripsi Proyek

Simple URL Checker adalah alat untuk menganalisis dan menilai keamanan URL. Dirancang untuk melindungi pengguna dari potensi ancaman online, proyek ini memberikan laporan analisi tentang keamanan dan risiko terkait sebuah tautan web.

## ✨ Fitur Utama

- 🛡️ Deteksi Keamanan 
  - Pengecekan terhadap basis data URL berbahaya
  - Analisis struktur dan pola URL mencurigakan
  - Identifikasi potensi phishing dan situs malware

- 🌐 Dukungan Multi Protokol
  - Kompatibel dengan HTTP dan HTTPS
  - Pemeriksaan sertifikat SSL
  - Validasi konfigurasi keamanan jaringan

- ⚡ Performa Bagus
  - Scanning cepat dalam hitungan milidetik
  - Algoritma optimasi untuk efisiensi pemrosesan
  - Rendah konsumsi sumber daya komputasi

## 🚀 Instalasi

### Prasyarat
- Python 3.7+
- pip
- Koneksi internet

### Langkah Instalasi
```bash
# Clone repository
git clone https://github.com/rexzea/URl-Checker.git

# Install dependensi
pip install requests beautifulsoup4
```

## 💻 Penggunaan Dasar

```python
import requests
import json
import csv
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

# Periksa keamanan URL
      target_url = input("Masukkan URL website untuk pengujian (contoh: http://example.com): ")

# Preview
--- Hasil Deteksi Phishing ---
URL: https://vsbattles.fandom.com/wiki/VS_Battles_Wiki
Skor Risiko: 0
Status Risiko: Aman
```

## 🔬 Metode Deteksi

URL Checker menggunakan sedikit multi lapis untuk menilai keamanan:

1. **Blacklist Global**
   - Cross reference dengan database URL berbahaya internasional
   - Pembaruan berkala daftar ancaman

2. **Analisis Struktural URL**
   - Deteksi pola URL mencurigakan
   - Mengidentifikasi penggunaan subdomain tidak lazim
   - Pengecekan karakter dan enkoding mencurigakan

3. **Verifikasi Sertifikat**
   - Pemeriksaan validitas sertifikat SSL
   - Deteksi sertifikat yang kedaluwarsa atau tidak terpercaya

4. **Pemindaian Konten**
   - Analisis metadata
   - Pengecekan potensi redirect berbahaya

## 🤝 Kontribusi

Kami terbuka terhadap kontribusi! Untuk berkontribusi:

1. Fork repository
2. Buat branch fitur (`git checkout -b fitur-baru`)
3. Commit perubahan (`git commit -m 'menambah fitur baru'`)
4. Push ke branch (`git push origin fitur-baru`)
5. Buat Pull Request

## ⚖️ Lisensi

[Rexzea]

## ⚠️ Disclaimer

Alat ini disediakan sebagaimana adanya. Meskipun kami berusaha memberikan analisis keamanan yang akurat, tidak ada jaminan 100% terhadap keamanan yang bagus. Selalu gunakan penilaian pribadi dan pertimbangan keamanan digital kamu yaa :)

## 📞 Kontak

Untuk pertanyaan atau saran, silakan hubungi:
- Email: [@futzfary]
- GitHub : [https://github.com/rexzea)]

---

**Catatan Pengembangan**: Proyek ini terus berkembang. Pantau pembaruan dan kontribusi terbaru yaa!
