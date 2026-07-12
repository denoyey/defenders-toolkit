# Defenders Toolkit

**Blue Team Security Auditing Toolkit - Enterprise**

Defenders Toolkit adalah kerangka kerja audit keamanan komprehensif dan *asynchronous* yang dibangun menggunakan Python. Dirancang untuk *Blue Team* dan profesional keamanan, alat ini mengotomatiskan pencarian kerentanan web umum, kesalahan konfigurasi, dan eksposur data sensitif.

## 🚀 Fitur

- **Eksekusi Asynchronous:** Dibangun di atas `asyncio` dan `aiohttp` untuk pemeriksaan keamanan non-blokir yang sangat cepat.
- **Arsitektur Modular:** Mudah diperluas dengan berbagai modul pemindaian.
- **CLI Interaktif:** Antarmuka baris perintah yang ramah pengguna dengan kode warna.
- **Pelaporan HTML Dashboard:** Secara otomatis menghasilkan laporan HTML yang menarik untuk temuan Anda.
- **Otentikasi Global:** Mendukung injeksi token Bearer atau *string Cookie* secara global di seluruh modul untuk pengujian terotentikasi.

## 🧩 Modul yang Disertakan

Toolkit saat ini mengekspos modul inti berikut melalui CLI-nya:

- **OSINT Subdomain Enumerator**
  Mengekstrak subdomain dari log Certificate Transparency (`crt.sh`) untuk pemetaan permukaan serangan (*attack surface mapping*).
- **Enterprise Sensitive Exposure Scanner**
  Melakukan pemindaian *asynchronous* menggunakan daftar kata (wordlist) dinamis, mekanisme anti-WAF, dan pelaporan JSON untuk menemukan file sensitif yang terekspos.
- **GraphQL Introspection Scanner**
  Mendeteksi *endpoint* GraphQL dan menguji kebocoran skema melalui kueri Introspection.
- **Cloud S3 & Subdomain Takeover Scanner**
  Mengidentifikasi *bucket* AWS S3 dan GCP dengan kesalahan konfigurasi yang dapat diakses oleh publik.

*(Catatan: Direktori `modules/` berisi banyak pemindai lain seperti pemeriksa JWT, penganalisis CORS, pemindai kebocoran konfigurasi, dll., yang dapat diintegrasikan sesuai kebutuhan.)*

## 🛠️ Instalasi

Pastikan Anda memiliki **Python 3.8+** terinstal.

```bash
git clone https://github.com/denoyey/defenders-toolkit.git
cd defenders-toolkit
# Opsional: Buat virtual environment
python3 -m venv venv
source venv/bin/activate
```

*Defenders Toolkit akan memverifikasi dan menginstal dependensi yang diperlukan secara otomatis (dari `requirements.txt`) pada saat pertama kali dijalankan.*

## 💻 Penggunaan

Mulai toolkit interaktif dengan menjalankan:

```bash
python3 main.py
```

Setelah CLI berjalan, Anda dapat:
1. **Memilih modul** dengan memasukkan nomor yang sesuai.
2. **Memasukkan target** URL atau domain Anda saat diminta.
3. Menggunakan opsi `[A]` untuk mengatur **Token Bearer atau Cookie** global jika target memerlukan otentikasi.
4. Menggunakan opsi `[R]` untuk menghasilkan **Dashboard HTML** interaktif yang mengkompilasi semua laporan pemindaian Anda.

## ⚠️ Penafian (Disclaimer)

Toolkit ini dikembangkan untuk tujuan pendidikan dan audit keamanan profesional saja. **Pastikan Anda memiliki izin eksplisit** untuk menguji sistem target sebelum menjalankan pemindaian apa pun. Pengembang tidak menanggung kewajiban dan tidak bertanggung jawab atas penyalahgunaan atau kerusakan yang disebabkan oleh program ini.

---
**Hak Cipta (c) 2026 Defenders Toolkit**
**Seluruh Hak Cipta.**
