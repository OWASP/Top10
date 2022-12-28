# A08:2021 - Kegagalan Integritas Data dan Perangkat Lunak     ![icon](assets/TOP_10_Icons_Final_Software_and_Data_Integrity_Failures.png){: style="height:80px;width:80px" align="right"}

## Faktor

| CWE Dipetakan | Tingkat Kejadian Maksimum | Rata-rata Tingkat Kejadian | Rata-rata Exploitasi Terbobot | Rata-rata Dampak Terbobot | Cakupan Maksimum | Rata-rata Cakupan | Total Kejadian | Total CVE |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 10          | 16,67%             | 2,05%              | 6,94                 | 7,94                | 75,04%       | 45,35%       | 47.972            | 1.152      |

## Ringkasan

Kategori baru pada tahun 2021 yang berfokus pada membuat asumsi terkait 
pembaruan perangkat lunak, data kritis, dan pipeline CI/CD tanpa memverifikasi 
integritas. Satu dari dampak dibobot tertinggi dari data Common Vulnerability 
and Exposures/Common Vulnerability Scoring System (CVE/CVSS). CWE yang patut 
diperhatikan *CWE-829: Inclusion of Functionality from Untrusted Control 
Sphere*, *CWE-494: Download of Code Without Integrity Check*, dan *CWE-502: 
Deserialization of Untrusted Data*.

## Deskripsi

Kegagalan integritas data dan perangkat lunak berhubungan dengan kode dan
infrastruktur yang tidak melindungi terhadap pelanggaran integritas. Suatu
contoh ini adalah dimana suatu aplikasi mengandalkan pada plugin, pustaka, atau
modul dari sumber-sumber, repostori, dan content delivery network (CDN)  yang 
tidak terpercaya. Suatu pipeline CI/CD yang tidak aman bisa memperkenalkan
potensi akses tanpa otorisasi, kode jahat, atau terkomprominya sistem.
Terakhir, banyak aplikasi sekarang menyertakan fungsionalitas pembaruan 
otomatis, dimana pembaruan diunduh tanpa adanya verifikasi integritas yang 
cukup dan diterapkan terhadap aplikasi yang sebelumnya terpercaya.
Penyerang bisa berpotensi mengunggah pembaruan milik mereka sendiri untuk 
didistribusikan dan dijalankan pada semua instalasi. Contoh lain adalah dimana
objek atau data yang dienkoding/diserialisasi ke dalam struktur yang dapat 
dilihat dan dimodifikasi oleh penyerang rentan terhadap deserialisasi yang 
tidak aman.

## Bagaimana Mencegah

- Gunakan tanda tangan digital atau mekanisme serupa untuk memverifikasi 
  bahwa perangkat lunak atau data berasal dari sumber yang diharapkan dan 
  tidak diubah.

- Pastikan pustaka dan dependensi, seperti npm atau Maven, menggunakan 
  repositori yang terpercaya. Apabila Anda punya profil dengan risiko lebih 
  tinggi, pertimbangkan untuk mewadahi suatu repositori internal yang 
  diketahui baik yang diperiksa.

- Pastikan alat keamanan rantai pasokan perangkat lunak, seperti OWASP 
  Dependency Check atau OWASP CycloneDX digunakan untuk memverifikasi bahwa 
  komponen tidak memiliki kerentanan yang sudah diketahui.

- Pastikan adanya proses peninjauan ketika mengubah kode dan konfigurasi 
  untuk meminimalisir kemungkinan kode atau konfigurasi berbahaya masuk ke
  dalam *pipeline* perangkat lunak Anda.

- Pastikan *CI/CD pipeline* Anda memiliki segregasi, konfigurasi, dan 
  kontrol akses yang tepat untuk memastikan integritas kode yang masuk 
  mulai dari proses *build* hingga proses *deployment*/penggelaran.

- Pastikan data terserialisasi yang tidak ditanda-tangani atau tidak 
  terenkripsi ini tidak terkirim ke klien yang tidak dipercaya tanpa 
  adanya pengecekan integritas atau tanda tangan digital untuk mendeteksi 
  pengubahan atau pemutaran ulang data yang telah diserialisasi.

## Contoh Skenario Penyerangan

**Skenario #1 Pembaruan tanpa tanda tangan**: Banyak router rumahan, set top 
box, firmware perangkat, dan lainnya tidak memverifikasi pembaruan lewat 
firmware yang telah ditandatangani. Firmware yang tidak ditandatangani 
merupakan target yang semakin berkembang bagi penyerang dan diperkirakan akan 
semakin parah. Ini merupakan persoalan/ancaman yang cukup besar karena sering 
kali tidak ada mekanisme untuk remediasi selain memperbaikinya pada versi 
mendatang dan menunggu versi sebelumnya kedaluwarsa.

**Skenario #2 Pembaharuan berbahaya SolarWinds**: Nation-state telah diketahui
menyerang mekanisme pembaruan, dengan serangan terkini yang patut diperhatikan
adalah serangan SolarWinds Orion. Perusahaan yang mengembangkan perangkat lunak
tersebut memiliki proses build dan integritas pembaruan yang aman. Namun, ini
berhasil dibelokkan, dan selama beberapa bulan, perusahaan mendistribusikan
suatu pembaruan jahat yang sangat ditargetkan ke lebih dari 18.000 organisasi,
yang sekitar 100 di antaranya terdampak. Ini adalah satu dari pembobolan yang
paling merentang luas dan paling signifikan dari sifat ini dalam sejarah.

**Skenario #3 Deserialisasi Yang Tidak Aman**: Aplikasi React memanggil satu 
set layanan mikro Spring Boot. Sebagai programmer fungsional, mereka mencoba 
memastikan bahwa kode mereka tidak dapat diubah. Solusi yang mereka hasilkan 
adalah men-serial-kan keadaan pengguna dan meneruskannya bolak-balik dengan 
setiap permintaan. Seorang penyerang memperhatikan tanda tangan objek Java 
"rO0" (dalam base64), dan menggunakan alat Java Serial Killer untuk mendapatkan 
eksekusi kode jarak jauh pada server aplikasi.


## Referensi
- [OWASP Cheat Sheet: Software Supply Chain Security](Akan Segera Datang)
- [OWASP Cheat Sheet: Secure build and deployment](Akan Segera Datang)
- [OWASP Cheat Sheet: Infrastructure as Code](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)
- [OWASP Cheat Sheet: Deserialization](https://www.owasp.org/index.php/Deserialization_Cheat_Sheet)
- [SAFECode Software Integrity Controls](https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)
- [A 'Worst Nightmare' Cyberattack: The Untold Story Of The SolarWinds Hack](https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack)
- [CodeCov Bash Uploader Compromise](https://about.codecov.io/security-update)
- [Securing DevOps by Julien Vehent](https://www.manning.com/books/securing-devops)

## Daftar CWE yang Dipetakan
[CWE-345 Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)

[CWE-353 Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html)

[CWE-426 Untrusted Search Path](https://cwe.mitre.org/data/definitions/426.html)

[CWE-494 Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)

[CWE-502 Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

[CWE-565 Reliance on Cookies without Validation and Integrity Checking](https://cwe.mitre.org/data/definitions/565.html)

[CWE-784 Reliance on Cookies without Validation and Integrity Checking in a Security Decision](https://cwe.mitre.org/data/definitions/784.html)

[CWE-829 Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)

[CWE-830 Inclusion of Web Functionality from an Untrusted Source](https://cwe.mitre.org/data/definitions/830.html)

[CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
