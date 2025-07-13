# A09:2021 – Kegagalan dalam Keamanan Logging dan Monitoring 

## Faktor-Faktor

| Klasifikasi CWE | Tingkat Kejadian Maksimum | Rata - Rata Tingkat kejadian | Cakupan Maksimum | Rata - Rata Cakupan | Rata-rata Bobot Eksploitasi | Rata - Rata Bobot Dampak | Total Kejadian | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 4           | 19.23%             | 6.51%              | 53.67%       | 39.97%       | 6.87                 | 4.99                | 53,615            | 242        |

## Tinjauan

Kegagalan dalam Keamanan Logging dan Monitoring datang dari survey industri (#3), naik 
sedikit dari posisi ke-10 di dalam OWASP top 10 2017. Mencatat dan memonitor dapat menjadi
sebuah kesulitan untuk melakukan testing, seringkali harus menggunakan tindakan seperti 
wawancara atau bertanya bila serangan telah terdeksi selama tes penetrasi. 
Dalam kategori ini juga tidak terlalu banyak data CVE/CVSS yang ada, 
tetapi dalam mendeteksi kemudian merespon dalam penjebolan sangatlah krusial.
visibilitas, peringatan insiden, dan forensik sangatlah berdampak pada hal tersebut. 
kategori ini memperluas *CWE-778 Insufficient Logging* dengan memasukan *CWE-117 Improper Output Neutralization
for Logs*, *CWE-223 Omission of Security-relevant Information*, dan *CWE-532 Insertion of Sensitive Information into Log File*.

## Deskripsi

Kembali ke OWASP Top 2021, Kategori ini membantu untuk mendeteksi, meningkatkan dan respon
terhadap penjebolan yang sedang aktif. Tanpa mencatat dan memonitor, penjebolan tidak
dapat dideteksi. Ketidakcukup melakukan log, deteksi, memonitor dan respon aktif terjadi setiap waktu:

-   Kejadian yang dapat di Audit, seperti login,
    kegagalan login dan transaksi dengan nilai yang tinggi tidak di catat.

-   Peringatan dan Error tidak menghasilkan pencatatan yang 
    memadai atau catatan pesan yang tidak jelas.

-   Log dari aplikasi dan API tidak di monitor untuk aktifitas mencurigakan.

-   Log hanya disimpan secara lokal.

-   Threshold peringatan yang sesuai dan proses dari respon eskalasi tidak efektif.

-   Tool Penetration testing dan Scan dari dynamic application security testing (DAST) (seperti OWASP ZAP) tidak memicu peringatan.

-   Aplikasi tidak dapat mendeteksi, mengeskalasi atau memperingati untuk serangan aktif
    di waktu sebenarnya(real-time) atau bahkan mendekati waktu sebenarnya.

Anda sangatlah rentan terhadap kebocoran data saat pencatatan dan peringatan kejadian
terlihat kepada user atau bahkan penyerang (lihat A01:2021 - Broken Access Control)

## Cara Mencegah

Pengembang harus mengimplementasikan beberapa atau semua kontrol dibawah ini
yang tergantung pada risiko dari aplikasi:

-   Pastikan semua kesalahan login, kontrol akses dan validasi input dari server-side
    dapat di catat dengan konteks pengguna yang cukup untuk mengidentifikasikan
    akun yang mencurigakan atau jahat serta catatan tersebut di simpan
    dengan waktu yang cukup untuk analisa forensik yang terlambat.

-   Pastikan semua catatan dihasilkan dalam format dimana 
    solusi pengelola catatan dapat dengan mudah digunakan.

-   Pastikan data catatan telah di encode dengan benar untuk 
    mencegah injeksi atau serangan pada pencatatan atau sistem monitor.  

-   Pastikan transaksi dengan nilai yang tinggi 
    memiliki jejak audit dengan kontrol integritas
    untuk mencegah gangguan dan penghapusan, 
    seperti hanya dapat ditambahkan ke database atau yang mirip seperti itu.

-   Tim DevSecOps harus membuat monitoring secara efektif dalam memonitor dan memperingati
    aktifitas mencurigakan yang terdeteksi dan merespon secara cepat.

-   Membuat atau adopsi sebuah respon insiden dan rencana pemulihan, 
    seperti NIST 800-61r2 atau versi atas nya.

There are commercial and open-source application protection frameworks
such as the OWASP ModSecurity Core Rule Set, and open-source log
correlation software, such as the ELK stack, that feature custom
dashboards and alerting.

## Contoh Skenario Penyerangan

**Skenario #1:** oeprator website Provider Rencana Kesehatan anak-anak 
tidak dapat mendeteksi penerobosan dikarenakan kurang nya dalam memonitor
dan mencatat. pihak luar menginformasikan kepada provider bahwa penyerang
memiliki akses dan telah memodifikasi ribuan rekam medis yang sensitif
dari 3.5 juta anak. tinjauan pasca insiden telah menemukan bahwa
pengembang website tidak menindak kerentanan yang signifikan. 
seperti disana tidak ada pencatatan atau pemonitoran dari sistem,
penjebolan data telah berperkembang dari tahun 2013, penjebolan
telah aktif lebih dari periode tujuh tahun.

**Skenario #2:** Sebuah perusahaan penerbangan india besar telah terbobol yang 
lebih dari 10 tahun melibatkan jutaan data penumpang. termasuk
passport dan data kartu kredit. Pembobolan data terjadi saat
third party cloud dari hosting provider, tidak menotifikasi
bahwa sistem penerbangan tersebut telah di bobol untuk beberapa waktu.

**Skenario #3:** Sebuah perusahaan penerbangan eropa besar menderita sebuah kebobolan
laporan GDPR yang dapat dilaporkan. Kebobolan tersebut telah dikabrkan
dikarenakan oleh kerentanan aplikasi keamanan pembayaran di eksploitasi
penyerang yang telah memanen lebih dari 400.000 rekam pembayaran pelanggan.
perushaan penerbangan tersebut telah di denda sebesar 20 juta pound 
sehingga menghasilkan pengatur privacy.

## Referensi

-   [OWASP kontrol proaktif OWASP Proactive Controls: Mengimplementasi 
    Pencatatan dan Pemonitoran](https://owasp.org/www-project-proactive-controls/v3/en/c9-security-logging.html)

-   [OWASP standart verifikasi keamanan: Pencatatan V8 dan 
    Pemonitoran](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Panduan melakukan Tes: Tes untuk code Error yang 
    mendetil ](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_for_Error_Code)

-   [OWASP Cheat Sheet:
    Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

-   [Integritas Data: Pemulihan dari ransomware dan peristiwa 
    destruktif](https://csrc.nist.gov/publications/detail/sp/1800-11/final)

-   [Integritas Data: Identifikasi dan melindungi asset dari 
    ransomware dan hal peristiwa destruktif
    lainnya](https://csrc.nist.gov/publications/detail/sp/1800-25/final)

-   [Integritas Data: Mendeteksi dan Merespon untuk ransomware dan peristiwa 
    destruktif lainnya](https://csrc.nist.gov/publications/detail/sp/1800-26/final)

## Daftar Klasifikasi CWE

CWE-117 Improper Output Neutralization for Logs

CWE-223 Omission of Security-relevant Information

CWE-532 Insertion of Sensitive Information into Log File

CWE-778 Insufficient Logging
