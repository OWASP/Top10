# A09:2021 – Kegagalan Pemantauan dan Pencatatan Log Keamanan    ![icon](assets/TOP_10_Icons_Final_Security_Logging_and_Monitoring_Failures.png){: style="height:80px;width:80px" align="right"}

## Faktor-Faktor

| CWE Dipetakan | Tingkat Kejadian Maksimum | Rata-rata Tingkat kejadian | Rata-rata Eksploitasi Terbobot | Rata-rata Dampak Terbobot | Cakupan Maksimum | Rata-rata Cakupan | Total Kejadian | Total CVE |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 4           | 19,23%             | 6,51%              | 6,87                 | 4,99                | 53,67%       | 39,97%       | 53.615            | 242        |

## Ringkasan

Kegagalan Pemantauan dan Pencatatan Log Keamanan datang dari survey komunitas
Top 10 (#3), naik sedikit dari posisi ke-10 di dalam OWASP Top 10 2017. 
Pencatatan log dan pemantaun bisa sulit diuji, sering kali melibatkan 
wawancara atau bertanya apakah serangan telah terdeksi selama uji penetrasi. 
Tidak banyak data CVE/CVSS yang ada untuk kategori ini, tetapi mendeteksi dan 
merespon penjebolan sangatlah penting. Itu bisa sangat berdampak bagi 
akuntabilitas, visibilitas, peringatan insiden, dan forensik.
Kategori ini memperluas lebih dari *CWE-778 Insufficient Logging* dengan 
memasukan *CWE-117 Improper Output Neutralization for Logs*, *CWE-223 Omission 
of Security-relevant Information*, dan *CWE-532 Insertion of Sensitive 
Information into Log File*.

## Deskripsi

Kembali ke OWASP Top 10 2021, kategori ini membantu untuk mendeteksi, 
mengeskalasi, dan merespon terhadap penjebolan yang sedang aktif. Tanpa 
pencatatan log dan pemantauan, penjebolan tidak dapat dideteksi. Pencatatan
log, deteksi, pemantauan, dan respon aktif yang tidak memadai terjadi setiap
kali:

-   Kejadian yang dapat diaudit, seperti login, kegagalan login, dan transaksi 
    dengan nilai tinggi tidak dicatat.

-   Peringatan dan error tidak menghasilkan pencatatan, pencatatan yang tidak
    memadai, atau catatan pesan yang tidak jelas.

-   Log dari aplikasi dan API tidak dipantau untuk aktivitas mencurigakan.

-   Log hanya disimpan secara lokal.

-   Ambang batas peringatan yang sesuai dan proses eskalasi respon tidak siap 
    atau tidak efektif.

-   Alat uji penetrasi dan pemindaian dari dynamic application security 
    testing (DAST) (seperti OWASP ZAP) tidak memicu peringatan.

-   Aplikasi tidak dapat mendeteksi, mengeskalasi, atau memperingati adanya 
    serangan aktif seketika (real-time) atau hampir seketika (near real-time).

Anda sangatlah rentan terhadap kebocoran informasi dengan membuat kejadian 
pencatatan log dan peringatan terlihat kepada user atau bahkan penyerang 
(lihat [A01:2021 - Broken Access Control](A01_2021-Broken_Access_Control.id.md))

## Cara Mencegah

Pengembang harus mengimplementasikan beberapa atau semua kontrol dibawah ini
yang tergantung pada risiko dari aplikasi:

-   Pastikan semua kegagalan login, kontrol akses, dan validasi masukan
    sisi server dapat dicatat dengan konteks pengguna yang cukup untuk 
    mengidentifikasi akun yang mencurigakan atau jahat serta disimpan
    dalam waktu yang cukup untuk analisa forensik yang tertunda.

-   Pastikan semua log dihasilkan dalam format dimana 
    solusi manajemen log dapat dengan mudah memakainya.

-   Pastikan data log telah di-encode dengan benar untuk mencegah injeksi 
    atau serangan pada sistem pencatatan log atau pemantauan.

-   Pastikan transaksi nilai tinggi memiliki jejak audit dengan kontrol 
    integritas untuk mencegah gangguan dan penghapusan, 
    seperti database yang *append-only* atau yang serupa.

-   Tim DevSecOps harus membuat pemantauan dan pemberi peringatan yang
    efektif sehingga aktivitas mencurigakan terdeteksi dan direspon secara 
    cepat.

-   Membuat atau adopsi sebuah rencana respon insiden dan pemulihan, 
    seperti National Institute of Standards and Technology (NIST) 800-61r2 
    atau versi setelahnya.

Ada kerangka kerja proteksi aplikasi komersil dan open source seperti misalnya
OWASP ModSecurity Core Rule Set, dan perangkat lunak korelasi log open source,
seperti stack ELK, yang memiliki fitur dasbor dan pemberian peringatan yang
dapat disesuaikan.

## Contoh Skenario Penyerangan

**Skenario #1:** Operator situs web penyedia rencana kesehatan anak-anak 
tidak dapat mendeteksi penerobosan karena ketiadaan pemantauan dan pencatatan
log. Pihak luar menginformasikan kepada penyedia bahwa penyerang telah 
mengakses dan memodifikasi ribuan rekam medis yang sensitif dari 3.5 juta 
anak. Tinjauan pasca insiden telah menemukan bahwa pengembang situs web belum
mengatasi kerentanan yang signifikan. Karena tidak ada pencatatan log atau
pemantauan sistem, penjebolan data mungkin telah berlangsung sejak 2013, suatu
perioda lebih dari tujuh tahun.

**Skenario #2:** Sebuah perusahaan penerbangan India besar telah terbobol
selama lebih dari sepuluh tahun melibatkan data pribadi jutaan penumpang, 
termasuk paspor dan data kartu kredit. Pembobolan data terjadi pada 
penyedia hosting cloud pihak ketiga, yang memberitahu ke perusahaan penerbangan
tentang pembobolan setelah sekian lama.

**Skenario #3:** Sebuah perusahaan penerbangan Eropa besar mengalami kebobolan
GDPR yang dapat dilaporkan. Kebobolan tersebut dikabarkan disebabkan oleh 
kerentanan aplikasi keamanan pembayaran yang dieksploitasi oleh penyerang,
yang telah memanen lebih dari 400.000 rekam pembayaran pelanggan.
Perusahaan penerbangan tersebut telah didenda sebesar 20 juta pound sebagai
akibatnya oleh regulator privasi.

## Referensi

-   [OWASP Proactive Controls: Implement Logging and
    Monitoring](https://owasp.org/www-project-proactive-controls/v3/en/c9-security-logging.html)

-   [OWASP Application Security Verification Standard: V7 Logging and
    Monitoring](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: Testing for Detailed Error
    Code](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_for_Error_Code)

-   [OWASP Cheat Sheet:
    Application Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html)

-   [OWASP Cheat Sheet:
    Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

-   [Data Integrity: Recovering from Ransomware and Other Destructive
    Events](https://csrc.nist.gov/publications/detail/sp/1800-11/final)

-   [Data Integrity: Identifying and Protecting Assets Against
    Ransomware and Other Destructive
    Events](https://csrc.nist.gov/publications/detail/sp/1800-25/final)

-   [Data Integrity: Detecting and Responding to Ransomware and Other
    Destructive
    Events](https://csrc.nist.gov/publications/detail/sp/1800-26/final)

## Daftar CWE yang Dipetakan

[CWE-117 Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)

[CWE-223 Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)

[CWE-532 Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)

[CWE-778 Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)

