# A05:2021 – Kesalahan Konfigurasi Keamanan 

## Faktor - Faktor

| Klasifikasi CWE | Tingkat Kejadian Maksimum | Rata-rata Tingkat Kejadian | Cakupan Maksimum | Rata-rata Cakupan | Rata-rata Bobot Exploitasi | Rata-rata Bobot Dampak | Total Kejadian| Total CVEs |
| :---------: | :----------------: | :----------------------: | :----------: | :----------------: | :------------------------: | :-----------------------: | :------------: | :--------: |
|     20      |       19.84%       |          4.51%           |    89.58%    |       44.84%       |            8.12            |           6.56            |    208,387     |    789     |

## Gambaran

Bergerak dari posisi ke 6 pada edisi sebelumnya, 90% aplikasi dilakukan pengecekan untuk sebuah bentuk dari miskonfigurasi. Dengan bergeraknya kearah software yang memiliki konfigurasi yang tinggi, maka tidak mengejutkan melihat kategori ini naik untuk posisinya. CWE (Common Weakness Enumeration) atau kelemahan enumerasi umum yang perlu diperhatikan termasuk dari _CWE-16 Configuration_ and _CWE-611 Improper Restriction of XML External Entity Reference_.

## Deskripsi

Aplikasi dapat dikatakan rentan apabila aplikasi tersebut :

- Tidak memiliki pertahanan yang sesuai atau security hardening yang diperlukan diseluruh bagian dari stack aplikasi atau tidak benar dalam melakukan konfigurasi untuk permission pada cloud services.

- Fitur - fitur yang tidak digunakan masih di enable atau diinstall (contoh seperti port, services, pages, accounts, atau privileges yang tidak dipakai)

- Akun default dan passwordnya masih di bolehkan dan tidak pernah diubah.

- Cara menghandle error memperlihatkan stack traces atau pesan lainnya yang terlalu informatif kepada user

- Untuk sistem yang telah diupdate, fitur security terbaru tidak digunakan atau belum dikonfigurasi.

- Pengaturan security pada server aplikasi, framework aplikasi (contoh Struts, Spring, ASP.NET), libraries, databases, dll, tidak diatur dengan secure values.

- Server tidak mengirim security header atau directives, atau tidak diatur dengan secure values.

- Software bersifat lama atau rentan (lihat A06:2021-Vulnerable and Outdated Components).

Tanpa proses konfigurasi keamanan aplikasi yang berulang dan terpadu, sistem berada dalam resiko yang tinggi.

## Cara untuk mencegah

Proses instalasi yang aman harus diimplementasikan, termasuk :

- Proses hardening yang dapat diulang akan mempercepat dan memudahkan untuk membuat untuk melakukan deploy ke environment lainnya yang dikunci dengan tepat. Development, QA, dan production environment harus dikonfigurasi secara identik, dengan credentials yang berbeda digunakan pada setiap environment. Proses ini harus di automasi untuk meminimalisir usaha yang diperlukan untuk mengatur environment baru yang aman.

- Platform minimal tanpa fitur, komponen, dokumentasi, dan sampel yang tidak diperlukan. Hapus atau jangan install fitur dan framework yang tidak digunakan.

- Sebuah tugas (task) untuk meninjau dan memperbarui konfigurasi yang sesuai untuk ke semua security notes, updates, dan patches sebagai bagian dari proses patch management (lihat A06:2021-Vulnerable and Outdated Components). Review cloud storage permissions (contoh, S3 bucket permissions).

- Sebuah arsitektur aplikasi yang tersegmentasi yang memberikan efektif dan pemisahan yang aman diantara komponen atau tenant, dengan segmentasi, containerization, atau cloud security groups (ACLs).

- Mengirim security directives ke clients, contoh Security Headers.

- Sebuah proses automasi untuk memverifikasi keefektifan dari konfigurasi dan setting di semua environments.

## Contoh Skenario Penyerangan

**Skenario #1:** Server Aplikasi datang dengan sampel aplikasi yang tidak dihapus dari server production. Sampel Aplikasi tersebut memiliki kelemahan keamanan yang dapat mengkompromi servernya. Misal salah satu aplikasi merupakan admin console dan default dari akun belum diganti. Maka penyerang dapat login dengan default password dan masuk.

**Skenario #2:** Direktori listing tidak di nonaktifkan di server. Sebuah penyerang menemukan bahwa mereka dapat melihat list direktori. Penyerang menemukan dan mendownload compiled Java classes, yang dimana mereka akan lakukan decompile dan reverse engineer untuk melihat kodenya. Setelah itu penyerang menemukan kelemahan fatal untuk akses kontrol pada aplikasi.

**Skenario #3:** Konfigurasi server aplikasi membolehkan error message yang detail, seperti stack traces, untuk ditampilkan kepada user. Hal tersebut dapat berpotensi untuk memberikan informasi yang bersifat sensitif atau kelemahan mendasar seperti versi komponen yang diketahui kelemahannya.

**Skenario #4:** Sebuah cloud service provider memiliki permission default open untuk sharing ke internet pada pengguna CSP lainnya. Ini memungkinkan untuk data sensitif yang disimpan pada cloud storage untuk diakses

## Referensi

- [OWASP Testing Guide: Configuration
  Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)

- OWASP Testing Guide: Testing for Error Codes

- Application Security Verification Standard V19 Configuration

- [NIST Guide to General Server
  Hardening](https://csrc.nist.gov/publications/detail/sp/800-123/final)

- [CIS Security Configuration
  Guides/Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

- [Amazon S3 Bucket Discovery and
  Enumeration](https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html)

## Daftar Klasifikasi CWE

CWE-2 Configuration

CWE-11 ASP.NET Misconfiguration: Creating Debug Binary

CWE-13 ASP.NET Misconfiguration: Password in Configuration File

CWE-15 External Control of System or Configuration Setting

CWE-16 Configuration

CWE-260 Password in Configuration File

CWE-315 Cleartext Storage of Sensitive Information in a Cookie

CWE-520 .NET Misconfiguration: Use of Impersonation

CWE-526 Exposure of Sensitive Information Through Environmental
Variables

CWE-537 Java Runtime Error Message Containing Sensitive Information

CWE-541 Inclusion of Sensitive Information in an Include File

CWE-547 Use of Hard-coded, Security-relevant Constants

CWE-611 Improper Restriction of XML External Entity Reference

CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute

CWE-756 Missing Custom Error Page

CWE-776 Improper Restriction of Recursive Entity References in DTDs
('XML Entity Expansion')

CWE-942 Overly Permissive Cross-domain Whitelist

CWE-1004 Sensitive Cookie Without 'HttpOnly' Flag

CWE-1032 OWASP Top Ten 2017 Category A6 - Security Misconfiguration

CWE-1174 ASP.NET Misconfiguration: Improper Model Validation
