# A05:2021 – Kesalahan Konfigurasi Keamanan    ![icon](assets/TOP_10_Icons_Final_Security_Misconfiguration.png){: style="height:80px;width:80px" align="right"}

## Faktor - Faktor

| CWE Dipetakan | Tingkat Kejadian Maksimum | Rata-rata Tingkat Kejadian | Rata-rata Exploitasi Terbobot | Rata-rata Dampak Terbobot | Cakupan Maksimum | Rata-rata Cakupan | Total Kejadian | Total CVE |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 20          | 19,84%             | 4,51%              | 8,12                 | 6,56                | 89,58%       | 44,84%       | 208.387           | 789        |

## Gambaran

Bergerak dari posisi ke 6 pada edisi sebelumnya, 90% aplikasi dilakukan pengecekan untuk sebuah bentuk dari miskonfigurasi. Dengan bergeraknya ke arah software yang sangat bisa dikonfigurasi, maka tidak mengejutkan melihat kategori ini naik untuk posisinya. CWE (Common Weakness Enumeration) atau kelemahan enumerasi umum yang perlu diperhatikan termasuk dari *CWE-16 Configuration* dan *CWE-611 Improper Restriction of XML External Entity Reference*.

## Deskripsi

Aplikasi dapat dikatakan rentan apabila aplikasi tersebut:

- Kurangnya security hardening yang sesuai di seluruh bagian dari stack 
  aplikasi atau tidak benar dalam melakukan konfigurasi untuk izin pada 
  layanan cloud.

- Fitur-fitur yang tidak digunakan masih difungsikan atau dipasang (mis. 
  seperti port, layanan, halaman, akun, atau privilege yang tidak dipakai).

- Akun default dan kata sandinya masih difungsikan dan tidak pernah diubah.

- Penanganan kesalahan mengungkap stack trace atau pesan lainnya yang 
  terlalu informatif kepada user.

- Untuk sistem yang ditingkatkan, fitur keamanan terbaru dinon-aktifkan atau 
  tidak dikonfigurasi secara aman.

- Pengaturan keamanan pada server aplikasi, framework aplikasi (mis. Struts, 
  Spring, ASP.NET), pustaka, basis data, dll, tidak diisi dengan nilai-nilai
  yang aman.

- Server tidak mengirim header atau direktif keamanan, atau tidak diisi 
  dengan nilai-nilai aman.

- Perangkat lunak kedaluwarsa atau rentan (lihat [A06:2021-Vulnerable and 
  Outdated Components](A06_2021-Vulnerable_and_Outdated_Components.id.md)).


Tanpa proses konfigurasi keamanan aplikasi yang dapat diulang dan terpadu, 
sistem berada dalam resiko yang lebih tinggi.

## Cara untuk mencegah

Proses instalasi yang aman harus diimplementasikan, termasuk:

- Proses hardening yang dapat diulang akan mempercepat dan memudahkan untuk membuat untuk melakukan deploy ke environment lainnya yang dikunci dengan tepat. Development, QA, dan production environment harus dikonfigurasi secara identik, dengan kredential yang berbeda digunakan pada setiap environment. Proses ini harus diotomasi untuk meminimalisir usaha yang diperlukan untuk mengatur environment baru yang aman.

- Platform minimal tanpa fitur, komponen, dokumentasi, dan sampel yang tidak diperlukan. Hapus atau jangan pasang fitur dan framework yang tidak digunakan.

- Sebuah tugas (task) untuk meninjau dan memperbarui konfigurasi yang sesuai untuk ke semua security notes, updates, dan patches sebagai bagian dari proses patch management (lihat [A06:2021-Vulnerable and Outdated Components](A06_2021-Vulnerable_and_Outdated_Components.id.md)). Tinjau izin cloud storage (contoh, izin S3 bucket).

- Sebuah arsitektur aplikasi yang tersegmentasi yang memberikan pemisahan yang efektif dan aman diantara komponen atau tenant, dengan segmentasi, containerization, atau cloud security groups (ACLs).

- Mengirim security directive ke client, contoh Security Header.

- Sebuah proses automasi untuk memverifikasi keefektifan dari konfigurasi dan setting di semua environments.

## Contoh Skenario Penyerangan

**Skenario #1:** Server aplikasi datang dengan sampel aplikasi yang tidak dihapus dari server production. Sampel aplikasi tersebut memiliki kelemahan keamanan yang dapat mengkompromi servernya. Misal salah satu aplikasi merupakan admin console dan default dari akun belum diganti. Maka penyerang dapat login dengan default password dan masuk.

**Skenario #2:** Direktori listing tidak di nonaktifkan di server. Seorang penyerang menemukan bahwa mereka dapat melihat list direktori. Penyerang menemukan dan mengunduh compiled Java class, dimana mereka akan lakukan decompile dan reverse engineer untuk melihat kodenya. Setelah itu penyerang menemukan kelemahan fatal untuk akses kontrol pada aplikasi.

**Skenario #3:** Konfigurasi server aplikasi membolehkan error message yang detail, seperti stack trace, untuk ditampilkan kepada user. Hal tersebut dapat berpotensi untuk memberikan informasi yang bersifat sensitif atau kelemahan mendasar seperti versi komponen yang diketahui kelemahannya.

**Skenario #4:** Sebuah cloud service provider memiliki permission default open untuk sharing ke internet pada pengguna CSP lainnya. Ini memungkinkan untuk data sensitif yang disimpan pada cloud storage untuk diakses

## Referensi

-   [OWASP Testing Guide: Configuration
    Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)

-   [OWASP Testing Guide: Testing for Error Codes](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)

-   [Application Security Verification Standard V14 Configuration](https://github.com/OWASP/ASVS/blob/master/4.0/en/0x22-V14-Config.md)

-   [NIST Guide to General Server
    Hardening](https://csrc.nist.gov/publications/detail/sp/800-123/final)

-   [CIS Security Configuration
    Guides/Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

-   [Amazon S3 Bucket Discovery and
    Enumeration](https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html)

## Daftar CWE Dipetakan

[CWE-2 7PK - Environment](https://cwe.mitre.org/data/definitions/2.html)

[CWE-11 ASP.NET Misconfiguration: Creating Debug Binary](https://cwe.mitre.org/data/definitions/11.html)

[CWE-13 ASP.NET Misconfiguration: Password in Configuration File](https://cwe.mitre.org/data/definitions/13.html)

[CWE-15 External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html)

[CWE-16 Configuration](https://cwe.mitre.org/data/definitions/16.html)

[CWE-260 Password in Configuration File](https://cwe.mitre.org/data/definitions/260.html)

[CWE-315 Cleartext Storage of Sensitive Information in a Cookie](https://cwe.mitre.org/data/definitions/315.html)

[CWE-520 .NET Misconfiguration: Use of Impersonation](https://cwe.mitre.org/data/definitions/520.html)

[CWE-526 Exposure of Sensitive Information Through Environmental Variables](https://cwe.mitre.org/data/definitions/526.html)

[CWE-537 Java Runtime Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/537.html)

[CWE-541 Inclusion of Sensitive Information in an Include File](https://cwe.mitre.org/data/definitions/541.html)

[CWE-547 Use of Hard-coded, Security-relevant Constants](https://cwe.mitre.org/data/definitions/547.html)

[CWE-611 Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)

[CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html)

[CWE-756 Missing Custom Error Page](https://cwe.mitre.org/data/definitions/756.html)

[CWE-776 Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')](https://cwe.mitre.org/data/definitions/776.html)

[CWE-942 Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html)

[CWE-1004 Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)

[CWE-1032 OWASP Top Ten 2017 Category A6 - Security Misconfiguration](https://cwe.mitre.org/data/definitions/1032.html)

[CWE-1174 ASP.NET Misconfiguration: Improper Model Validation](https://cwe.mitre.org/data/definitions/1174.html)

