# Risiko - Risiko Keamanan Aplikasi

## Apa Saja Risiko Keamanan Aplikasi??

Penyerang berpotensi menggunakan beragam cara melalui aplikasi Anda untuk membahayakan bisnis atau organisasi Anda. Setiap cara mewakili risiko, yang mungkin, cukup serius untuk memperoleh perhatian.

![App Security Risks](images/0x10-risk-1.png)

Terkadang cara ini mudah ditemukan dan dieksploitasi, namun kadang-kadang sulit. Demikian juga, kerusakan yang diakibatkan
dapat berkisar dari tidak ada apa-apa hingga membuat Anda keluar dari bisnis. Untuk menentukan risiko di organisasi Anda, Anda
dapat mengevaluasi kemungkinan yang diasosiasikan untuk setiap agen ancaman, vektor serangan, kelemahan keamanan, dan
mengkombinasikan dengan estimasi dampak teknis dan bisnis bagi organisasi Anda. Semua faktor ini menentukan risiko
keseluruhan.

## Apa Risiko Saya?

[OWASP Top 10](https://owasp.org/www-project-top-ten/) ini berfokus pada identifikasi risiko yang paling serius bagi sebagian besar organisasi. Untuk setiap risiko, kami memberikan informasi umum mengenai kemungkiinan dan dampak teknis dengan menggunakan skema penilaian sederhana berikut, yang berdasarkan pada  OWASP Risk Rating Methodology.  

| Agen Ancaman| Vektor Serangan | Keberadaan kelemahan| Deteksi Kelemahan | Dampak Teknis | Dampak Bisnis |
| -- | -- | -- | -- | -- | -- |
| Appli-   | Mudah 3 | Tersebar 3 | Mudah 3 | Parah 3 | Bisnis    |
| kasi   | Menengah 2 | Umum 2 | Rata - rata 2 | Sedang 2 | Spesifik |
| Spesifik | Sulit 1 | Tidak Umum 1 | Sulit 1 | Rendah 1 |       |


Pada Edisi ini, kami telah memperbaharui Penilaian Risiko Sistem untuk membantu dalam menghitung kemungkinan dan dampak dari risiko tertentu. Untuk Lebih Detail, Lihat pada [Catatan tentang Risiko](0xc0-note-about-risks.md). 

Setiap organisasi itu unik, begitu pula aktor ancaman untuk organisasi tersebut, tujuan mereka, dan dampak dari setiap pelanggaran. Jika organisasi kepentingan publik menggunakan sistem manajemen konten (CMS) untuk informasi publik dan sistem kesehatan menggunakan CMS yang sama persis untuk catatan kesehatan yang sensitif, pelaku ancaman dan dampak bisnis dapat sangat berbeda untuk perangkat lunak yang sama. Penting untuk memahami risiko organisasi Anda berdasarkan pada agen ancaman dan dampak bisnis yang berlaku.

Bila memungkinkan, nama risiko di Top 10 sesuai dengan [Common Weakness Enumeration](https://cwe.mitre.org/) (CWE) kelemahan untuk mempromosikan konvensi penamaan yang berlaku umum dan untuk mengurangi kekeliruan.

## Referensi

### OWASP

* [OWASP Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology)
* [Article on Threat/Risk Modeling](https://owasp.org/www-community/Threat_Modeling)

### Eksternal

* [ISO 31000: Risk Management Std](https://www.iso.org/iso-31000-risk-management.html)
* [ISO 27001: ISMS](https://www.iso.org/isoiec-27001-information-security.html)
* [NIST Cyber Framework (US)](https://www.nist.gov/cyberframework)
* [ASD Strategic Mitigations (AU)](https://www.asd.gov.au/infosec/mitigationstrategies.htm)
* [NIST CVSS 3.0](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator)
* [Microsoft Threat Modelling Tool](https://www.microsoft.com/en-us/download/details.aspx?id=49168)
