# A06:2021 – Komponen yang Rentan dan Kedaluwarsa

## Faktor-Faktor

| Klasifikasi CWE | Tingkat Kejadian Maksimum | Rata-rata Tingkat kejadian | Cakupan Maksimum | Rata-rata Cakupan | Rata-rata Bobot Eksploitasi | Rata-rata Bobot Dampak | Total Kejadian | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 3           | 27.96%             | 8.77%              | 51.78%       | 22.47%       | 5.00                 | 5.00                | 30,457            | 0          |

## Ikhtisar

Sebelumnya #2 dari survei komunitas Top 10 tetapi juga memiliki data yang cukup untuk membuat Top 10 melalui data. Komponen yang rentan adalah masalah umum yang kami 'struggle' untuk menguji dan menilai risiko dan merupakan satu-satunya kategori yang tidak memiliki CWE yang dipetakan ke CWE yang disertakan, jadi bobot baku eksploitasi/dampak 5.0 digunakan. CWE terkenal yang disertakan adalah *CWE-1104: Penggunaan Komponen Pihak Ketiga yang Tidak Dikelola* dan dua CWE dari Top 10 2013 dan 2017.

## Deskripsi 

Anda kemungkinan besar rentan:

-   Jika Anda tidak mengetahui versi semua komponen yang Anda gunakan (sisi klien dan sisi server). Ini termasuk komponen yang secara langsung Anda gunakan serta dependensi bersarang.
-   Jika perangkat lunak rentan, tidak didukung, atau ketinggalan zaman. Ini termasuk OS, server web/aplikasi, sistem manajemen basis data (DBMS), aplikasi, API dan semua komponen, lingkungan runtime, dan pustaka.
-   Jika Anda tidak memindai kerentanan secara teratur dan berlangganan buletin keamanan yang terkait dengan komponen yang Anda gunakan.
-   Jika Anda tidak memperbaiki atau meningkatkan platform, kerangka kerja, dan dependensi yang mendasarinya secara tepat waktu dan berbasis risiko. Ini biasanya terjadi di lingkungan ketika patch adalah tugas bulanan atau triwulanan dibawah kendali perubahan, membiarkan organisasi terbuka selama berhari-hari atau berbulan-bulan terpapar secara tidak perlu atas kerentanan-kerentangan yang telah diperbaiki.
-   Jika pengembang perangkat lunak tidak menguji kompatibilitas pustaka-pustaka yang diperbarui, ditingkatkan, atau di-patch.
-   Jika Anda tidak mengamankan konfigurasi komponen (lihat A05:2021-Security Misconfiguration).

## Cara Mencegah

Harus ada proses manajemen patch untuk: 

-   Menghapus dependensi, fitur, komponen, file, dan dokumentasi yang tidak digunakan.
-   Inventarisasi versi komponen sisi klien dan sisi server secara terus menerus (mis., kerangka kerja, pustaka) dan dependensinya menggunakan alat seperti versi, OWASP Dependency Check, retire.js, dll. Memantau secara terus menerus sumber-sumber seperti Common Vulnerability and Exposures (CVE) dan National Vulnerability Database (NVD) untuk  kerentanan dalam komponen. Gunakan alat analisis komposisi perangkat lunak untuk mengotomatisasi proses. Berlangganan email peringatan untuk kerentanan keamanan yang terkait dengan komponen yang Anda gunakan.
-   Hanya dapatkan komponen dari sumber resmi melalui tautan yang aman. Pilih paket yang ditandatangani untuk mengurangi kemungkinan menyertakan komponen berbahaya yang dimodifikasi (Lihat A08:2021-Software and Data Integrity Failures).
-   Memantau pustaka dan komponen yang tidak dirawat atau tidak membuat patch keamanan untuk versi yang lebih lama. Jika tambalan tidak memungkinkan, pertimbangkan untuk menggunakan tambalan virtual untuk memantau, mendeteksi, atau melindungi dari masalah yang ditemukan.

Setiap organisasi harus memastikan rencana berkelanjutan untuk memantau, melakukan triase, dan menerapkan pembaruan atau perubahan konfigurasi selama masa pakai aplikasi atau portofolio.

## Contoh Skenario Serangan 

**Skenario #1:** Komponen biasanya berjalan dengan hak istimewa yang sama seperti aplikasi itu sendiri, sehingga cacat pada komponen apa pun dapat mengakibatkan dampak yang serius. Jadi cacat tersebut dapat terjadi secara tidak sengaja (mis., kesalahan pengkodean) atau disengaja (mis., pintu belakang dalam suatu komponen). Beberapa contoh kerentanan komponen yang dapat dieksploitasi yang ditemukan adalah:

-   CVE-2017-5638, kerentanan eksekusi kode jarak jauh Struts 2 yang memungkinkan eksekusi kode sembarang di server, telah disalahkan atas pembobolan-pembobolan yang signifikan.
-   Sementara internet of things (IoT) seringkali sangat sulit untuk ditambal, pentingnya menambal bisa sangat besar (mis., perangkat biomedis).

Ada alat otomatis untuk membantu penyerang menemukan sesuatu yang belum ditambal atau sistem yang salah konfigurasi. Misalnya, mesin pencari Shodan IoT dapat membantu Anda menemukan perangkat yang masih mengalami kerentanan Heartbleed yang ditambal pada April 2014.

## Referensi

-   OWASP Application Security Verification Standard: V1 Architecture, design and threat modelling
-   OWASP Dependency Check (for Java and .NET libraries)
-   OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)
-   OWASP Virtual Patching Best Practices
-   The Unfortunate Reality of Insecure Libraries
-   MITRE Common Vulnerabilities and Exposures (CVE) search
-   National Vulnerability Database (NVD)
-   Retire.js for detecting known vulnerable JavaScript libraries
-   Node Libraries Security Advisories
-   [Ruby Libraries Security Advisory Database and Tools]
-   https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf

## Daftar Klasifikasi CWE

CWE-937 OWASP Top 10 2013: Using Components with Known Vulnerabilities

CWE-1035 2017 Top 10 A9: Using Components with Known Vulnerabilities

CWE-1104 Use of Unmaintained Third Party Components
