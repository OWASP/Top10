# A06:2021 – Komponen yang Rentan dan Kadaluwarsa

## Faktor

| Klasifikasi CWE | Tingkat Kejadian Maksimum | Rata - Rata Tingkat kejadian | Cakupan Maksimum | Rata - Rata Cakupan | Rata-rata Bobot Eksploitasi | Rata - Rata Bobot Dampak | Total Kejadian | Total CVE |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 3           | 27.96%             | 8.77%              | 51.78%       | 22.47%       | 5.00                 | 5.00                | 30,457            | 0          |

## Ikhtisar

Sebelumnya #2 dari survei industri tetapi juga memiliki data yang cukup untuk membuat
Top 10 melalui data. Komponen yang rentan adalah masalah umum yang kami
perjuangkan untuk menguji dan menilai risiko dan merupakan satu-satunya kategori yang tidak memiliki CVE yang dipetakan ke CWE yang disertakan, jadi bawaan eksploitasi/dampak 5.0 yang digunakan. CWE terkenal yang disertakan adalah *CWE-1104: Penggunaan
Komponen Pihak Ketiga yang Tidak Dikelola* dan dua CWE dari Top 10 2013
dan 2017.

## Deskripsi 

Anda kemungkinan besar rentan:

-   Jika Anda tidak mengetahui versi semua komponen yang Anda gunakan ( sisi
    klien dan sisi server). Ini termasuk komponen yang secara langsung
    anda gunakan serta dependensi bersarang.

-   Jika perangkat lunak rentan, tidak didukung, atau ketinggalan zaman. Ini
    termasuk OS, server web/aplikasi, sistem manajemen basis data
    (DBMS), aplikasi, API dan semua komponen, lingkungan runtime,
    dan pustaka.

-   Jika Anda tidak memindai kerentanan secara teratur dan berlangganan
    buletin keamanan yang terkait dengan komponen yang anda gunakan.

-   Jika Anda tidak memperbaiki atau meningkatkan platform, kerangka kerja,
    dan dependensi yang mendasarinya secara tepat waktu dan berbasis risiko. 
    Ini biasanya terjadi di lingkungan ketika sedang menambal tugas bulanan atau triwulanan dibawah kendali perubahan, membiarkan organisasi terbuka selama berhari-hari atau berbulan bulan terpapar kerentanan tetap yang tidak perlu.

-   Jika pengembang perangkat lunak tidak menguji kompatibilitas yang diperbarui,
    perpustakaan yang ditingkatkan, atau ditambal.

-   Jika anda tidak mengamankan konfigurasi komponen (lihat
    A05:2021-Security Misconfiguration).

## Cara Mencegah

Harus ada proses manajemen patch untuk: 

-   Menghapus dependensi, fitur, komponen, file,
    dan dokumentasi yang tidak digunakan.

-   Inventarisasi komponen versi klien dan sisi server secara terus menerus
    (misalnya, kerangka kerja, pustaka) dan dependensinya menggunakan alat seperti versi, Pemeriksaan Dependesi OWASP, retire.js, dll. Memantau secara terus menerus sumber seperti CVE dan NVD untuk memeriksan kerentanan dalam komponen. Gunakan alat untuk mengotomatisasi proses analisis komposisi perangkat lunak.
    Berlangganan terhadap peringatan email untuk kerentanan keamanan yang terkait dengan komponen yang Anda gunakan.

-   Hanya dapatkan komponen dari sumber resmi melalui tautan yang aman.
    Pilih paket yang ditandatangani untuk mengurangi kemungkinan menyertakan komponen berbahaya yang dimodifikasi (Lihat A08:2021-Software and Data Integrity
    Failures).

-   Memantau pustaka dan komponen yang tidak dirawat atau tidak
    membuat patch keamanan untuk versi yang lebih lama. Jika tambalan tidak
    memungkinkan, pertimbangkan untuk menggunakan tambalan virtual untuk memantau, mendeteksi, atau melindungi dari masalah yang ditemukan.

Setiap organisasi harus memastikan rencana berkelanjutan untuk memantau, melakukan triase, dan menerapkan pembaruan atau perubahan konfigurasi selama masa pakai
aplikasi atau portofolio.

## Contoh Skenario Serangan 

**Skenario #1:** Komponen biasanya berjalan dengan hak istimewa yang sama seperti
aplikasi itu sendiri, sehingga cacat pada komponen apa pun dapat mengakibatkan dampak yanh serius. Jadi cacat tersebut dapat terjadi secara tidak sengaja (misalnya, kesalahan pengkodean) atau disengaja (misalnya, pintu belakang dalam suatu komponen). Beberapa contoh kerentanan komponen yang dapat dieksploitasi yang ditemukan adalah:

-   CVE-2017-5638, kerentanan eksekusi kode jarak jauh Struts 2 yang
    memungkinkan eksekusi kode arbitrer di server, telah
    disalahkan atas pelanggaran yang signifikan.

-   Sementara internet of things (IoT) seringkali sangat sulit untuk ditambal, 
    Penting menambalnya bisa sangat bagus.
    (Misal, perangkat biomedis).

Ada alat otomatis untuk membantu penyerang menemukan sesuatu yang belum ditambal atau
sistem yang salah konfigurasi. Misalnya, mesin pencari Shodan IoT dapat
membantu Anda menemukan perangkat yang masih mengalami kerentanan Heartbleed yang
ditambal pada April 2014.

## Referensi

-   OWASP Application Security Verification Standard: V1 Architecture,
    design and threat modelling

-   OWASP Dependency Check (for Java and .NET libraries)

-   OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)

-   OWASP Virtual Patching Best Practices

-   The Unfortunate Reality of Insecure Libraries

-   MITRE Common Vulnerabilities and Exposures (CVE) search

-   National Vulnerability Database (NVD)

-   Retire.js for detecting known vulnerable JavaScript libraries

-   Node Libraries Security Advisories

-   [Ruby Libraries Security Advisory Database and Tools]()

-   https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf

## Daftar Klasifikasi CWE

CWE-937 OWASP Top 10 2013: Using Components with Known Vulnerabilities

CWE-1035 2017 Top 10 A9: Using Components with Known Vulnerabilities

CWE-1104 Use of Unmaintained Third Party Components
