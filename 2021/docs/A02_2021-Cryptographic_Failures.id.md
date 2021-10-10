# A02:2021 – Kegagalan Kriptografi

## Faktor

| Klasifikasi CWE | Tingkat Kejadian Maksimum | Rata - Rata Tingkat kejadian | Cakupan Maksimum | Rata - Rata Cakupan | Rata-rata Bobot Eksploitasi | Rata - Rata Bobot Dampak | Total Kejadian | Total CVE |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 29          | 46.44%             | 4.49%              | 79.33%       | 34.85%       | 7.29                 | 6.81                | 233,788           | 3,075      |

## Ikhtisar

Bergeser satu posisi ke #2, sebelumnya dikenal sebagai *Sensitif Data
Exposure*, yang lebih merupakan gejala yang luas daripada akar penyebab,
fokusnya adalah kegagalan yang terkait dengan kriptografi (atau ketiadaannya),
yang sering menyebabkan paparan data sensitif. CWE terkenal yang disertakan
adalah *CWE-259: Use of Hard-coded Password*, *CWE-327: Broken or Risky
Crypto Algorithm*, dan *CWE-331 Insufficient Entropy* .

## Deskripsi

Hal pertama adalah menentukan kebutuhan perlindungan data dalam perjalanan
dan pada saat istirahat. Misalnya, kata sandi, nomor kartu kredit, catatan kesehatan, informasi pribadi, dan rahasia bisnis yang memerlukan ekstra
perlindungan, terutama jika data tersebut termasuk dalam undang-undang privasi, misalnya, EU's General Data Protection Regulation (GDPR), atau peraturan, misalnya,
perlindungan data keuangan seperti PCI Data Security Standard (PCI DSS).
Untuk semua data tersebut:

-   Apakah ada data yang dikirimkan dalam bentuk teks yang jelas? 
    ini menyangkut protokol seperti 
    HTTP, SMTP, and FTP. Lalu lintas internet luar yang berbahaya.
    Verifikasi semua lalu lintas yang ada di internal, misalnya antara penyeimbang beban,web server, atau sistem back-end.

-   Apakah ada algoritma kriptografi lama atau lemah yang digunakan baik secara default
    atau dalam kode yang lebih lama?

-   Apakah kunci kripto bawaan sedang digunakan, 
    kunci kripto yang lemah dihasilkan atau digunakan kembali, 
    atau apakah manajemen atau rotasi kunci yang tepat hilang?

-   Apakah enkripsi tidak diterapkan, misalnya, apakah ada agen pengguna (browser) 
    yang arahan atau header keamanan hilang?

-   Apakah agen pengguna (misalnya, aplikasi, klien email) tidak memverifikasi jika
    sertifikat yang diterima server valid?

Lihat ASVS Crypto (V7), Data Protection (V9), dan SSL/TLS (V10)

## Cara Mengatasi

Lakukan minimal hal berikut, dan lihat referensi: 

-   Mengklasifikasikan data yang diproses, disimpan, atau dikirim oleh aplikasi .
    Identifikasi data mana yang sensitif menurut undang-undang privasi,
    persyaratan peraturan, atau kebutuhan bisnis.

-   Tetapkan kontrol sesuai klasifikasi.

-   Jangan menyimpan data sensitif yang tidak perlu. Buang sesegera
    mungkin atau gunakan tokenisasi yang sesuai dengan PCI DSS atau bahkan pemotongan.
    Data yang tidak disimpan tidak dapat dicuri.

-   Pastikan untuk mengenkripsi semua data sensitif saat istirahat.

-   Pastikan gunakan standar algoritma, protokol yang mutakhir dan kuat, serta 
    kunci berada pada tempatnya; menggunakan manajemen kunci yang tepat.

-   Enkripsi semua data dalam perjalanan dengan protokol aman seperti TLS dengan
    cipher perfect forward secrecy (PFS), prioritas cipher oleh
    server, dan parameter yang aman. Terapkan enkripsi menggunakan arahan
    seperti HTTP Strict Transport Security (HSTS).

-   Menonaktifkan caching untuk respons yang berisi data sensitif.

-   Simpan kata sandi menggunakan fungsi hashing adaptif dan salted yang kuat
    dengan faktor kerja (faktor penundaan), seperti Argon2, scrypt, bcrypt atau
    PBKDF2.

-   Verifikasi secara independen efektivitas konfigurasi dan
    pengaturan.

## Contoh Scenario Serangan

**Skenario #1**: Aplikasi mengenkripsi nomor kartu kredit dalam
database menggunakan enkripsi database otomatis. Namun, data ini
secara otomatis didekripsi ketika diambil, memungkinkan cacat injeksi SQL untuk
mengambil nomor kartu kredit dalam teks yang jelas.

**Skenario #2**: Situs tidak menggunakan atau menerapkan TLS untuk semua halaman atau
mendukung enkripsi yang lemah. Penyerang memantau lalu lintas jaringan (misalnya, di
jaringan nirkabel yang tidak aman), menurunkan versi koneksi dari HTTPS ke
HTTP, memotong permintaan, dan mencuri cookie sesi pengguna.
Penyerang Kemudian replay cookie ini dan membajak pengguna sesi (dikonfirmasi), mengakses atau memodifikasi data pribadi pengguna. Alih-alih diatas, 
mereka dapat mengubah semua data yang diangkut, misalnya, penerima
mentransfer uang.

**Skenario #3**: Kata sandi pada database  menggunakan hash tanpa garam atau sederhana untuk
menyimpan kata sandi semua orang. Cacat unggah file memungkinkan penyerang untuk
mengambil basis data kata sandi. Semua unsalted hashes dapat diekspos
dengan tabel pelangi dari hash yang telah dihitung sebelumnya. Hash yang dihasilkan oleh
fungsi hash sederhana atau cepat dapat dipecahkan oleh GPU, meskipun telah
diasinkan.

## Referensi

-   [OWASP Proactive Controls: Protect Data
    Everywhere](https://owasp.org/www-project-proactive-controls/v3/en/c8-protect-data-everywhere)

-   [OWASP Application Security Verification Standard (V7,
    9, 10)](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Cheat Sheet: Transport Layer
    Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: User Privacy
    Protection](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)

-   OWASP Cheat Sheet: Password and Cryptographic Storage

-   [OWASP Cheat Sheet:
    HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)

-   OWASP Testing Guide: Testing for weak cryptography


## Daftar Klasifikasi CWE

CWE-261 Weak Encoding for Password

CWE-296 Improper Following of a Certificate's Chain of Trust

CWE-310 Cryptographic Issues

CWE-319 Cleartext Transmission of Sensitive Information

CWE-321 Use of Hard-coded Cryptographic Key

CWE-322 Key Exchange without Entity Authentication

CWE-323 Reusing a Nonce, Key Pair in Encryption

CWE-324 Use of a Key Past its Expiration Date

CWE-325 Missing Required Cryptographic Step

CWE-326 Inadequate Encryption Strength

CWE-327 Use of a Broken or Risky Cryptographic Algorithm

CWE-328 Reversible One-Way Hash

CWE-329 Not Using a Random IV with CBC Mode

CWE-330 Use of Insufficiently Random Values

CWE-331 Insufficient Entropy

CWE-335 Incorrect Usage of Seeds in Pseudo-Random Number Generator
(PRNG)

CWE-336 Same Seed in Pseudo-Random Number Generator (PRNG)

CWE-337 Predictable Seed in Pseudo-Random Number Generator (PRNG)

CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator
(PRNG)

CWE-340 Generation of Predictable Numbers or Identifiers

CWE-347 Improper Verification of Cryptographic Signature

CWE-523 Unprotected Transport of Credentials

CWE-720 OWASP Top Ten 2007 Category A9 - Insecure Communications

CWE-757 Selection of Less-Secure Algorithm During Negotiation
('Algorithm Downgrade')

CWE-759 Use of a One-Way Hash without a Salt

CWE-760 Use of a One-Way Hash with a Predictable Salt

CWE-780 Use of RSA Algorithm without OAEP

CWE-818 Insufficient Transport Layer Protection

CWE-916 Use of Password Hash With Insufficient Computational Effort
