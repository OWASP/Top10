# A02:2021 – Kegagalan Kriptografi    ![icon](assets/TOP_10_Icons_Final_Crypto_Failures.png){: style="height:80px;width:80px" align="right"}

## Faktor-Faktor

| CWE Dipetakan | Tingkat Kejadian Maksimum | Rata-rata Tingkat kejadian | Rata-rata Eksploitasi Terbobot | Rata-rata Dampak Terbobot | Cakupan Maks | Rata-rata Cakupan | Total Kejadian | Total CVE |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 29          | 46,44%             | 4,49%              | 7,29                | 6,81                | 79,33%        | 34,85%       | 233.788           | 3.075      |

## Ikhtisar

Bergeser satu posisi ke #2, sebelumnya dikenal sebagai *Sensitive Data
Exposure*, yang lebih merupakan gejala yang luas daripada akar masalah,
fokusnya adalah kegagalan yang terkait dengan kriptografi (atau ketiadaannya),
yang sering menyebabkan paparan data sensitif. CWE terkenal yang disertakan
adalah *CWE-259: Use of Hard-coded Password*, *CWE-327: Broken or Risky
Crypto Algorithm*, dan *CWE-331 Insufficient Entropy*.

## Deskripsi

Hal pertama adalah menentukan kebutuhan perlindungan data dalam perjalanan
dan pada saat istirahat. Misalnya, kata sandi, nomor kartu kredit, catatan 
kesehatan, informasi pribadi, dan rahasia bisnis yang memerlukan ekstra
perlindungan, terutama jika data tersebut termasuk dalam undang-undang privasi, 
misalnya, General Data Protection Regulation (GDPR) Uni Eropa, atau peraturan, 
misalnya, perlindungan data keuangan seperti PCI Data Security Standard (PCI DSS).
Untuk semua data tersebut:

-   Apakah ada data yang dikirimkan dalam bentuk teks polos? 
    Ini menyangkut protokol seperti HTTP, SMTP, FTP dan memakai peningkatan TLS
    seperti STARTTLS. Lalu lintas internet eksternal itu berbahaya. Verifikasi 
    semua lalu lintas yang ada di internal, misalnya antara load balancer, 
    server web, atau sistem back-end.

-   Apakah ada algoritma kriptografi lama atau lemah yang digunakan baik secara
    default atau dalam kode yang lebih lama?

-   Apakah kunci kripto bawaan sedang digunakan, 
    kunci kripto yang lemah dihasilkan atau digunakan kembali, 
    atau apakah kurangnya manajemen atau rotasi kunci yang tepat? Apakah kunci
    kripto dimasukkan ke dalam repositori kode sumber?

-   Apakah enkripsi tidak dipaksakan, misalnya, apakah header atau direktif
    keamanan browser HTTP ada yang kurang?

-   Apakah sertifikat server yang diterima dan rantai kepercayaan divalidasi
    secara tepat?

-   Apakah vektor inisialisasi diabaikan, dipakai ulang, atau tidak
    dibangkitkan secara cukup aman bagi mode operasi kriptografis? Apakah
    mode operasi yang tidak aman seperti ECB dipakai? Apakah enkripsi dipakai
    ketika enkripsi terautentikasi lebih sesuai?

-   Apakah kata sandi dipakai sebagai kunci kriptografis karena ketiadaan
    fungsi penurunan kunci basis kata sandi?

-   Apakah keacakan yang dipakai untuk tujuan kriptografis tidak dirancang
    untuk memenuhi persyaratan kriptografis? Bahkan bila fungsi yang benar
    dipilih, apakah itu perlu di-seed oleh pengembang, dan bila tidak, apakah
    pengembang menimpa fungsionalitas seed kuat yang dibangun ke dalamnya
    dengan suatu seed yang kurang cukup entropi/ketidak-tertebakan?

-   Apakah fungsi hash usang seperti MD5 atau SHA1 dipakai, atau apakah fungsi
    hash non kriptografis dipakai ketika fungsi hash kriptografsi diperlukan?

-   Apakah metoda padding kriptografis yang usang seperti PKCS no 1 v1.5
    dipakai?

-   Apakah pesan kesalahan kriptografis atau informasi side channel dapat
    dieksploitasi, misalnya dalam bentuk serangan padding oracle?

Lihat ASVS Crypto (V7), Data Protection (V9), dan SSL/TLS (V10)

## Cara Mengatasi

Lakukan minimal hal berikut, dan lihat referensi: 

-   Mengklasifikasikan data yang diproses, disimpan, atau dikirim oleh aplikasi.
    Identifikasi data mana yang sensitif menurut undang-undang privasi,
    persyaratan regulasi, atau kebutuhan bisnis.

-   Jangan menyimpan data sensitif yang tidak perlu. Buang sesegera mungkin 
    atau gunakan tokenisasi yang sesuai dengan PCI DSS atau bahkan pemotongan.
    Data yang tidak disimpan tidak dapat dicuri.

-   Pastikan untuk mengenkripsi semua data sensitif saat istirahat.

-   Pastikan standar algoritma, protokol, dan kunci yang mutakhir dan kuat dipakai; 
    gunakan manajemen kunci yang tepat.

-   Enkripsi semua data dalam perjalanan dengan protokol aman seperti TLS dengan
    cipher forward secrecy (FS), penentuan prioritas cipher oleh server, dan 
    parameter yang aman. Paksakan enkripsi menggunakan direktif seperti HTTP 
    Strict Transport Security (HSTS).

-   Menonaktifkan caching untuk respons yang berisi data sensitif.

-   Tetapkan kontrol keamanan yang diperlukan sesuai klasifikasi data.

-   Jangan memakai protokol warisan (legacy) seperti FTP dan SMTP untuk 
    mengirim data sensitif.

-   Simpan kata sandi menggunakan fungsi hashing adaptif dan salted yang kuat
    dengan faktor kerja (faktor penundaan), seperti Argon2, scrypt, bcrypt, atau
    PBKDF2.

-   Vektor inisialisasi (IV, initialization vector) mesti dipilih yang sesuai
    bagi mode operasi. Untuk banyak mode, ini berarti memakai suatu CSPRNG
    (cryptographically secure pseudo random number generator). Untuk mode-mode
    yang memerlukan suatu nonce, maka IV tidak memerlukan sebuah CSPRNG. Dalam
    semua kasus, IV tidak boleh dipakai dipakai dua kali untuk sebuah kunci 
    tetap.

-   Selalu gunakan enkripsi terautentikasi bukan hanya enkripsi.

-   Kunci mesti dibuat secara kriptografis acak dan disimpan di memori sebagai
    larik byte. Bila suatu kata sandi dipakai, maka itu mesti dikonversi ke 
    suatu kunci melalui sebuah fungsi penurunan kunci basis kata sandi yang
    tepat.

-   Pastikan bahwa keacakan kriptografis dipakai dimana sesuai, dan itu tidak
    di-seed dalam suatu cara yang dapat diprediksi atau dengan entropi rendah.
    Kebanyakan API modern tidak memerlukan pengembang men-seed CSPRNG untuk
    memperoleh keamanan.

-   Hindari fungsi kriptografis dan skema padding yang usang, seperti misalnya
    MD5, SHA1, PKCS no 1 v1.5.

-   Verifikasi secara independen efektivitas konfigurasi dan pengaturan.

## Contoh Skenario Serangan

**Skenario #1**: Aplikasi mengenkripsi nomor kartu kredit dalam
database menggunakan enkripsi database otomatis. Namun, data ini
secara otomatis didekripsi ketika diambil, memungkinkan cacat injeksi SQL untuk
mengambil nomor kartu kredit dalam teks polos.

**Skenario #2**: Situs tidak menggunakan atau menerapkan TLS untuk semua halaman atau
mendukung enkripsi yang lemah. Penyerang memantau lalu lintas jaringan (misalnya, di
jaringan nirkabel yang tidak aman), menurunkan versi koneksi dari HTTPS ke
HTTP, mengintersepsi permintaan, dan mencuri cookie sesi pengguna.
Penyerang kemudian replay cookie ini dan membajak sesi pengguna (yang terautentikasi), 
mengakses atau memodifikasi data pribadi pengguna. Alih-alih di atas, 
mereka dapat mengubah semua data yang diangkut, misalnya, penerima
dari suatu transfer uang.

**Skenario #3**: Kata sandi pada database menggunakan hash tanpa salt atau sederhana untuk
menyimpan kata sandi semua orang. Cacat unggah file memungkinkan penyerang untuk
mengambil basis data kata sandi. Semua unsalted hash dapat diekspos
dengan tabel pelangi dari hash yang telah dihitung sebelumnya. Hash yang dihasilkan oleh
fungsi hash sederhana atau cepat dapat dipecahkan oleh GPU, meskipun telah
di-salt.

## Referensi

-   [OWASP Proactive Controls: Protect Data
    Everywhere](https://owasp.org/www-project-proactive-controls/v3/en/c8-protect-data-everywhere)

-   [OWASP Application Security Verification Standard (V7,
    9, 10)](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Cheat Sheet: Transport Layer
    Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: User Privacy
    Protection](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Password and Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

-   [OWASP Cheat Sheet:
    HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)

-   [OWASP Testing Guide: Testing for weak cryptography](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README)

## Daftar Klasifikasi CWE

[CWE-261 Weak Encoding for Password](https://cwe.mitre.org/data/definitions/261.html)

[CWE-296 Improper Following of a Certificate's Chain of Trust](https://cwe.mitre.org/data/definitions/296.html)

[CWE-310 Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html)

[CWE-319 Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

[CWE-321 Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)

[CWE-322 Key Exchange without Entity Authentication](https://cwe.mitre.org/data/definitions/322.html)

[CWE-323 Reusing a Nonce, Key Pair in Encryption](https://cwe.mitre.org/data/definitions/323.html)

[CWE-324 Use of a Key Past its Expiration Date](https://cwe.mitre.org/data/definitions/324.html)

[CWE-325 Missing Required Cryptographic Step](https://cwe.mitre.org/data/definitions/325.html)

[CWE-326 Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

[CWE-327 Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

[CWE-328 Reversible One-Way Hash](https://cwe.mitre.org/data/definitions/328.html)

[CWE-329 Not Using a Random IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html)

[CWE-330 Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)

[CWE-331 Insufficient Entropy](https://cwe.mitre.org/data/definitions/331.html)

[CWE-335 Incorrect Usage of Seeds in Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/335.html)

[CWE-336 Same Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/336.html)

[CWE-337 Predictable Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/337.html)

[CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/338.html)

[CWE-340 Generation of Predictable Numbers or Identifiers](https://cwe.mitre.org/data/definitions/340.html)

[CWE-347 Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)

[CWE-523 Unprotected Transport of Credentials](https://cwe.mitre.org/data/definitions/523.html)

[CWE-720 OWASP Top Ten 2007 Category A9 - Insecure Communications](https://cwe.mitre.org/data/definitions/720.html)

[CWE-757 Selection of Less-Secure Algorithm During Negotiation('Algorithm Downgrade')](https://cwe.mitre.org/data/definitions/757.html)

[CWE-759 Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html)

[CWE-760 Use of a One-Way Hash with a Predictable Salt](https://cwe.mitre.org/data/definitions/760.html)

[CWE-780 Use of RSA Algorithm without OAEP](https://cwe.mitre.org/data/definitions/780.html)

[CWE-818 Insufficient Transport Layer Protection](https://cwe.mitre.org/data/definitions/818.html)

[CWE-916 Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
