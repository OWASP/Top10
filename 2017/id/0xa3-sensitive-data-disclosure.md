# A3:2017 Pengungkapan Data Sensitif

| Agen ancaman / vektor serangan | Kelemahan Keamanan | Dampak |
| -- | -- | -- |
| Akses Lvl: Eksploitasi 2 | Prevalensi 3: Deteksi 2 | Teknis 3: Bisnis |
| Daripada secara langsung menyerang crypto, Penyerang memilih untuk mencuri keys, mengeksekusi metode serangan man-in-the-middle, atau mencuri data teks yang jelas dari server, saat dalam proses, atau dari klien pengguna, mis. browser. Serangan manual umumnya diperlukan. Password Database yang sebelumnya diambil bisa diambil dengan metode brute force dengan kemampuan Graphics Processing Units (GPU). | Beberapa tahun terakhir ini, Hal ini menjadi serangan yang paling umum. Kelemahan yang paling umum adalah tidak melakukan enkripsi data yang sensitif. Ketika crypto digunakan, pembuatan dan manajemen key yang lemah, serta algoritma yang lemah, penggunaan protokol dan penggunaan cipher sering terjadi, terutama untuk teknik penyimpanan hashing sandi yang lemah. Untuk data dalam transit, kelemahan sisi server mudah terdeteksi, tetapi sulit untuk terdeteksi bagi data saat yang dalam keadaan tidak terpakai atau tidak berubah. | Kegagalan sering membuat semua data yang seharusnya dilindungi dapat dilihat. Biasanya, informasi ini mencakup informasi pribadi sensitif (PII) seperti catatan kesehatan, kredensial, data pribadi, dan kartu kredit, yang seringkali memerlukan perlindungan seperti yang ditentukan oleh hukum atau peraturan seperti undang-undang GDPR atau undang-undang privasi setempat. |

## Apakah Aplikasi itu Rentan?

Hal pertama adalah menentukan kebutuhan proteksi data saat transit dan saat tidak digunakan. Misalnya, kata sandi, nomor kartu kredit, catatan kesehatan, informasi pribadi dan rahasia bisnis memerlukan perlindungan yang ekstra, terutama jika data tersebut termasuk dalam undang-undang privasi, mis. Peraturan Perlindungan Data Umum UE (GDPR), atau peraturan, mis. perlindungan data keuangan seperti PCI Data Security Standard (PCI DSS). Untuk semua data tersebut:

* Apakah ada data yang dikirimkan dalam bentuk teks yang jelas? Ini menyangkut protokol seperti HTTP, SMTP, dan FTP. Lalu lintas internet luar sangatlah berbahaya. Lakukan verifikasi semua lalu lintas internal dan mis seperti diantara load balancer, web server, atau sistem back-end.
* Apakah ada algoritma kriptografi yang telah usang atau cukup lemah yang digunakan secara default atau dalam kode yang lebih lama?
* Apakah kunci kripto default sedang digunakan, atau mungkin kunci kripto yang lemah yang dihasilkan atau digunakan kembali, atau manajemen kunci serta rotasi krypto yang harusnya tepat malah hilang?
* Apakah enkripsi tidak diberlakukan. apakah ada perintah agen pengguna browser(peramban) seperti arahan dalam keamanan atau tajuk(header) yang telah hilang?
* Apakah agen pengguna (misalnya aplikasi, klien email) tidak memverifikasi bila sertifikat server yang diterima valid?

Lihat ASVS [Crypto (V7)](https://www.owasp.org/index.php/ASVS_V7_Cryptography), [Data Protection (V9)](https://www.owasp.org/index.php/ASVS_V9_Data_Protection) and [SSL/TLS (V10)](https://www.owasp.org/index.php/ASVS_V10_Communications).

## Cara Mencegah

Lakukan hal berikut, setidaknya minimal kita harus dan baca rujukannya:

* Klasifikasikan data yang diproses, disimpan atau dikirim oleh aplikasi. Identifikasi data mana yang sensitif menurut hukum privasi, persyaratan peraturan, atau kebutuhan bisnis.
* Terapkan kontrol sesuai klasifikasi.
* Jangan menyimpan data sensitif secara tidak perlu. Buang sesegera mungkin atau gunakan tokenisasi sesuai standar PCI DSS atau bahkan pemotongannya. Data yang tidak disimpan tidak bisa dicuri.
* Pastikan untuk mengenkripsi semua data sensitif saat tidak digunakan.
* Pastikan algoritma, protokol, dan kunci standar yang kuat selalu sesuai dengan yang baru ada; gunakan manajemen kunci yang tepat.
* Enkripsikan semua data dalam transit dengan protokol aman seperti TLS dengan kriptifikasi keamanan maju yang sempurna (PFS), prioritas cipher oleh server, dan parameter yang aman. Terapkan enkripsi menggunakan arahan seperti HTTP Strict Transport Security (HSTS).
* Nonaktifkan caching untuk respon yang mengandung data sensitif.
* Simpan kata sandi dengan menggunakan fungsi hashing adaptif yang kuat dengan faktor kerja (faktor keterlambatan), seperti [Argon2](https://www.cryptolux.org/index.php/Argon2), [scrypt](https://wikipedia.org/wiki/Scrypt), [bcrypt](https://wikipedia.org/wiki/Bcrypt) or [PBKDF2](https://wikipedia.org/wiki/PBKDF2).
* Verifikasi secara independen efektivitas pada konfigurasi dan pengaturan.

## Contoh Skenario Serangan

**Skenario #1**: Aplikasi mengenkripsi nomor kartu kredit dalam database menggunakan enkripsi dengan basis data otomatis. Namun, data ini secara otomatis didenkripsi saat diambil, memungkinkan celah unutk injeksi SQL untuk mengambil nomor kartu kredit dengan tulisan yang jelas.

**Skenario #2**: Situs tidak menggunakan atau memberlakukan TLS untuk semua halaman atau enkripsinya lemah. Penyerang memonitor lalu lintas jaringan (misalnya di jaringan nirkabel yang tidak aman), menurunkan koneksi dari HTTPS ke HTTP, mencegat permintaan, dan mencuri cookie dari pengguna. Penyerang kemudian memutar ulang cookie ini dan membajak sesi pengguna (dikonfirmasi), mengakses atau memodifikasi data pribadi pengguna. Alih-alih di atas, mereka dapat mengubah semua data yang diangkut, mis. penerima transfer uang

**Skenario #3**: Database kata sandi menggunakan hash yang kurang kuat atau sederhana untuk menyimpan kata kunci setiap orang. Sebuah file upload fluge memungkinkan penyerang untuk mengambil database password. Semua hash yang tidak dikriptografikan dapat terkena serangan dengan metode rainbow table dari hash yang telah dihitung sebelumnya. Hash yang dihasilkan oleh fungsi hash sederhana atau hash cepat dapat di-crack oleh GPU, bahkan walaupun telah dikriptografikan.

## Referensi

* [OWASP Proactive Controls: Protect Data](https://www.owasp.org/index.php/OWASP_Proactive_Controls#7:_Protect_Data)
* [OWASP Application Security Verification Standard]((https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project)): [V7](https://www.owasp.org/index.php/ASVS_V7_Cryptography), [9](https://www.owasp.org/index.php/ASVS_V9_Data_Protection), [10](https://www.owasp.org/index.php/ASVS_V10_Communications)
* [OWASP Cheat Sheet: Transport Layer Protection](https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet)
* [OWASP Cheat Sheet: User Privacy Protection](https://www.owasp.org/index.php/User_Privacy_Protection_Cheat_Sheet)
* [OWASP Cheat Sheet: Password](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet) and [Cryptographic Storage](https://www.owasp.org/index.php/Cryptographic_Storage_Cheat_Sheet)
* [OWASP Security Headers Project](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project); [Cheat Sheet: HSTS](https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet)
* [OWASP Testing Guide: Testing for weak cryptography](https://www.owasp.org/index.php/Testing_for_weak_Cryptography)

### Eksternal

* [CWE-220: Exposure of sens. information through data queries](https://cwe.mitre.org/data/definitions/220.html)
* [CWE-310: Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html); [CWE-311: Missing Encryption](https://cwe.mitre.org/data/definitions/311.html)
* [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
* [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
* [CWE-326: Weak Encryption](https://cwe.mitre.org/data/definitions/326.html); [CWE-327: Broken/Risky Crypto](https://cwe.mitre.org/data/definitions/327.html)
* [CWE-359: Exposure of Private Information - Privacy Violation](https://cwe.mitre.org/data/definitions/359.html)
