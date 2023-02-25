# A11:2021 – Langkah Selanjutnya

Secara desaiin, OWASP Top 10 secara bawaan terbatas ke 10 risiko yang paling signifikan. Setiap OWASP Top 10 memiliki risiko-risiko yang lama dipertimbangkan untuk disertakan dan nyaris lolos, tapi pada akhirnya, mereka tidak berhasil. Tak peduli bagaimana kami mencoba menginterpretasi atau memelintir data, risiko-risiko lain lebih unggul dan berdampak.

Bagi organisasi yang sedang menuju ke program appsec yang matang atau konsultasi keamanan atau vendor peralatan yang berharap mengembangkan cakupan bagi tawaran mereka, empat masalah berikut layak ditempuh untuk diidentifikasi dan diperbaiki.

## Masalah-masalah Kualitas Kode

| Klasifikasi CWE | Tingkat Kejadian Maks | Rerata Tingkat kejadian | Rerate Eksploatasi Terbobot | Rerata Dampak Terbobot | Cakupan Maks | Rerata Cakupan | Total Kejadian | Total CVE |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 38           | 49.46%              | 2.22%               | 7.1                   | 6.7                  | 60.85%        | 23.42%        | 101736             | 7564        |

-   **Deskripsi.** Masalah kualitas kode termasuk pola atau cacat keamanan, memakai ulang variabel untuk berbagai kegunaan, eksposur informasi sensitif dalam luaran pengawakutuan, kesalahan off-by-one, kondisi race saat pemeriksaan/saat penggunaan (time of check/time of use, TOCTOU), kesalahan konversi unsigned atau signed, use after free, dan lebih banyak lagi. Ciri khas bagian ini adalah mereka biasanya bisa diidentifikasi dengan flag kompiler yang ketat, alat analisis kode statik, dan plugin IDE linter. Bahasa-bahasa modern dari desain mengeliminasi banyak masalah ini, seperti konsep peminjaman dan kepemilikan memori Rust, desain thread Rust, dan penentuan tipe ketat dan pemeriksaan batas Go.

-   **Bagaimana mencegahnya**. Fungsikan dan gunakan opsi analisis kode statik bahasa dan penyunting Anda. Pertimbangkan memakai alat analisis kode statik. Pertimbangkan apakah mungkin memakai atau bermigrasi ke suatu bahasa atau framework yang mengeliminasi kelas-kelas bug, seperti Rust atau Go.

-   **Contoh skenario serangan**. Seorang penyerang mungkin mendapatkan atau memutakhirkan informasi sensitif dengan mengeksploitasi suatu 'race condition' memakai sebuah variable yang dipakai bersama secara statik melintas beberapa thread.

-   **Referensi**
    - [OWASP Code Review Guide](https://owasp.org/www-pdf-archive/OWASP_Code_Review_Guide_v2.pdf)

    - [Google Code Review Guide](https://google.github.io/eng-practices/review/)


## Denial of Service

| Klasifikasi CWE | Tingkat Kejadian Maks | Rerata Tingkat kejadian | Rerate Eksploatasi Terbobot | Rerata Dampak Terbobot | Cakupan Maks | Rerata Cakupan | Total Kejadian | Total CVE |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 8            | 17.54%              | 4.89%               | 8.3                   | 5.9                  | 79.58%        | 33.26%        | 66985              | 973         |

-   **Deskripsi**. Denial of service selalu mungkin dengan sumber daya yang cukup. Namun, desain dan praktek pengodan memiliki hubungan yang signifikan pada magnituda dari penyangkalan layanan. Misalkan seseorang dengan tautan dapat mengakses sebuah berkas besar, atau transaksi yang mahal secara komputasi terjadi pada setiap halaman. Dalam kasus itu, penyangkalan layanan memerlukan upaya lebih sedikit untuk dijalankan.

-   **Bagaimana mencegahnya**. Uji kinerja kode untuk penggunaan CPU, I/O, dan memori; rancang ulang, optimasikan, atau singgahkan (cache) operasi-operasi yang mahal. Pertimbangkan kendali akses untuk obyek-obyek yang lebih besar untuk memastikan bahwa hanya individu yang terotorisasi yang dapat mengakses obyek atau berkas sangat besar atau menyajikan mereka memakai jaringan singgahan tepi.

-   **Contoh skenario serangan**. Penyerang mungkin mendapatkan bahwa suatu operasi makan waktu 5-10 detik sampai selesai ketika menjalankan empat thread konkuren, server tampaknya berhenti merespon. Penyerang memakai 1000 thread dan membuat seluruh sistem luring.

-   **Referensi**
    - [OWASP Cheat Sheet: Denial of Service](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
    
    - [OWASP Attacks: Denial of Service](https://owasp.org/www-community/attacks/Denial_of_Service)

## Kesalahan Manajemen Memori

| Klasifikasi CWE | Tingkat Kejadian Maks | Rerata Tingkat kejadian | Rerate Eksploatasi Terbobot | Rerata Dampak Terbobot | Cakupan Maks | Rerata Cakupan | Total Kejadian | Total CVE |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 14           | 7.03%               | 1.16%               | 6.7                   | 8.1                  | 56.06%        | 31.74%        | 26576              | 16184       |

-   **Deskripsi**. Aplikasi web cenderung ditulis dalam bahasa-bahasa yang memorinya dikelola, seperti Java, .NET, atau node.js (JavaScript atau TypeScript). Namun, bahasa-bahasa ini ditulis dalam bahasa sistem yang memiliki masalah-masalah manajemen memori, seperti buffer overflow atau heap overflow, use after free, integer overflow, dan lebih banyak lagi. Ada banyak 'sandbox escape' selama bertahun-tahun yang membuktikan bahwa karena bahasa aplikasi web secara nominal "aman" memori, landasannya tidak.

-   **Bagaimana mencegahnya**. Banyak API modern yang kini ditulis dalam bahasa-bahasa yang aman-memori seperti Rust atau Go. Dalam kasus Rust, keamanan memori adalah fitur sangat penting dari bahasa. Untuk kode yang telah ada, penggunaan flag compiler yang ketat, penentuan tipe yang kuat, analisis kode statik, dan uji fuzz bisa menguntungkan dalam mengidentifikasi kebocoran memori, memori, dan array overrun, dan lebih banyak lagi.

-   **Contoh skenario serangan**. Buffer overflow dan heap overflow masih menjadi andalah para penyerang selama bertahun-tahun. Penyerang mengirim data ke suatu program, yang disimpannya dalam buffer stack yang berukuran terlalu kecil. Hasilnya adalah informasi pada call stack ditimpa, termasuk pointer balik fungsi. Data menata nilai pointer balik sehingga ketika fungsi kembali, itu memindah kendali ke kode jahat yang dimuat dalam data penyerang.

-   **Referensi**
    - [OWASP Vulnerabilities: Buffer Overflow](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)
    
    - [OWASP Attacks: Buffer Overflow](https://owasp.org/www-community/attacks/Buffer_overflow_attack)
    
    - [Science Direct: Integer Overflow](https://www.sciencedirect.com/topics/computer-science/integer-overflow)
