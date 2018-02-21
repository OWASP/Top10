# RN Catatan Rilis

## Apa yang berubah dari tahun 2013 sampai 2017?

Perubahan telah meningkat selama empat tahun terakhir, dan OWASP Top 10 perlu diubah. Kami telah benar-benar melakukan refactored OWASP Top 10, mengubah metodologinya, menggunakan proses panggilan data baru, bekerja dengan masyarakat, mengatur ulang risiko kami, menulis ulang setiap risiko dari awal, dan menambahkan referensi ke kerangka kerja dan bahasa yang sekarang sudah biasa digunakan

Selama beberapa tahun terakhir, teknologi dan arsitektur mendasar dari aplikasi telah berubah secara signifikan:

Microservices yang ditulis di node.js dan Spring Boot menggantikan aplikasi monolitik tradisional. Microservices hadir dengan tantangan keamanan mereka sendiri termasuk membangun kepercayaan antara layanan mikroservice, kontainer, manajemen rahasia, dan lain-lain. Kode lama yang tidak pernah diharapkan dapat diakses dari Internet sekarang duduk di belakang layanan web API atau RESTful untuk dikonsumsi oleh Aplikasi Halaman Tunggal (SPA) dan aplikasi mobile. Asumsi arsitektur menurut kode, seperti penelepon yang terpercaya, sudah tidak berlaku lagi.
Aplikasi halaman tunggal, yang ditulis dalam kerangka kerja JavaScript seperti Angular and React, memungkinkan pembuatan front end yang kaya fitur modular. Fungsi sisi klien yang secara tradisional telah disampaikan sisi server membawa tantangan keamanan tersendiri.
JavaScript sekarang menjadi bahasa utama web dengan node.js menjalankan sisi server dan kerangka web modern seperti Bootstrap, Electron, Angular, dan React yang berjalan pada klien.

## Isu baru, didukung data

A4: 2017-XML Entitas Eksternal (XXE) adalah kategori baru yang terutama didukung oleh kumpulan perangkat analisis keamanan pengujian (SAST) kumpulan kode (https://www.owasp.org/index.php/Source_Code_Analysis_Tools)) sumber.

## Isu baru, didukung oleh masyarakat

Kami meminta masyarakat untuk memberikan wawasan tentang dua kategori kelemahan kedepan. Setelah lebih dari 500 pengantar peer, dan menghapus isu-isu yang sudah didukung oleh data (seperti Sensitive Data Exposure and XXE), dua isu baru tersebut adalah:

A8: 2017-Insecure Deserialization, yang memungkinkan eksekusi kode jarak jauh atau manipulasi objek sensitif pada platform yang terpengaruh.
A10: 2017-Pembukaan dan Pemantauan Tidak Cukup, kurangnya yang dapat mencegah atau secara signifikan menunda aktivitas berbahaya dan deteksi pelanggaran, respon insiden, dan forensik digital.

## Bergabung atau pensiun, tapi tidak dilupakan

Referensi Objek Langsung A4-Tidak aman dan A7-Hilang fungsi level akses kontrol digabungkan menjadi A5: 2017- kontrol akses rusak.
A8-Cross-Site Request Forgery (CSRF), karena banyak kerangka mencakup pertahanan CSRF (https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)), hanya ditemukan 5% aplikasi.
A10-Unvalidated Redirects and Forwards, sementara ditemukan di sekitar 8% aplikasi, diarsipkan secara keseluruhan oleh XXE.

![0x06-release-notes-1](images/0x06-release-notes-1.png)
