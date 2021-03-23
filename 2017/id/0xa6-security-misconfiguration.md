# A6:2017 Kesalahan Konfigurasi Keamanan

| Agen ancaman / vektor serangan                                                                                                                                                                                                                                  | Kelemahan Keamanan                                                                                                                                                                                                                                                                                                                                                                                               | Dampak                                                                                                                                                                                                                                                                  |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Akses Lvl : Exploitasi 3                                                                                                                                                                                                                                        | Prevalensi 3 : Deteksi 3                                                                                                                                                                                                                                                                                                                                                                                         | Teknik 2 : Bisnis                                                                                                                                                                                                                                                       |
| Penyerang akan sering mencoba untuk mengeksploitasi kelemahan yang tidak diawasi atau mengakses akun default, halaman yang tidak digunakan, file dan direktori yang tidak dilindungi, dll untuk mendapatkan akses yang tidak sah atau informasi tentang sistem. | Kesalahan konfigurasi keamanan dapat terjadi di semua tingkat _stack_ aplikasi, termasuk layanan jaringan, platform, server web, server aplikasi, database, _framework_, kode kustom, dan _pre-installed virtual machine_, _container_, atau penyimpanan. Pemindai otomatis berguna untuk mendeteksi kesalahan konfigurasi, penggunaan akun atau konfigurasi default, layanan yang tidak perlu, opsi lawas, dll. | Kelemahan seperti itu sering memberi penyerang akses yang tidak sah ke beberapa data sistem atau fungsionalitas. Terkadang kelemahan tersebut berujung pada kerusakan sistem secara menyeluruh. Dampak bisnis tergantung pada kebutuhan perlindungan aplikasi dan data. |

## Apakah Aplikasi itu Rentan?

Aplikasi dapat menjadi rentan jika:

- Tidak ada _hardening_ keamanan yang sesuai di seluruh bagian dari _stack_ aplikasi, atau izin yang tidak dikonfigurasi dengan benar pada layanan _cloud_.
- Fitur yang tidak diperlukan masih diaktifkan atau diinstal (contoh: _port_, layanan, halaman, akun, atau _privilege_ yang tidak perlu).
- Akun bawaan dengan kata sandi yang masih diaktifkan dan tidak berubah.
- Penanganan _error_ yang menyingkapkan _stack trace_ atau _error message_ yang terlalu informatif kepada pengguna.
- Untuk sistem yang diperbarui, fitur keamanan terbaru dinonaktifkan atau tidak dikonfigurasi dengan aman.
- Pengaturan keamanan di server aplikasi, _framework_ aplikasi (contoh: Struts, Spring, ASP.NET), _library_, _database_, dll tidak disetting secara aman.
- Server tidak mengirim security headers atau arahan keamanan atau tidak diatur untuk mengamankan nilai dari sisi backend.
- Software telah out of date atau diketahui rentan (lihat **A9:2017-Using Components with Known Vulnerabilities**).

Tanpa proses konfigurasi keamanan aplikasi yang diintegrasikan dan dilakukan secara berkala, sistem berisiko lebih tinggi.

## Cara Pencegahan

Proses instalasi secara aman harus diimplementasikan, termasuk:

- Proses _hardening_ yang dapat diulang bisa mempermudah dan mempercepat proses _deploy_ untuk _environment_ baru yang terkunci dengan baik. _Environment_ untuk _Development_, _QA_, dan _Production_ harus diatur secara serupa, dan dengan _credential_ yang berbeda-beda dalam setiap _environment_ nya. Proses ini harus bisa dilakukan secara otomatis untuk mengurangi usaha dalam pembuatan _environment_ baru yang aman.
- _Platform_ yang minimal tanpa fitur, komponen, dokumentasi, dan contoh yang tidak dibutuhkan. Hapus atau jangan _install_ fitur dan _framework_ yang tidak dibutuhkan.
- Tugas untuk mengkaji ulang dan memperbarui pengaturan yang pantas kepada semua catatan keamanan, _update_, dan _patch_ sebagai bagian dari proses manajemen _patch_ (lihat **A9:2017-Using Components with Known Vulnerabilities**). Khususnya, review perizinan penyimpanan _cloud_ (contoh: S3 bucket permissions).
- Arsitektur aplikasi yang terbagi-bagi dan menyediakan pemisahan yang efektif dan aman antara komponen atau _tenant_ menggunakan segmentasi, _containerization_, atau _cloud security groups_ (ACL).
- Mengirimkan arahan keamanan kepada _client_, contoh: [Security Headers](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project).
- Proses otomatis dalam memastikan efektivitas dari pengaturan dalam semua _environment_.

## Contoh Skenario Serangan

**Skenario #1**: Server aplikasi disediakan bersama aplikasi contoh yang tidak dihapus dari server _production_. Aplikasi contoh ini memiliki celah keamanan yang diketahui dan dapat digunakan penyerang untuk membahayakan server. Jika salah satu dari aplikasi tersebut adalah _admin console_ dan akun bawaan tidak diganti saat di-_install_, maka penyerang dapat masuk menggunakan _password_ bawaan dan mengambil alih kontrol.

**Skenario #2**: _Directory listing_ tidak dimatikan pada server. Penyerang mengetahui bahwa mereka dapat dengan mudah membuat daftar direktori. Penyerang dapat menemukan dan mengunduh _class_ Java yang sudah di-_compile_, yang dapat mereka _decompile_ dan _reverse engineer_ untuk melihat _code_ di dalamnya. Setelah itu penyerang dapat menemukan celah _access control_ dalam aplikasi tersebut.

**Skenario #3**: Pengaturan server aplikasi yang memperlihatkan pesan error secara detail, contoh: stack traces, yang ditampilkan kepada pengguna. Hal ini memiliki potensi untuk membeberkan informasi sensitif atau celah-celah mendasar seperti versi komponen yang mungkin diketahui memiliki celah keamanan.

**Skenario #4**: Penyedia layanan _cloud_ yang memberikan _default sharing permission_ yang dapat diakses oleh pengguna layanan lain melalui Internet. Hal ini dapat menyebabkan akses kepada data sensitif yang disimpan dalam penyimpanan _cloud_.

## Referensi

### OWASP

- [OWASP Testing Guide: Configuration Management](https://www.owasp.org/index.php/Testing_for_configuration_management)
- [OWASP Testing Guide: Testing for Error Codes](<https://www.owasp.org/index.php/Testing_for_Error_Code_(OWASP-IG-006)>)
- [OWASP Security Headers Project](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project)

Untuk persyaratan tambahan bisa di lihat lebih detail pada (ASVS) Application Security Verification Standard [V19 Configuration](https://www.owasp.org/index.php/ASVS_V19_Configuration).

### Eksternal

- [NIST Guide to General Server Hardening](https://csrc.nist.gov/publications/detail/sp/800-123/final)
- [CWE-2: Environmental Security Flaws](https://cwe.mitre.org/data/definitions/2.html)
- [CWE-16: Configuration](https://cwe.mitre.org/data/definitions/16.html)
- [CWE-388: Error Handling](https://cwe.mitre.org/data/definitions/388.html)
- [CIS Security Configuration Guides/Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [Amazon S3 Bucket Discovery and Enumeration](https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html)
