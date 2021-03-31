# A9:2017 Menggunakan Komponen yang Diketahui Rentan

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl : Exploitability 2 | Prevalence 3 : Detectability 2 | Technical 2 : Business |
| Meskipun mudah untuk menemukan eksploitasi yang telah tercatat dalam banyak kasus kerentanan yang telah diketahui, kerentanan lain yang belum diketahui membutuhkan usaha yang lebih dalam mengembangkan sebuah Custom Exploit. | Tingkat kelaziman mengenai permasalahan ini sangat luas. Komponen yang sulit dalam pola pengembangan dapat menyebabkan tim pengembangan bahkan kurang mengerti mengenai komponen yang mereka gunakan dalam aplikasi mereka atau pada API, apalagi menjaganya agar tetap mutakhir. beberapa sistem pemindai seperti retire.js dapat membantu dalam pendeteksian, tetapi dalam mengetahui exploitability membutuhkan upaya tambahan | sementara itu, dalam beberapa kasus kerentanan yang diketahui hanya menyebabkan dampak kecil, beberapa pelanggaran terbesar hingga saat ini mengandalkan pengeksploitasian kerentanan yang ada dalam komponen, bergantung dalam aset yang anda sedang lindungi, kemungkinan resiko seperti ini harus berada pada urutan teratas dalam daftar kerentanan |

## Apakah Aplikasi Rentan?

Kemungkinan besar anda rentan:

* Jika anda tidak mengetahui versi dari semua komponen yang anda gunakan (baik sisi klien maupun sisi server). Ini termasuk komponen yang langsung anda gunakan serta dependensi bertingkat.
* Jika perangkat lunak rentan, tidak didukung, atau ketinggalan zaman. Seperti OS, server web / aplikasi, sistem manajemen basis data (DBMS), aplikasi, API dan semua komponen, lingkungan yang berjalan, dan pustaka.
* Jika Anda tidak memindai kerentanan secara teratur dan berlangganan buletin keamanan yang terkait dengan komponen yang Anda gunakan.
* Jika Anda tidak memperbaiki atau meningkatkan platform, kerangka kerja, dan dependensi yang mendasarinya secara tepat waktu dan berbasis risiko. Ini biasanya terjadi di lingkungan ketika perbaikan sedang dilakukan setiap bulan atau tiga bulan sekali dalam perubahan kendali, yang membuat organisasi terbuka untuk beberapa hari atau bulan dari keterpaparan yang tidak perlu terhadap kerentanan tetap.
* Jika pengembang perangkat lunak tidak menguji kompatibilitas pustaka yang diperbarui, ditingkatkan, atau diperbaiki.
* Jika Anda tidak mengamankan konfigurasi komponen (see **A6:2017-Security Misconfiguration**).

## Cara Untuk Mencegah

Seharusnya ada proses manajemen patch untuk:

* Menghapus dependensi yang tidak digunakan, fitur, komponen, file, dan dokumentasi yang tidak perlu.
* Secara terus menerus meninventarisasi versi komponen dari sisi klien dan sisi server (contoh: framework, library) dan dependensi mereka menggunakan alat seperti versions, DependencyCheck, retire.js, dll. 
* Secara terus menerus memonitor sumber seperti CVE dan NVD untuk menemukan kerentanan dalam komponen. Gunakan software composition analysis tools untuk mengotomatiskan proses. Berlangganan pada email peringatan untuk kerentanan keamanan yang berkaitan dengan komponen yang anda gunakan.
* Hanya dapatkan komponen dari sumber resmi dari tautan aman. Utamakan signed packages untuk mengurangi kemungkinan menyertakan komponen yang dimodifikasi dan berbahaya.
* Monitor library dan komponen yang tidak dikelola atau tidak membuat patch keamanan untuk versi lama. Jika patching tidak memungkinkan, pertimbangkan deploying patch virtual untuk memonitor, mendeteksi, atau melindungi dari masalah yang ditemukan.

Setiap organisasi harus memastikan bahwa ada rencana berkelanjutan untuk memonitoring, triaging, dan menerapkan update atau perubahan konfigurasi selama masa pakai aplikasi atau portfolio.

## Contoh Skenario Serangan

**Skenario #1**: Komponen biasanya berjalan dengan hak yang sama seperti aplikasi itu sendiri, jadi kekurangan pada komponen apa pun dapat mengakibatkan dampak yang serius. Kondisi semacam itu bisa tidak disengaja (mis. Kesalahan pada sisi code) atau disengaja (mis. Pintu belakang di dalam komponen). Beberapa contoh kerentanan komponen yang dapat dieksploitasi yang ditemukan adalah:

* [CVE-2017-5638](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638), kerentanan eksekusi kode jarak jauh Struts 2 yang memungkinkan eksekusi kode arbitrer pada server, telah disalahkan atas pelanggaran yang signifikan.
* Meskipun [internet of things (IoT)](https://en.wikipedia.org/wiki/Internet_of_things) seringkali sulit atau tidak mungkin untuk diperbaiki, pentingnya memperbaiki mereka bisa jadi sangat penting (mis. Perangkat biomedis).

Ada alat otomatis untuk membantu penyerang menemukan sistem yang belum diperbaiki atau salah dalam konfigurasi. Contoh, [mesin telusur Shodan IoT](https://www.shodan.io/report/89bnfUyJ) dapat membantu Anda menemukan perangkat yang masih terkena [Heartbleed] [Heartbleed](https://en.wikipedia.org/wiki/Heartbleed) kerentanan yang telah di-patch pada April 2014.

## Referensi

### OWASP

* [OWASP Application Security Verification Standard: V1 Architecture, design and threat modelling](https://www.owasp.org/index.php/ASVS_V1_Architecture)
* [OWASP Dependency Check (for Java and .NET libraries)](https://www.owasp.org/index.php/OWASP_Dependency_Check)
* [OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)](https://www.owasp.org/index.php/Map_Application_Architecture_(OTG-INFO-010))
* [OWASP Virtual Patching Best Practices](https://www.owasp.org/index.php/Virtual_Patching_Best_Practices)

### External

* [The Unfortunate Reality of Insecure Libraries](https://www.aspectsecurity.com/research-presentations/the-unfortunate-reality-of-insecure-libraries)
* [MITRE Common Vulnerabilities and Exposures (CVE) search](https://www.cvedetails.com/version-search.php)
* [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
* [Retire.js for detecting known vulnerable JavaScript libraries](https://github.com/retirejs/retire.js/)
* [Node Libraries Security Advisories](https://nodesecurity.io/advisories)
* [Ruby Libraries Security Advisory Database and Tools](https://rubysec.com/)
