# A9:2017 Menggunakan Komponen yang Diketahui Rentan

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl : Exploitability 2 | Prevalence 3 : Detectability 2 | Technical 2 : Business |
| Meskipun mudah untuk menemukan eksploitasi yang telah tercatat dalam banyak kasus kerentanan yang telah diketahui, kerentanan lain yang belum diketahui membutuhkan usaha yang lebih dalam mengembangkan sebuah Custom Exploit. | Tingkat kelaziman mengenai permasalahan ini sangat luas. Komponen yang sulit dalam pola pengembangan dapat menyebabkan tim pengembangan bahkan kurang mengerti mengenai komponen yang mereka gunakan dalam aplikasi mereka atau pada API, apalagi menjaganya agar tetap mutakhir. beberapa sistem pemindai seperti retire.js dapat membantu dalam pendeteksian, tetapi dalam mengetahui exploitability membutuhkan upaya tambahan | sementara itu, dalam beberapa kasus kerentanan yang diketahui hanya menyebabkan dampak kecil, beberapa pelanggaran terbesar hingga saat ini mengandalkan pengeksploitasian kerentanan yang ada dalam komponen, bergantung dalam aset yang anda sedang lindungi, kemungkinan resiko seperti ini harus berada pada urutan teratas dalam daftar kerentanan |

## Apakah aplikasi rentan?

Tampaknya aplikasi anda rentan:

* Jika anda tidak tahu versi dari semua komponen yang digunakan (bagian client maupun server). Ini juga termasuk Komponen yang langsung anda gunakan sebagai komponen yang bergantung satu sama lain (nested dependencies).
* Jika software rentan, tidak mendukung, atau masa aktif telah habis. Termasuk juga OS, web/aplikasi server, database management system (DBMS), aplikasi, API dan semua komponen, lingkungan berjalannya program, dan libarynya.
* Jika anda tidak melakukan scanning vulnerabilities secara teratur dan mengikuti kabar keamanan  terkait dengan komponen yang anda gunakan
* Jika anda tidak memperbaiki atau memperbarui platform yang mendasarinya, frameworks, dan dependencies yang termasuk dalam risk-based secara berkala. Ini biasanya terjadi pada environments saat penutupan celah sebagai tugas setiap bulan atau kuarter pada masa kontrol perubahan, yang mana organisasi telah membiarkan beberapa hari atau bulan akan pengerjaan tidak penting untuk pembenaran celah 
* Jika software deplopers tidak melakukan test terhadap kesesuaian update, upgrade atau pembaruan libary.
* Jika anda tidak mengamankan konfigurasi komponen (lihat **A6:2017-Security Misconfiguration**).

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

* [OWASP Application Security Verification Standard: V1 Architecture, design and threat modelling](https://wiki.owasp.org/index.php/ASVS_V1_Architecture)
* [OWASP Dependency Check (for Java and .NET libraries)](https://wiki.owasp.org/index.php/OWASP_Dependency_Check)
* [OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)](https://wiki.owasp.org/index.php/Map_Application_Architecture_(OTG-INFO-010))
* [OWASP Virtual Patching Best Practices](https://wiki.owasp.org/index.php/Virtual_Patching_Best_Practices)

### External

* [The Unfortunate Reality of Insecure Libraries](https://www.aspectsecurity.com/research-presentations/the-unfortunate-reality-of-insecure-libraries)
* [MITRE Common Vulnerabilities and Exposures (CVE) search](https://www.cvedetails.com/version-search.php)
* [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
* [Retire.js for detecting known vulnerable JavaScript libraries](https://github.com/retirejs/retire.js/)
* [Node Libraries Security Advisories](https://nodesecurity.io/advisories)
* [Ruby Libraries Security Advisory Database and Tools](https://rubysec.com/)
