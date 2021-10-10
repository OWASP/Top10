# A08:2021 - Software and Data Integrity Failures - Gagalnya Menjaga Integritas Data dan Perangkat Lunak
<img src="https://raw.githubusercontent.com/OWASP/Top10/master/2021/docs/assets/TOP_10_Icons_Final_Software_and_Data_Integrity_Failures.png" alt="icon" height=80px width=80px align="center">

## Faktor

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Max Coverage | Avg Coverage | Avg Weighted Exploit | Avg Weighted Impact | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 10          | 16.67%             | 2.05%              | 75.04%       | 45.35%       | 6.94                 | 7.94                | 47,972            | 1,152      |


| Klasifikasi CWE | Tingkat Kejadian Maksimum | Rata - Rata Tingkat Kejadian | Cakupan Maksimum | Rata - Rata Cakupan | Rata - Rata Bobot Exploitasi | Rata - Rata Bobot Dampak | Total Kejadian | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 10          | 16.67%             | 2.05%              | 75.04%       | 45.35%       | 6.94                 | 7.94                | 47,972            | 1,152      |

## Penjelasan Singkat

_A new category for 2021 focuses on making assumptions related to software updates, critical data, and CI/CD pipelines without verifying integrity. One of the highest weighted impacts from Common Vulnerability and Exposures/Common Vulnerability Scoring System (CVE/CVSS) data. Notable Common Weakness Enumerations (CWEs) include CWE-829: Inclusion of Functionality from Untrusted Control Sphere, CWE-494: Download of Code Without Integrity Check, and CWE-502: Deserialization of Untrusted Data._

Kategori baru pada tahun 2021 yang berhubungan dengan pembaharuan perangkat lunak, data penting, dan CI/CD pipeline yang dilakukan tanpa memverifikasi kredibilitasnya.
Berdasarkan data dari CVE/CVSS **Gagalnya Menjaga Integritas Data dan Perangkat Lunak** merupakan salah satu celah keamanan dengan dampak tertinggi.

CWE yang patut diperhatikan *CWE-829: Inclusion of Functionality from Untrusted Control Sphere*,
*CWE-494: Download of Code Without Integrity Check*,
dan *CWE-502: Deserialization of Untrusted Data*.

## Deskripsi
_Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations. An example of this is where an application relies upon plugins, libraries, or modules from untrusted sources, repositories, and content delivery networks (CDNs). An insecure CI/CD pipeline can introduce the potential for unauthorized access, malicious code, or system compromise. Lastly, many applications now include auto-update functionality, where updates are downloaded without sufficient integrity verification and applied to the previously trusted application. Attackers could potentially upload their own updates to be distributed and run on all installations. Another example is where objects or data are encoded or serialized into a structure that an attacker can see and modify is vulnerable to insecure deserialization._

Gagalnya Menjaga Integritas Data dan Perangkat Lunak disebabkan oleh kode dan infrastruktur yang tidak mencegah terjadinya pelanggaran integritas.
Contohnya sebuah objek/data yang telah di enkoding/diserialisasi di dalam struktur yang dapat dilihat dan dimodifikasi oleh penyerang rentan terhadap deserialisasi yang tidak aman.

Contoh lainnya adalah aplikasi yang bergantung pada *plugins*, *libraries*, atau *modules* yang asalnya dari sumber yang tidak dipercaya, repositori - repositori, *Content Delivery Network (CDNs)*.
*CI/CD Pipeline* yang tidak aman dapat menyebabkan munculnya akses illegal/tidak sah, kode yang berbahaya, atau kerusakan sistem.

Terakhir, aplikasi sekarang banyak yang memiliki fitur pembaharuan otomatis, yang dimana pembaharuan - pembaharuan yang ada diunduh tanpa adanya verifikasi integritas dan diterapkan/digunakan terhadap aplikasi yang sebelumnya terpercaya.
Penyerang memiliki kemungkinan besar untuk mengunggah pembaharuan milik mereka sendiri untuk di distribusikan dan dijalankan/diterapkan pada semua instalasi/pembaharuan.

## Bagaimana Cara Mencegahnya
- _Use digital signatures or similar mechanisms to verify the software or data is from the expected source and has not been altered._
- Gunakan tanda tangan digital atau mekanisme yang sama untuk memverifikasi bahwa perangkat lunak atau data berasal dari sumber yang diharapkan dan tidak di manipulasi.

- _Ensure libraries and dependencies, such as npm or Maven, are consuming trusted repositories. If you have a higher risk profile, consider hosting an internal known-good repository that's vetted._
- Pastikan *libaries* dan dependensi seperti npm atau Maven menggunakan repositori yang terpercaya. Apabila anda merupakan target berisiko tinggi, pertimbangkan untuk hos repositori yang dikenal baik dan sudah di periksa kepercayaannya.

- _Ensure that a software supply chain security tool, such as OWASP Dependency Check or OWASP CycloneDX, is used to verify that components do not contain known vulnerabilities._
- Pastikan alat keamanan rantai pasokan perangkat lunak, seperti OWASP Dependency Check atau OWASP CycloneDX digunakan untuk memverifikasi bahwa komponen komponen tersebut tidak memiliki kerentanan yang sudah diketahui.

- _Ensure that there is a review process for code and configuration changes to minimize the chance that malicious code or configuration could be introduced into your software pipeline._
- Pastikan adanya proses review ketika mengubah kode dan konfigurasi untuk meminimalisir kemungkinan kode atau konfigurasi berbahaya masuk ke dalam *pipeline* perangkat lunak anda.

- _Ensure that your CI/CD pipeline has proper segregation, configuration, and access control to ensure the integrity of the code flowing through the build and deploy processes._
- Pastikan *CI/CD pipeline* anda memiliki metode pemisahan, konfigurasi dan akses kontrol yang tepat untuk memastikan integritas kode yang masuk mulai dari proses *build* / pembangunan hinga proses *deployment* / penyebaran perangkat lunak.

- _Ensure that unsigned or unencrypted serialized data is not sent to untrusted clients without some form of integrity check or digital signature to detect tampering or replay of the serialized data_
- Pastikan data yang belum di tanda tangani atau tidak terenkripsi ini tidak terkirim ke klien yang tidak dipercaya tanpa adanya pengecekan integritas atau tanda tangan digital untuk mendeteksi apakah data telah di manipulasi atau pemutaran ulang data yang telah di serialisasi.

## Contoh Skenario Penyerangan
_**Scenario #1 Update without signing:** Many home routers, set-top
boxes, device firmware, and others do not verify updates via signed
firmware. Unsigned firmware is a growing target for attackers and is
expected to only get worse. This is a major concern as many times there
is no mechanism to remediate other than to fix in a future version and
wait for previous versions to age out._

**Skenario #1 Pembaharuan tanpa tanda tangan**: Mayoritas dari router rumahan, decoder, firmware perangkat, dan perangkat lainnya tidak memverifikasi pembaharuan lewat firmware yang telah di tandatangani/sudah valid.
Firmware yang tidak ditandatangani / tidak valid merupakan target yang menarik bagi penyerang dan diperkirakan daya tariknya semakin lama akan semakin tinggi
Hal ini merupakan persoalan/ancaman yang cukup besar karena seringkali tidak ada mekanisme untuk memulihkan/memperbaiki selain memperbaikinya menggunakan versi firmware yang baru dan menunggu versi firmware sebelumnya kadaluarsa.

_**Scenario #2 SolarWinds malicious update**: Nation-states have been
known to attack update mechanisms, with a recent notable attack being
the SolarWinds Orion attack. The company that develops the software had
secure build and update integrity processes. Still, these were able to
be subverted, and for several months, the firm distributed a highly
targeted malicious update to more than 18,000 organizations, of which
around 100 or so were affected. This is one of the most far-reaching and
most significant breaches of this nature in history._

**Skenario #2 Pembaharuan berbahaya SolarWinds**: Serangan siber bertingkat nasional atau serangan yang melibatkan suatu negara / bangsa terkenal dengan serangannya terhadap mekanisme pembaharuan, **SolarWinds Orion attack** merupakan salah satu serangan bertingkat nasional yang patut diperhatikan. Perlu diketahui perusahaan yang mengembangkan SolarWinds memiliki proses pembaharuan yang berintegritas atau aman dan proses pembuatan perangkat lunak yang aman. Meskipun demikian proses yang aman ini masih dapat di tumbangkan atau diganggu, dan selama beberapa bulan perusahaan ini mendistribusikan pembaharuan berbahaya yang ditargetkan ke lebih dari 18.000 organisasi, sekitar 100 atau lebih organisasi terkena dampak dari pembaharuan ini.
Insiden ini termasuk salah satu insiden yang konsekuensi nya dapat berpengaruh besar, mempengaruhi banyak hal dan salah satu insiden yang paling signifikan dalam sejarah **Gagalnya Menjaga Integritas Data dan Perangkat Lunak**.


_**Scenario #3 Insecure Deserialization:** A React application calls a
set of Spring Boot microservices. Being functional programmers, they
tried to ensure that their code is immutable. The solution they came up
with is serializing the user state and passing it back and forth with
each request. An attacker notices the "rO0" Java object signature (in base64) and
uses the Java Serial Killer tool to gain remote code execution on the
application server._

**Skenario #3 Deserialisasi Yang Tidak Aman**: Aplikasi React memanggil satu set layanan mikro Spring Boot. Sebagai programmer fungsional, mereka mencoba memastikan bahwa kode mereka tidak dapat diubah. Solusi yang mereka hasilkan adalah membuat serial status pengguna dan meneruskannya bolak-balik dengan setiap permintaan. Seorang penyerang memperhatikan tanda tangan objek Java "R00", dan menggunakan alat Pembunuh Serial Java untuk mendapatkan eksekusi kode jarak jauh pada server aplikasi.


## Referensi
- [OWASP Cheat Sheet: Software Supply Chain Security] (Akan Segera Datang)
- [OWASP Cheat Sheet: Secure build and deployment] (Akan Segera Datang)
- [OWASP Cheat Sheet: Infrastructure as Code](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)
- [OWASP Cheat Sheet: Deserialization](https://www.owasp.org/index.php/Deserialization_Cheat_Sheet)
- [SAFECode Software Integrity Controls](https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)
- [A 'Worst Nightmare' Cyberattack: The Untold Story Of The SolarWinds Hack](https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack)
- [CodeCov Bash Uploader Compromise](https://about.codecov.io/security-update)
- [Securing DevOps by Julien Vehent](https://www.manning.com/books/securing-devops)

## Daftar Klasifikasi CWE
[CWE-345 Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)

[CWE-353 Missing Support for Integrity Check](https://cwe.mitre.org/data/definitions/353.html)

[CWE-426 Untrusted Search Path](https://cwe.mitre.org/data/definitions/426.html)

[CWE-494 Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)

[CWE-502 Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

[CWE-565 Reliance on Cookies without Validation and Integrity Checking](https://cwe.mitre.org/data/definitions/565.html)

[CWE-784 Reliance on Cookies without Validation and Integrity Checking in a Security Decision](https://cwe.mitre.org/data/definitions/784.html)

[CWE-829 Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)

[CWE-830 Inclusion of Web Functionality from an Untrusted Source](https://cwe.mitre.org/data/definitions/830.html)

[CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
