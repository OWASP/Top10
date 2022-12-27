# A04:2021 – Rancangan Tak Aman   ![icon](assets/TOP_10_Icons_Final_Insecure_Design.png){: style="height:80px;width:80px" align="right"} 


## Faktor-Faktor

| CWE Dipetakan | Tingkat Kejadian Maksimum | Rata - Rata Tingkat kejadian | Rata-rata Eksploitasi Terbobot | Rata-rata Dampak Terbobot | Cakupan Maksimum | Rata-rata Cakupan | Total Kejadian | Total CVE |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 40          | 24,19%             | 3,00%              | 6,46                 | 6,78                | 77,25%       | 42,51%       | 262.407           | 2.691      |

## Ringkasan

Kategori baru untuk 2021 ini berfokus pada resiko yang berhubungan ke desain dan kekurangan arsitektur, kategori ini mencakup penggunaan permodelan ancaman, design pattern yang jauh lebih aman dan referensi arsitektur. Sebagai sebuah komunitas kami perlu bergerak lebih dari "shift-left" dalam ruang pengodean untuk aktivitas-aktivtas pra-kode yang kritis bagi prinsip-prinsip Aman dari Disain. Contoh CWE termasuk *CWE-209: Generation of Error Message Containing Sensitive Information*, *CWE-256: Unprotected Storage of Credentials*, *CWE-501: Trust Boundary Violation*, dan *CWE-522: Insufficiently Protected Credentials*.

## Deskripsi

Desain yang tidak aman adalah sebuah representasi kategori yang luas dari banyak kelemahan yang berbeda, yang diekspresikan sebagai "desain kontrol yang tidak ada atau kurang efisien." Desain tidak aman bukan sumber dari semua kategori risiko Top 10 yang lain. Ada perbedaan antara desain tidak aman dan implementasi tidak aman. Kami membedakan antara cacat desain dan kerusakan implementasi karena suatu alasan, mereka memiliki akar masalah dan remediasi yang berbeda. Sebuah desain aman masih bisa memiliki kerusakan implementasi yang mengarah ke kerentanan yang dapat dieksploitasi. Suatu desain tidak aman tidak dapat diperbaiki oleh sebuah implementasi yang sempurna karena menurut definisi, kendali keamanan yang diperlukan tidak pernah dibuat untuk bertahan terhadap serangan tertentu. Satu dari faktor yang berkontribusi terhadap desain tidak aman adalah ketiadaan pembuatan profil risiko bisnis yang inheren dalam perangkat lunak atau sistem yang sedang dikembangkan, maka menjadi kegagagalan untuk menentukan desain keamanan level apa yang diperlukan.

### Persyaratan dan Manajemen Sumber Daya

Kumpulkan dan negosiasikan persyaratan bisnis bagi suatu aplikasi dengan pemilik bisnis, termasuk persyaratan perlindungan menyangkut kerahasiaan, integritas, ketersediaan, dan otentisitas dari semua aset data dan logika bisnis yang diharapkan. Perhitungkan akan seberapa terpapar aplikasi Anda dan bila Anda perlu segregasi tenant (sebagai tambahan ke kendali akses). Kumpulkan persyaratkan teknis, termasuk persyaratan keamanan fungsional dan non-fungsional. Rencanakan dan negosiasikan budget yang mencakup semua desain, build, uji coba, dan operasi, termasuk aktivitas-aktivitas keamanan.

### Desain Aman

Desain yang aman adalah sebuah budaya dan metodologi yang secara konstan mengevaluasi ancaman dan memastikan bahwa kode yang telah didesain dan dites sudah kuat (robust) untuk mencegah metode penyerangan yang telah diketahui. Pemodelan ancaman mesti diintegrasikan ke sesi-sesi 'refinement' (atau aktivitas-aktivitas serupa); cari perubahan dalam aliran data dan kendali akses atau kendali keamanan lain. Dalam pengembangan cerita pengguna tentukan aliran yang benar dan keadaan-keadaan gagal, memastikan bahwa mereka dipahami dengan baik dan disetujui oleh pihak-pihak yang bertanggung jawab dan terdampak. Analisis asumsi dan kondisi bagi aliran gagal dan yang diharapkan, pastikan bahwa mereka masih akurat dan dikehendaki. Tentukan bagaimana memvalidasi asumsi dan menegakkan kondisi yang diperlukan untuk perilaku yang layak. Pastikan hasil didokumentasikan dalam cerita pengguna. Belajar dari kesalahan dan tawarkan insentif positif untuk mempromosikan perbaikan. Desain aman bukanlah tambahan atau perkakas yang dapat Anda tambahkan ke perangkat lunak.

### Siklus Hidup Pengembangan Aman

Perangkat lunak aman memerlukan sebuah siklus hidup pengembangan aman, beberapa bentuk pola desain aman, metodologi 'paved road', pustaka komponen yang diamankan, 'tooling', dan pemodelan ancaman. Hubungi spesialis keamanan Anda di awal proyek perangkat lunak untuk keseluruhan proyek dan pemeliharaan perangkat lunak Anda. Pertimbangkan untuk memanfaatkan [OWASP Software Assurance Maturity Model (SAMM)](https://owaspsamm.org) untuk membantu menstrukturkan upaya pengembangan perangkat lunak aman Anda.

## Cara Mencegah

-   Buat dan gunakan alur pengembangan aman dengan para profesional AppSec
    untuk membantu dalam mengevaluasi dan mendesain keamanan serta kontrol 
    yang terkait privasi

-   Buat dan gunakan sebuah pustaka dari design pattern yang aman atau gunakan 
    komponen jalan beraspal siap pakai

-   Gunakan pemodelan ancaman untuk autentikasi kritis, kontrol akses, logika 
    bisnis, dan alur-alur kunci

-   Integrasikan kendali dan bahasa keamanan ke dalam cerita pengguna

-   Integrasikan uji plausabilitas pada setiap tier dari aplikasi Anda (dari 
    frontend ke backend)

-   Tulis tes unit dan tes integrasi untuk memvalidasi bahwa semua aliran 
    kritis tahan ke pemodelan ancaman. Kompail use-case dan misuse-case bagi 
    setiap tier aplikasi Anda

-   Segregasikan lapisan tier pada sistem dan lapisan jaringan bergantung pada 
    kebutuhan eksposur dan proteksi

-   Segregasikan tenant secara robust dengan desain pada seluruh tier

-   Batasi konsumsi sumber daya oleh pengguna atau layanan

## Contoh Skenario Penyerang

**Skenario #1:** Sebuah alur kerja untuk pemulihan kredensial mungkin
termasuk "pertanyaan dan jawaban" yang telah dilarang oleh NIST 800-63b,
OWASP ASVS, dan OWASP TOP 10. Pertanyaan dan jawaban tidak dapat dipercayai
sebagai bukti dari identitas dimana bisa jadi jawaban diketahui lebih
dari satu orang, dimana inilah mengapa mereka dilarang. Kode seperti
itu harus dihilangkan dan diganti dengan desain yang lebih aman.

**Skenario #2:** Sebuah bioskop memungkinkan agar mendapatkan diskon bila
memesan secara grup dan memiliki maksimal 15 peserta sebelum memerlukan deposit.
Penyerang dapat memodelkan sebuah ancaman untuk alur ini dan mereka melakukan
pengujian apakah mereka dapat memesan enam ratus kursi dan semua bioskop
dalam satu waktu dengan request yang sedikit, hal ini menyebabkan hilangnya pemasukan
secara besar-besaran oleh bioskop tersebut.

**Skenario #3:**  Sebuah situs web e-commerce rantai retail tidak memiliki 
perlindungan dari bot yang dijalankan oleh "scalper" untuk membeli kartu grafis
kelas tinggi untuk dijual kembali di website tersebut. Hal ini membuat image 
jelek dari pembuat kartu grafis dan pemiliki rantai retail dan membuat 
penggemar kecewa dikarenakan tidak bisa mendapat kartu ini pada harga apa pun. 
Hati-hati juga desain anti-bot dan aturan logika domain, seperti pembelian yang
dilakukan beberapa detik setelah ketersediaan mungkin mengidentifikasikan
 pembelian tidak autentik dan menolak beberapa transaksi.

## Referensi

-   [OWASP Cheat Sheet: Secure Design Principles](Segera Hadir)

-   [OWASP SAMM: Design:Security Architecture](https://owaspsamm.org/model/design/security-architecture/)

-   [OWASP SAMM: Design:Threat Assessment](https://owaspsamm.org/model/design/threat-assessment/) 

-   [NIST – Guidelines on Minimum Standards for Developer Verification of Software](https://www.nist.gov/publications/guidelines-minimum-standards-developer-verification-software)

-   [The Threat Modeling Manifesto](https://threatmodelingmanifesto.org)

-   [Awesome Threat Modeling](https://github.com/hysnsec/awesome-threat-modelling)


## Daftar CWE yang Dipetakan

[CWE-73 External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)

[CWE-183 Permissive List of Allowed Inputs](https://cwe.mitre.org/data/definitions/183.html)

[CWE-209 Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)

[CWE-213 Exposure of Sensitive Information Due to Incompatible Policies](https://cwe.mitre.org/data/definitions/213.html)

[CWE-235 Improper Handling of Extra Parameters](https://cwe.mitre.org/data/definitions/235.html)

[CWE-256 Unprotected Storage of Credentials](https://cwe.mitre.org/data/definitions/256.html)

[CWE-257 Storing Passwords in a Recoverable Format](https://cwe.mitre.org/data/definitions/257.html)

[CWE-266 Incorrect Privilege Assignment](https://cwe.mitre.org/data/definitions/266.html)

[CWE-269 Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)

[CWE-280 Improper Handling of Insufficient Permissions or Privileges](https://cwe.mitre.org/data/definitions/280.html)

[CWE-311 Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)

[CWE-312 Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)

[CWE-313 Cleartext Storage in a File or on Disk](https://cwe.mitre.org/data/definitions/313.html)

[CWE-316 Cleartext Storage of Sensitive Information in Memory](https://cwe.mitre.org/data/definitions/316.html)

[CWE-419 Unprotected Primary Channel](https://cwe.mitre.org/data/definitions/419.html)

[CWE-430 Deployment of Wrong Handler](https://cwe.mitre.org/data/definitions/430.html)

[CWE-434 Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)

[CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')](https://cwe.mitre.org/data/definitions/444.html)

[CWE-451 User Interface (UI) Misrepresentation of Critical Information](https://cwe.mitre.org/data/definitions/451.html)

[CWE-472 External Control of Assumed-Immutable Web Parameter](https://cwe.mitre.org/data/definitions/472.html)

[CWE-501 Trust Boundary Violation](https://cwe.mitre.org/data/definitions/501.html)

[CWE-522 Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)

[CWE-525 Use of Web Browser Cache Containing Sensitive Information](https://cwe.mitre.org/data/definitions/525.html)

[CWE-539 Use of Persistent Cookies Containing Sensitive Information](https://cwe.mitre.org/data/definitions/539.html)

[CWE-579 J2EE Bad Practices: Non-serializable Object Stored in Session](https://cwe.mitre.org/data/definitions/579.html)

[CWE-598 Use of GET Request Method With Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html)

[CWE-602 Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)

[CWE-642 External Control of Critical State Data](https://cwe.mitre.org/data/definitions/642.html)

[CWE-646 Reliance on File Name or Extension of Externally-Supplied File](https://cwe.mitre.org/data/definitions/646.html)

[CWE-650 Trusting HTTP Permission Methods on the Server Side](https://cwe.mitre.org/data/definitions/650.html)

[CWE-653 Insufficient Compartmentalization](https://cwe.mitre.org/data/definitions/653.html)

[CWE-656 Reliance on Security Through Obscurity](https://cwe.mitre.org/data/definitions/656.html)

[CWE-657 Violation of Secure Design Principles](https://cwe.mitre.org/data/definitions/657.html)

[CWE-799 Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html)

[CWE-807 Reliance on Untrusted Inputs in a Security Decision](https://cwe.mitre.org/data/definitions/807.html)

[CWE-840 Business Logic Errors](https://cwe.mitre.org/data/definitions/840.html)

[CWE-841 Improper Enforcement of Behavioral Workflow](https://cwe.mitre.org/data/definitions/841.html)

[CWE-927 Use of Implicit Intent for Sensitive Communication](https://cwe.mitre.org/data/definitions/927.html)

[CWE-1021 Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html)

[CWE-1173 Improper Use of Validation Framework](https://cwe.mitre.org/data/definitions/1173.html)

