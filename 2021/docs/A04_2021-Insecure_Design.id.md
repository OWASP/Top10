# A04:2021 – Insecure Design

## Faktor-Faktor

| Klasifikasi CWE | Tingkat Kejadian Maksimum | Rata - Rata Tingkat kejadian | Cakupan Maksimum | Rata - Rata Cakupan | Rata-rata Bobot Eksploitasi | Rata - Rata Bobot Dampak | Total Kejadian | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 40          | 24.19%             | 3.00%              | 77.25%       | 42.51%       | 6.46                 | 6.78                | 262,407           | 2,691      |

## Tinjauan

Kategori baru untuk 2021 ini berfokus pada resiko yang berhubungan ke desain dan kekurangan arsitektur, kategori ini mencakup penggunaan permodelan ancaman, design pattern yang jauh lebih aman dan referensi arsitektur. Sebagai sebuah komunitas kami perlu bergerak lebih dari "shift-left" dalam ruang pengodean untuk aktivitas-aktivtas pra-kode yang kritis bagi prinsip-prinsip Aman dari Disain. Contoh CWE termasuk *CWE-209: Generation of Error Message Containing Sensitive Information*, *CWE-256: Unprotected Storage of Credentials*, CWE-501: Trust Boundary Violation*, dan *CWE-522: Insufficiently Protected Credentials*.

## Deskripsi

Desain yang tidak aman adalah sebuah representasi kategori yang luas dari banyak kelemahan yang berbeda, yang diekspresikan sebagai "desain kontrol yang tidak ada atau kurang efisien." Desain tidak aman bukan sumber dari semua kategori risiko Top 10 yang lain. Ada perbedaan antara desain tidak aman dan implementasi tidak aman. Kami membedakan antara cacat desain dan kerusakan implementasi karena suatu alasan, mereka memiliki root cause dan remediasi yang berbeda. Sebuah desain aman masih bisa memiliki kerusakan implementasi yang mengarah ke kerentanan yang dapat dieksploitasi. Suatu desain tidak aman tidak dapat diperbaiki oleh sebuah implementasi yang sempurna karena menurut definisi, kendali keamanan yang diperlukan tidak pernah dibuat untuk bertahan terhadap serangan tertentu. Satu dari faktor yang berkontribusi terhadap desain tidak aman adalah ketiadaan pembuatan profil risiko bisnis yang inheren dalam perangkat lunak atau sistem yang sedang dikembangkan, maka menjadi kegagagalan untuk menentukan desain keamanan level apa yang diperlukan.

### Persyaratan dan Manajemen Sumber Daya

Kumpulkan dan negosiasikan persyaratan bisnis bagi suatu aplikasi dengan pemilik bisnis, termasuk persyaratan perlindungan menyangkut kerahasiaan, integritas, ketersediaan, dan otentisitas dari semua aset data dan logika bisnis yang diharapkan. Perhitungkan akan seberapa terpapar aplikasi Anda dan bila Anda perlu segregasi tenant (sebagai tambahan ke kendali akses). Kompail persyaratkan teknis, termasuk persyaratan keamanan fungsional dan non-fungsional. Rencanakan dan negosiasikan budget yang mencakup semua desain, build, uji coba, dan operasi, termasuk aktivitas-aktivitas keamanan.

### Desain Aman

Desain yang aman adalah sebuah budaya dan metodologi yang secara konstan mengevaluasi ancaman dan memastikan bahwa kode yang telah didesain dan dites sudah kuat (robust) untuk mencegah metode penyerangan yang telah diketahui. Pemodelan ancaman mesti diintegrasikan ke sesi-sesi 'refinement' (atau aktivitas-aktivitas serupa); cari perubahan dalam aliran data dan kendali akses atau kendali keamanan lain. Dalam pengembangan cerita pengguna tentukan aliran yang benar dan keadaan-keadaan gagal, memastikan bahwa mereka dipahami dengan baik dan disetujui oleh pihak-pihak yang bertanggung jawab dan terdampak. Analisis asumsi dan kondisi bagi aliran gagal dan yang diharapkan, pastikan bahwa mereka masih akurat dan dikehendaki. Tentukan bagaimana memvalidasi asumsi dan menegakkan kondisi yang diperlukan untuk perilaku yang layak. Pastikan hasil didokumentasikan dalam cerita pengguna. Belajar dari kesalahan dan tawarkan insentif positif untuk mempromosikan perbaikan. Desain aman bukanlah tambahan atau perkakas yang dapat Anda tambahkan ke perangkat lunak.

### Siklus Hidup Pengembangan Aman

Perangkat lunak aman memerlukan sebuah siklus hidup pengembangan aman, beberapa bentuk pola desain aman, metodologi 'paved road', pustaka komponen yang diamankan, 'tooling', dan pemodelan ancaman. Hubungi spesialis keamanan Anda di awal proyek perangkat lunak untuk keseluruhan proyek dan pemeliharaan perangkat lunak Anda. Pertimbangkan untuk memanfaatkan Software Assurance Maturity Model (SAMM) untuk membantu menstrukturkan upaya pengembangan perangkat lunak aman Anda.

## Cara Mencegah

-   Buat dan gunakan alur pengembangan aman dengan profesional untuk membantu dalam mengevaluasi dan mendesain keamanan serta kontrol yang terkait privasi
-   Buat dan gunakan sebuah pustaka dari design pattern yang aman atau gunakan komponen yang sudah dapat dipakai
-   Gunakan permodelan ancaman untuk autentikasi genting, kontrol akses, business logic, dan key flows
-   Integrasikan kendali dan bahasa keamanan ke dalam cerita pengguna
-   Integrasikan uji plausabilitu pada setiap tier dari aplikasi Anda (dari frontend ke backend)
-   Tulis tes unit dan tes integrasi untuk memvalidasi bahwa semua aliran genting tahan ke permodelan ancaman. Kompail use-case dan misuse-case bagi setiap tier aplikasi Anda
-   Segregasikan lapisan tier pada sistem dan lapisan jaringa bergantung pada kebutuhan eksposur dan proteksi
-   Segregasikan tenant secara robust dengan desain pada seluruh tier
-   Batasi konsumsi sumber daya oleh pengguna atau layanan

## Contoh Skenario Penyerang

**Skenario #1:** Sebuah alur kerja untuk pemulihan kredensial mungkin
termasuk "Pertanayaan dan Jawaban" Dimana telah di larang oleh NIST 800-63b,
OWASP ASVS dan OWASP TOP 10. Pertanyaan dan Jawaban tidak dapat dipercayai
sebagai bukti dari identitas dimana bisa jadi jawaban diketaui lebih
dari satu orang, dimana inilah mengapa mereka di larang. Kode seperti
tersebut harus di hilangkan dan di ganti dengan desain yang lebih aman.

**Skenario #2:** Sebuah bioskop memungkinkan agar mendapatkan diskon bila
membooking secara grup dan memiliki maksimal 15 peserta sebelum memerlukan deposit.
Penyerang dapat memodelkan sebuah ancaman untuk alur ini dan mereka melakukan
pengujian apaklah mereka dapat membooking enam ratus kursi dan semua bioskop
dalam satu waktu dengan request yang sedikit, hal ini menyebabkan hilangnya pemasukan
secara besar-besaran oleh bioskop tersebut.

**Skenario #3:**  Sebuah rantai retail e-commerce website tidak memiliki 
perlindungan dari bot yang dijalankan oleh "Scalper" untuk membeli kartu grafis
kelas tinggi untuk dijual kembali diwebsite tersebut. hal ini membuat image jelek dari
pembuat kartu grafis dan pemiliki rantai retail dan membuat penggemar kecewa
dikarenakan tidak dapat mendapat kartu ini dalam harga apapun. hati-hati juga
desain anti-bot dan aturan logika domain, seperti membeli dengan beberapa detik
ketersediaan dapat kemungkinan mengidentifikasikan pembelian tidak autentik
dan menolak beberapa transaksi.

## Referensi

-   [OWASP Cheat Sheet: Secure Design Principles](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html)

-   NIST - Pedoman Standar Minimum Untuk Verivikasi Pengembang Dari
    > Perangkat Lunak
    > https://nvlpubs.nist.gov/nistpubs/ir/2021/NIST.IR.8397.pdf

## Daftar Klasifikasi CWE

CWE-73 External Control of File Name or Path

CWE-183 Permissive List of Allowed Inputs

CWE-209 Generation of Error Message Containing Sensitive Information

CWE-213 Exposure of Sensitive Information Due to Incompatible Policies

CWE-235 Improper Handling of Extra Parameters

CWE-256 Unprotected Storage of Credentials

CWE-257 Storing Passwords in a Recoverable Format

CWE-266 Incorrect Privilege Assignment

CWE-269 Improper Privilege Management

CWE-280 Improper Handling of Insufficient Permissions or Privileges

CWE-311 Missing Encryption of Sensitive Data

CWE-312 Cleartext Storage of Sensitive Information

CWE-313 Cleartext Storage in a File or on Disk

CWE-316 Cleartext Storage of Sensitive Information in Memory

CWE-419 Unprotected Primary Channel

CWE-430 Deployment of Wrong Handler

CWE-434 Unrestricted Upload of File with Dangerous Type

CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request
Smuggling')

CWE-451 User Interface (UI) Misrepresentation of Critical Information

CWE-472 External Control of Assumed-Immutable Web Parameter

CWE-501 Trust Boundary Violation

CWE-522 Insufficiently Protected Credentials

CWE-525 Use of Web Browser Cache Containing Sensitive Information

CWE-539 Use of Persistent Cookies Containing Sensitive Information

CWE-579 J2EE Bad Practices: Non-serializable Object Stored in Session

CWE-598 Use of GET Request Method With Sensitive Query Strings

CWE-602 Client-Side Enforcement of Server-Side Security

CWE-642 External Control of Critical State Data

CWE-646 Reliance on File Name or Extension of Externally-Supplied File

CWE-650 Trusting HTTP Permission Methods on the Server Side

CWE-653 Insufficient Compartmentalization

CWE-656 Reliance on Security Through Obscurity

CWE-657 Violation of Secure Design Principles

CWE-799 Improper Control of Interaction Frequency

CWE-807 Reliance on Untrusted Inputs in a Security Decision

CWE-840 Business Logic Errors

CWE-841 Improper Enforcement of Behavioral Workflow

CWE-927 Use of Implicit Intent for Sensitive Communication

CWE-1021 Improper Restriction of Rendered UI Layers or Frames

CWE-1173 Improper Use of Validation Framework
