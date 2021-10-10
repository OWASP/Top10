# A04:2021 – Insecure Design

## Faktor

| Pemetaan CWE | Rasio Maks Insiden | Rata-rata Rasio Insiden | Cakupan Maks | Rata-rata Cakupan | Rata-rata besaran Eksploitasi | Rata-rata besaran dampak | Total Kejadian | Total CVE |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 40          | 24.19%             | 3.00%              | 77.25%       | 42.51%       | 6.46                 | 6.78                | 262,407           | 2,691      |

## Tinjauan

kategori baru untuk OWASP 2021 ini berfokus pada resiko yang berhubungan
ke desain dan kekurangan arsitektur, kategori ini mencakup penggunaan
permodelan ancaman, design pattern yang jauh lebih aman dan referensi arsitektur.
Penting bahwa CWE termasuk *CWE-209: Generation of Error Message Containing Sensitive Information*,
*CWE-256: Unprotected Storage of Credentials*, CWE-501: Trust Boundary
Violation*, dan *CWE-522: Insufficiently Protected Credentials*.

## Deskripsi

Desain yang tidak aman adalah sebuah representasi kategori yang luas
dari banyak perbedaan kelemahan, yang diekspresikan sebagai "desain
kontrol yang tidak ada atau kurang efisien." desain tidak aman
yang hilang adalah dimana tidak ada nya kontrol(absen). Sebagai contoh,
bayangkan sebuah code/class yang seharusnya mengenkripsikan data sensitif,
tetapi saat implementasinya tidak ada atau tidak dipakai. Sedangkan
desain tidak aman yang kurang efektif adalah dimana sebuah ancaman dapat
terealisasi tetapi karena ada nya kurang nya validasi logic domain(business)
sehingga hal tersebut dapat tercegah. Sebagai contoh, bayangkan logika domain
yang seharusnya untuk memproses keringanan pajak yang berdasarkan
golongan pendapatan tidak dapat memvalidasi bahwa semua input telah
ditandai dengan benar dan bahkan memberikan keringanan pajak yang sangat banyak
daripada yang seharusnya diberikan.

Desain yang aman adalah sebuah budaya dan metodologi yang secara konstan
mengevaluasi ancaman dan memastikan bahwa kode yang telah didesain dan dites
sudah kuat untuk mencegah metode penyerangan yang telah diketahui.
Desain yang aman membutuhkan sebuah alur pengembangan yang aman, 
seperti desain pattern yang aman, komponen library, tooling dan permodelan untuk ancaman.

## Cara Mencegah

-   Buat dan gunakan alur pengembangan amana dengan
    profesional untuk membantu dalam mengevaluasi dan mendesain keamanan
    serta kontrol yang terkait privasi

-   Bust dan gunakan sebuah library dari design pattern yang aman
    atau gunakan komponen yang sudah dapat dipakai. 

-   Gunakan permodelan ancaman untuk autentikasi genting, kontrol akses
    business logic dan key flows.

-   Tulis unit dan tes integrasi untuk memvalidasi bahwa semua aliran
    genting tahan ke permodelan ancaman.

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

-   \[OWASP Cheat Sheet: Secure Design Principles\] (TBD)

-   NIST - Pedoman Standar Minimum Untuk Verivikasi Pengembang Dari
    > Perangkat Lunak
    > https://www.nist.gov/system/files/documents/2021/07/09/Developer%20Verification%20of%20Software.pdf

## Daftar Pemetaan CWE

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
