# A01:2021 – Kontrol Akses yang Rusak      ![icon](assets/TOP_10_Icons_Final_Broken_Access_Control.png){: style="height:80px;width:80px" align="right"}

## Faktor-Faktor

| CWE Dipetakan | Tingkat Kejadian Maksimum | Rata-Rata Tingkat Kejadian | Cakupan Maksimum | Rata-Rata Cakupan | Rata-rata Bobot Eksploitasi | Rata-Rata Bobot Dampak | Total Kejadian | Total CVE | 
| :---------: | :----------------: | :----------------------: | :----------: | :----------------: | :------------------------: | :-----------------------: | :------------: | :--------: | 
|     34      |       55,97%       |          3,81%           | 94,55%    |       47,72%       |            6,92            |           5,93 |    318.487     |   19.013   |

## Gambaran

Bergerak ke atas dari posisi ke 5, 94% aplikasi diuji untuk untuk berbagai jenis
dari broken access control. CWE (Common Weakness Enumeration) atau kelemahan
enumerasi umum yang perlu diperhatikan termasuk dari _CWE-200: Exposure of
Sensitive Information to an Unauthorized Actor_, _CWE-201: Exposure of Sensitive
Information Through Sent Data_, dan _CWE-352: Cross-Site Request Forgery_.

## Deskripsi

Kontrol akses memberlakukan sebuah kebijalan sedemikian rupa sehingga pengguna
tidak dapat bertindak di luar izin yang dimaksudkan. Kegagalan biasanya mengarah
pada pengungkapan informasi yang tidak diizinkan, modifikasi, atau penghancuran
dari semua data atau menjalankan sebuah fungsi bisnis di luar batas pengguna.
Kelemahan umum kontrol akses termasuk:

-   Pelanggaran prinsip privilese terkecil (least privilege) atau penolakan baku
    (deny by default), dimana akses semestinya hanya diberikan untuk
    kapabilitas, peran, atau pengguna tertentu, tapi tersedia untuk siapa pun.

-   Melewati pengecekan kontrol akses dengan memodifikasi URL (parameter
    tampering atau force browsing), state aplikasi internal, atau halaman HTML,
    atau menggunakan alat serang yang memodifikasi permintaan API.

-   Mengizinkan melihat atau mengedit akun orang lain, dengen menyediakan
    identifier uniknya (insecure direct object references).

-   Mengakses API dengan kontrol akses yang kurang untuk POST, PUT dan DELETE.

-   Penaikan sebuah privilese (Elevation of privilege).  Bertindak sebagai
    seorang pengguna tanpa login atau bertindak sebagai seorang admin ketika
    login sebagai pengguna.

-   Manipulasi metadata, seperti memakai ulang atau mengubah token kontrol akses
    JSON Web Token (JWT), atau memanipulasi cookie atau hidden field untuk
    menaikan privilese (elevation privilege) atau menyalahgunakan JWT 
    invalidation.

-   Salah konfigurasi CORS sehingga mengizinkan akses API dari asal yang tidak
    terotorisasi/tak terpercaya.

-   Force browsing untuk mengakses halaman terotentikasi sebagai pengguna tak
    terotentikasi atau mengakses privileged pages sebagai pengguna standar. 

## Cara Mencegah

Kontrol akses hanya efektif pada kode server-side yang dapat dipercaya atau
server-less API, dimana penyerang tidak dapat memodifikasi pemeriksaan kontrol
akses atau meta data.

-   Menolak semua akses kecuali ke sumber daya publik.

-   Melakukan implementasi mekanisme kontrol akses sekali dan digunakan kembali
    pada seluruh aplikasi sehingga meminimalisir penggunaan Cross-Origin Resource
    Sharing (CORS).

-   Agar user tidak dapat melakukan create, read, update, atau delete record
    secara bebas, model kontrol akses seharusnya membatasi hal tersebut dengan
    menggunakan ownership untuk tiap record.

-   Batas yang diperlukan oleh bisnis yang unik pada aplikasi seharusnya dilakukan
    oleh domain models.

-   Nonaktifkan direktori listing web server dan pastikan file metadata (contohnya
    .git) dan file backup tidak ada di dalam web root.

-   Catat kegagalan kontrol akses dan alert admin jika diperlukan (seperti
    kegagalan berulang).

-   Batasi laju akses kontroler dan API untuk meminimalisir kerusakan dari
    automated attack tooling.

-   Identifier sesi stateful mesti di-invalidasi pada server setelah logout.
    Token JWT stateless mesti agak berumur pendek sehingga jendela kesempatan
    bagi penyerang diminimalkan. Untuk JWT yang berumur lebih panjang sangat
    disarankan untuk mengikuti standar OAuth untuk mencabut akses.

Pengembang dan staf QA mesti menyertakan unit kontrol akses fungsional dan uji
integrasi.

## Contoh Skenario Penyerangan

**Skenario #1:** Aplikasi menggunakan data yang belum diverifikasi pada sebuah
pemanggilan SQL yang mengakses informasi akun:
```
 pstmt.setString(1, request.getParameter("acct"));
 ResultSet results = pstmt.executeQuery( );
```
Penyerang hanya perlu untuk memodifikasi parameter ‘acct’ pada browser untuk
mengirim nomor akun mana yang diinginkan. Jika tidak diverifikasi secara benar, 
maka penyerang dapat mengakses akun user mana pun.
```
https://example.com/app/accountInfo?acct=notmyacct
```
**Skenario #2:** Penyerang dapat memaksa untuk melakukan penjelajahan ke URL 
target. Hak admin diperlukan untuk mengakses halaman admin.
```
https://example.com/app/getappInfo
https://example.com/app/admin_getappInfo
```

Jika sebuah user yang belum diautentikasi dapat mengakses kedua halaman tersebut
maka itu merupakan suatu kelemahan. Jika user yang non-admin dapat mengakses
halaman admin, maka merupakan suatu kelemahan.

## Referensi

- [OWASP Proactive Controls: Enforce Access
  Controls](https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls)

- [OWASP Application Security Verification Standard: V4 Access
  Control](https://owasp.org/www-project-application-security-verification-standard)

- [OWASP Testing Guide: Authorization
  Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)

- [PortSwigger: Exploiting CORS
  misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)

## Daftar CWE Dipetakan

CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path
Traversal')

CWE-23 Relative Path Traversal

CWE-35 Path Traversal: '.../...//'

CWE-59 Improper Link Resolution Before File Access ('Link Following')

CWE-200 Exposure of Sensitive Information to an Unauthorized Actor

CWE-201 Exposure of Sensitive Information Through Sent Data

CWE-219 Storage of File with Sensitive Data Under Web Root

CWE-264 Permissions, Privileges, and Access Controls (should no longer be used)

CWE-275 Permission Issues

CWE-276 Incorrect Default Permissions

CWE-284 Improper Access Control

CWE-285 Improper Authorization

CWE-352 Cross-Site Request Forgery (CSRF)

CWE-359 Exposure of Private Personal Information to an Unauthorized Actor

CWE-377 Insecure Temporary File

CWE-402 Transmission of Private Resources into a New Sphere ('Resource Leak')

CWE-425 Direct Request ('Forced Browsing')

CWE-441 Unintended Proxy or Intermediary ('Confused Deputy')

CWE-497 Exposure of Sensitive System Information to an Unauthorized Control
Sphere

CWE-538 Insertion of Sensitive Information into Externally-Accessible File or
Directory

CWE-540 Inclusion of Sensitive Information in Source Code

CWE-548 Exposure of Information Through Directory Listing

CWE-552 Files or Directories Accessible to External Parties

CWE-566 Authorization Bypass Through User-Controlled SQL Primary Key

CWE-601 URL Redirection to Untrusted Site ('Open Redirect')

CWE-639 Authorization Bypass Through User-Controlled Key

CWE-651 Exposure of WSDL File Containing Sensitive Information

CWE-668 Exposure of Resource to Wrong Sphere

CWE-706 Use of Incorrectly-Resolved Name or Reference

CWE-862 Missing Authorization

CWE-863 Incorrect Authorization

CWE-913 Improper Control of Dynamically-Managed Code Resources

CWE-922 Insecure Storage of Sensitive Information

CWE-1275 Sensitive Cookie with Improper SameSite Attribute
