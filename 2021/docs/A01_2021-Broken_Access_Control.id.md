# A01:2021 – Kerusakan Akses Kontrol

## Faktor-Faktor

| CWEs Mapped | Max Incidence Rate | Rata-Rata Incidence Rate | Max Coverage | Rata-Rata Coverage | Rata-Rata Weighted Exploit | Rata-Rata Weighted Impact | Total Kejadian | Total CVEs |
| :---------: | :----------------: | :----------------------: | :----------: | :----------------: | :------------------------: | :-----------------------: | :------------: | :--------: |
|     34      |       55.97%       |          3.81%           |    94.55%    |       47.72%       |            6.92            |           5.93            |    318,487     |   19,013   |

## Gambaran

Bergerak ke atas dari posisi ke 5, 94% aplikasi di tes untuk untuk berbagai jenis dari broken access control. CWE (Common Weakness Enumeration) atau kelemahan enumerasi umum yang perlu diperhatikan termasuk dari _CWE-200: Exposure of Sensitive Information to an Unauthorized Actor_, _CWE-201: Exposure of Sensitive Information Through Sent Data_, and _CWE-352: Cross-Site Request Forgery_.

## Deskripsi

Akses Kontrol menetapkan sebuah peraturan yang dimana user tidak dapat melakukan sebuah aksi diluar permission yang diberikan. Kegagalan atas hal ini dapat mengakibatkan pengeluaran informasi yang tidak diizinkan, modifikasi, atau penghancuran dari semua data atau pemberlakuan sebuah fungsi bisnis di luar limit sebuah user. Kelemahan Akses Kontrol termasuk dari :

Melewati pengecekan akses kontrol dengan memodifikasi URL, internal application state, atau HTML page, atau menggunakan custom API attack tool.

Membolehkan primary key untuk dapat diganti ke record user lain, membolehkan penglihatan atau perubahan akun orang lain.

Penaikan sebuah privilege (Elevation Privilege). Yang dimana sebuah orang dapat dianggap sebagai user tanpa melakukan logged in dan yang dimana sebuah user dapat dianggap sebagai admin tanpa melakukan logged in.

Manipulasi metadata, seperti memanipulasi dengan JSON Web Token (JWT) akses kontrol token, atau memanipulasi cookie atau hidden field untuk menaikan privilege (elevation privilege) atau menyalahgunakan penggunaan dari JWT invalidation.

Konfigurasi yang salah pada CORS sehingga menyebabkan API akses yang tidak diizinkan.

Force browsing untuk mengakses authenticated pages sebagai unauthenticated user atau mengakses privileged pages sebagai user standard. Mengakses API yang tidak memiliki akses kontrol untuk POST, PUT, dan DELETE.

## Cara Mencegah

Akses Kontrol hanya efektif pada kode server-side yang dapat dipercaya dan server-less API, yang dimana penyerang tidak dapat memodifikasi pengecek akses kontrol atau meta datanya.

- Menolak semua akses kecuali ke public resource.

- Melakukan implementasi mekanisme akses kontrol sekali dan digunakan kembali pada seluruh aplikasi sehingga meminimalisir penggunaan CORS.

- Agar user tidak dapat melakukan create, read, update, atau mendelete record secara bebas, model akses kontrol seharusnya membatasi hal tersebut dengan menggunakan ownership untuk tiap record.

- Batas yang diperlukan oleh bisnis yang unik pada aplikasi seharusnya dilakukan oleh domain models.

- Nonaktifkan direktori listing web server dan pastikan file metadata (contohnya .git) dan file backup tidak ada di dalam web roots.

- Catat kegagalan akses kontrol dan alert admin jika diperlukan (seperti adanya kegagalan yang terjadi berulang - ulang).

- Ukur batasan dari API dan akses ke kontroler untuk meminimalisir kerusakan dari automated attack tooling.

- JWT tokens harus langsung di hilangkan validasinya pada server setelah logout.

Developers and QA staff should include functional access control unit
and integration tests.

## Contoh Skenario Penyerangan

**Skenario #1:** Aplikasi menggunakan data yang belum diverifikasi pada sebuah pemanggilan SQL yang mengakses informasi akun

> pstmt.setString(1, request.getParameter("acct"));
>
> ResultSet results = pstmt.executeQuery( );

Penyerang hanya perlu untuk memodifikasi parameter ‘acct’ pada browser untuk mengirim nomer akun mana yang diinginkan. Jika parameter tersebut tidak diverifikasi secara benar, maka penyerang dapat mengakses akun user manapun.

https://example.com/app/accountInfo?acct=notmyacct

**Skenario #2:** Penyerang dapat memaksa untuk melakukan penjelajahan ke target URLs. Halaman Admin memerlukan hak admin untuk dapat diakses.

> https://example.com/app/getappInfo
>
> https://example.com/app/admin_getappInfo

Jika sebuah user yang belum di autentikasi dapat mengakses kedua page tersebut maka itu merupakan suatu kelemahan. Jika user yang non-admin dapat mengakses halaman admin, maka merupakan suatu kelemahan.

## Referensi

- [OWASP Proactive Controls: Enforce Access
  Controls](https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls)

- [OWASP Application Security Verification Standard: V4 Access
  Control](https://owasp.org/www-project-application-security-verification-standard)

- [OWASP Testing Guide: Authorization
  Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)

- [PortSwigger: Exploiting CORS
  misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)

## Daftar Pemetaan CWE

CWE-22 Improper Limitation of a Pathname to a Restricted Directory
('Path Traversal')

CWE-23 Relative Path Traversal

CWE-35 Path Traversal: '.../...//'

CWE-59 Improper Link Resolution Before File Access ('Link Following')

CWE-200 Exposure of Sensitive Information to an Unauthorized Actor

CWE-201 Exposure of Sensitive Information Through Sent Data

CWE-219 Storage of File with Sensitive Data Under Web Root

CWE-264 Permissions, Privileges, and Access Controls (should no longer
be used)

CWE-275 Permission Issues

CWE-276 Incorrect Default Permissions

CWE-284 Improper Access Control

CWE-285 Improper Authorization

CWE-352 Cross-Site Request Forgery (CSRF)

CWE-359 Exposure of Private Personal Information to an Unauthorized
Actor

CWE-377 Insecure Temporary File

CWE-402 Transmission of Private Resources into a New Sphere ('Resource
Leak')

CWE-425 Direct Request ('Forced Browsing')

CWE-441 Unintended Proxy or Intermediary ('Confused Deputy')

CWE-497 Exposure of Sensitive System Information to an Unauthorized
Control Sphere

CWE-538 Insertion of Sensitive Information into Externally-Accessible
File or Directory

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
