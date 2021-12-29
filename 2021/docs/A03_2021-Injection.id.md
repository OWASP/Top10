# A03:2021 – Injeksi

## Faktor-faktor

| CWEs yang dipetakan | Jumlah kejadian maksimum | Jumlah kejadian rata-rata | Cakupan maksimal | Cakupan rata-rata | Eksploit tertimbang rata-rata | Dampak tertimbang rata-rata | Total peristiwa | Total CVEs |
|:-------------------:|:------------------------:|:-------------------------:|:----------------:|:-----------------:|:-----------------------------:|:---------------------------:|:---------------:|:----------:|
| 33        	      | 19.09%                   | 3.37%                     | 94.04%           | 47.90%            | 7.25                          | 7.15                        | 274,228         | 32,078     |

## Sudut pandang

Injeksi meluncur turun ke posisi tiga. 94% dari aplikasi-aplikasi yang 
dites oleh beberapa bentuk dari injeksi. Yang dapat dicatat dari CWEs meliputi :
*CWE-79: Pengkodean lintas situs*, *CWE-89: injeksi SQL*, and *CWE-73:
Kontrol eksternal dari nama file atau bagian*.

## Gambaran

Sebuah aplikasi riskan untuk diserang ketika:

-   Pengguna memasukkan data yang tidak divalidasi, disaring atau dibersihkan oleh aplikasi.

-   Kueri secara dinamis atau permintaan yang tidak diberikan parameter tanpa konteks-peringatan pengalihan biasanya langsung pada mesin penerjemah.

-   Data berlawanan digunakan di antara parameter pencari pemetaan relasi object (ORM) untuk mengekstraksi tambahan, rekaman sensitif.

-   Data berlawanan biasanya langsung digunakan atau digabungkan. SQL atau perintah mengandung struktur dan data malfungsi dalam perintah kueri dinamis,
    perintah-perintah, atau prosedur tersimpan.

Beberapa injeksi yang biasa terjadi adalah SQL, NoSQL, perintah OS, pemetaan relasi objek(ORM), LDAP, dan bahasa ekspresi(EL) atau injeksi perpustakaan navigasi grafik objek. Konsepnya adalah identik
di antara semua mesin penerjemah. Penelaahan kode sumber adalah metode terbaik dalam mendeteksi apakah aplikasi tersebut beresiko untuk diinjeksi. Testing otomatis
terhadap semua parameter-parameter, headers, URL, cookies, JSON, SOAP, and input data XML sangat disarankan. 
Organisasi dapat menyertakan sumber statik (SAST) dan perangkat tes aplikasi dinamis (DAST) ke dalam CI/CD
pipeline untuk mengidentifikasi pengenalan serpihan-serpihan injeksi sebelum di sebarkan ke produksi.

## Bagaimana cara mencegah
-   Pencegahan injeksi membutuhkan penyimpanan data terpisah dari perintah dan kueri.

-   Pilihan yang disukai adalah menggunakan API yang aman, dimana mencegah penggunaan mesin penerjemah secara keseluruhan
    , menyediakan sebuah tatap muka berparameter, atau migrasi ke perangkat pemetaan relasi objek.

-   Catatan : Bahkan ketika diparameterkan, prosedur tersimpan masih memperkenalkan injeksi 
    SQL jika PL/SQL atau T-SQL menggabungkan kueri dan data atau
    mengeksekusi data yang berlawanan dengan EXECUTE IMMEDIATE or exec().

-   Menggunakan positif atau "daftar putih" pada validasi masukan di sisi server. Ini bukan pertahanan komplit seperti banyak 
    aplikasi membutuhkan karakter spesial, seperti area teks atau APIs untuk aplikasi portabel.

-   Untuk sisa apapun dari kueri dinamis, melewatkan karakter spesial menggunakan sintaks peralihan spesifik 
    untuk mesin penerjemah.

-   Catatan: struktur SQL seperti nama tabel, nama kolom, dan lain sebagainya tidak bisa
    dilewatkan, dan nama struktur yang diberikan pengguna adalah berbahaya. Ini adalah masalah yang sering terjadi
    dalam pelaporan penulisan perangkat lunak.

-   Menggunakan LIMIT dan kontrol SQL lainnya di antara kueri untuk mencegah penyingkapan rekaman data secara massal
    dalam kasus injeksi SQL.

## Contoh skenario serangan

**Skenario #1:** sebuah aplikasi menggunakan data yang tidak terpercaya pada kontruksi dari panggilan SQL yang rawan berikut ini:

String query = "SELECT \* FROM accounts WHERE custID='" +
request.getParameter("id") + "'";

**Skenario #2:** serupa dengan sebuah aplikasi dengan kepercayaan buta dalam frameworks
akan menghasilkan kueri yang masih rawan, (contoh, bahasa kueri hibernate(HQL)):

> Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" +
> request.getParameter("id") + "'");

pada kedua kasus tersebut, penyerang akan memodifikasi nilai parameter ‘id’ pada peramban web 
untuk mengirim :‘ or ‘1’=’1. Sebagai contoh:

http://example.com/app/accountView?id=' or '1'='1

Ini akan merubah arti dari kedua kueri untuk mengembalikan semua rekaman data dari akun tabel. 
Serangan lebih berbahaya dapat merubah atau menghapus data atau bahkan prosedur tersimpan.

## Referensi

-   [OWASP Proactive Controls: Secure Database
    Access](https://owasp.org/www-project-proactive-controls/v3/en/c3-secure-database)

-   [OWASP ASVS: V5 Input Validation and
    Encoding](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: SQL
    Injection,](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) [Command
    Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection),
    and [ORM
    Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection)

-   [OWASP Cheat Sheet: Injection
    Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: SQL Injection
    Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Injection Prevention in
    Java](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html)

-   [OWASP Cheat Sheet: Query
    Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)

-   [OWASP Automated Threats to Web Applications –
    OAT-014](https://owasp.org/www-project-automated-threats-to-web-applications/)

-   [PortSwigger: Server-side template
    injection](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)

## Daftar dari Pemetaan CWEs

CWE-20 Validasi masukan yang tidak wajar

CWE-74 Naturalisasi yang tidak wajar dari elemen khusus dalam keluaran yang digunakan oleh komponen hilir ('Injeksi')

CWE-75 Kegagalan untuk membersihkan elemen spesial ke dalam sebuah plane yang berbeda          
(Injeksi elemen khusus)

CWE-77 Naturalisasi yang tidak wajar dari elemen khusus yang digunakan dalam perintah
('Injeksi perintah')

CWE-78 Naturalisasi yang tidak wajar dari elemen khusus yang digunakan dalam sebuah perintah OS
('Injeksi perintah OS')

CWE-79 Naturalisasi yang tidak wajar dari masukan selama proses memunculkan halaman web
('Pengkodean lintas situs')

CWE-80 Naturalisasi yang tidak wajar dari kode terkait HTML tags dalam sebuah halaman web
(XSS dasar)

CWE-83 Naturalisasi yang tidak wajar dari kode dalam atribut dalam sebuah halaman web

CWE-87 Naturalisasi yang tidak wajar dari sintaks alternatif XSS 

CWE-88 Naturalisasi yang tidak wajar dari pemisah argumen dalam sebuah perintah
('Injeksi argumen')

CWE-89 Naturalisasi yang tidak wajar dari elemen khusus yang digunakan dalam sebuah perintah SQL
('Injeksi SQL')

CWE-90 Naturalisasi yang tidak wajar dari elemen khusus yang digunakan dalam kueri LDAP
('Injeksi LDAP')

CWE-91 Injeksi XML (alias Blind XPath Injection)

CWE-93 Naturalisasi yang tidak wajar dari urutan CRLF  ('Injeksi CRLF')

CWE-94 Kontrol yang tidak wajar dari kode yang digenerasi ('Injeksi kode')

CWE-95 Naturalisasi yang tidak wajar dari arahan dalam kode yang dievaluasi secara dinamis ('Injeksi eval')

CWE-96 Naturalisasi yang tidak wajar pada arahan dalam kode yang disimpan secara statis
('Injeksi kode statis')

CWE-97 Naturalisasi yang tidak wajar pada sisi server meliputi (SSI) di antara sebuah halaman web

CWE-98 Kontrol yang tidak wajar dari nama berkas untuk menyertakan atau membutuhkan pernyataan dalam program PHP
('Penyertaan berkas remote PHP')

CWE-99 Kontrol yang tidak wajar dari sumber daya pengenal ('Injeksi sumber daya')

CWE-100 Kedaluwarsa ; sebelumnya terkait semua masalah validasi masukan

CWE-113 Naturalisasi yang tidak wajar dari urutan CRLF Sequences dalam HTTP Headers ('Pemisahan respon HTTP')

CWE-116 Pengkodean enkode yang tidak wajar atau melewatkan keluaran

CWE-138 Naturalisasi yang tidak wajar dari elemen khusus

CWE-184 Daftar yang tidak komplit atau input yang tidak diperbolehkan

CWE-470 Penggunaan dari masukan yang dikontrol secara eksternal untuk memilih kelas-kelas atau kode
('Pencerminan yang tidak aman')

CWE-471 Modifikasi dari data yang diasumsikan tidak pernah usang(MAID)

CWE-564 SQL Injeksi : Hibernate

CWE-610 Referensi yang dikontrol secara eksternal untuk sebuah sumber daya dalam lapisan lainnya

CWE-643 Naturalisasi yang tidak wajar dari data di antara ekspresi XPath ('Injeksi XPath')

CWE-644 Naturalisasi yang tidak wajar dari HTTP Headers untuk naskah kode

CWE-652 Naturalisasi yang tidak wajar diantara ekspresi XQuery
('Injeksi XQuery')

CWE-917 Naturalisasi yang tidak wajar dari elemen khusus yang digunakan dalam sebuah
pernyataan bahasa ekspresi('Injeksi bahasa ekspresi')
