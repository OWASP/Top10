# A10:2021 – Server-Side Request Forgery (SSRF) 
<img src="https://raw.githubusercontent.com/OWASP/Top10/master/2021/docs/assets/TOP_10_Icons_Final_SSRF.png" alt="icon" height=80px width=80px align="center">

## Faktor-Faktor

| Klasifikasi CWE | Tingkat Kejadian Maksimum | Rata - Rata Tingkat Kejadian  | Cakupan Maximum | Rata - Rata Cakupan | Rata - Rata Bobot Exploitasi | Rata - Rata Bobot Dampak | Total Kejadian | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 1           | 2.72%              | 2.72%              | 67.72%       | 67.72%       | 8.28                 | 6.72                | 9,503             | 385        |

## Penjelasan Singkat

Kategori ini ditambahkan dari survei 10 komunitas teratas (#1). Data ini menunjukan tingkat insiden yang relatif rendah dengan cakupan pengujian di atas rata-rata serta
nilai dampak dan potensial eksploitasi di atas rata-rata. Entri-entri baru kemungkinan besar menjadi cluster kecil atau tunggal dari CWE - CWE karena tingkat atensi dan tingkat kesadarannya, harapannnya entri-entri baru ini dapat menjadi fokusan riset keamanan dan dapat digolongkan/dimasukkan kedalam kategori/cluster yang lebih besar di edisi mendatang.

## Deskripsi

Kecacatan _SSRF_ muncul saat sebuah aplikasi web meminta _remote resource_ tanpa melakukan validasi URL yang di berikan oleh pengguna. Ini memperbolehkan penyerang untuk memaksa aplikasi untuk mengirim _crafted request_ ke destinasi yang tidak diharapkan, meskipun sudah dilindungi oleh _firewall_, VPN, atau tipe lain dari daftar aturan akses jaringan - _Access Control List_ (ACL).

Aplikasi web saat ini menyediakan fitur yang nyaman bagi pengguna akhir, sehingga proses meminta URL menjadi hal yang lumrah. Oleh karena itu, insiden _SSRF_ semakin meningkat. Selain itu, tingkat keparahan _SSRF_ semakin meningkat karena layanan-layanan _cloud_ dan tingkat komplexitas arsitektur _cloud_.

## Bagaimana Cara Mencegahnya


Pengembang dapat mencegah terjadinya _SSRF_ dengan mengimplementasikan beberapa atau semua tindakan kontrol pertahanan berikut:

### Dari Network Layer

- Segmentasi fitur/fungsi _remote resource access_ di jaringan yang berbeda untuk mengurangi dampak dari _SSRF_.
- Terapkan kebijakan firewall _deny by default_ atau aturan kontrol akses jaringan untuk memblokir semua lalu lintas eksternal kecuali lalu lintas intranet yang penting.  
  _Petunjuk:_  
  ~ Buat / Bangunlah siklus hidup dan hak kepemilikan untuk peraturan firewall berdasarkan aplikasinya.  
  ~ Catat semua akses jaringan yang melewati firewall baik akses jaringan yang diterima ataupun yang diblokir/tolak (lihat [A09:2021-Security Logging and Monitoring Failures](A09_2021-Security_Logging_and_Monitoring_Failures.id.md)).

### Dari Application Layer

- Bersihkan dan validasi semua data inputan yang dimasukkan oleh klien

- Terapkan skema URL, port, dan destinasi dengan daftar izin positif

- Jangan mengirim respon mentah ke klien

- Nonaktifkan pengalihan HTTP

- Perhatikan konsistensi URL untuk menghindari serangan _DNS rebinding_ dan serangan _(TOCTOU) time of check, time of use_

Jangan gunakan daftar penolakan atau ekspresi reguler untuk mitigasi _SSRF_. Penyerang mempunyai daftar muatan, alat, dan kemampuan untuk membobol/melewati daftar penolakan.

### Tindakan Lainnya Yang Dapat Dipertimbangkan

- Jangan _deploy_ layanan yang berhubungan dengan keamanan pada sistem yang berada di barisan depan, contohnya _OpenId_. Kontrol lalu lintas lokal pada sistem ini (Localhost).

- Khusus untuk _frontends_ dengan pengguna/grup pengguna yang loyal atau berdedikasi serta dapat dikelola gunakanlah enkripsi jaringan (VPN) pada sistem independen mengingat adanya kebutuhan proteksi yang sangat tinggi.

## Contoh Skenario Penyerangan

Penyerang dapat menggunakan _SSRF_ untuk menyerang sitem yang telah dilindungi dibalik firewall aplikasi web, firewall,atau jaringan ACL dengan skenario-skenario penyerangan sebagai berikut:

**Skenario #1:** Memindai port server internal. Apabila arsitektur jaringan tidak tersegmentasi, penyerang dapat mendapatkan gambaran bagaimana jaringan internal terbentuk
dan dapat menentukan port-port mana yang terbuka atau tertutup pada server internal berdasarkan hasil koneksi, waktu yang dibutuhkan untuk melakukan koneksi atau waktu yang dibutuhkan untuk menolak koneksi yang bermuatan _SSRF_.

**Skenario #2:** Kebocoran data sensitif. Penyerang dapat mengakses file lokal seperti `file:///etc/passwd</span>` dan `http://localhost:28017/`.

**Skenario #3:** Akses penyimpanan metadata dari layanan cloud - Mayoritas penyedia layanan cloud memiliki penyimpanan metadata seperti `http://169/254.169.254/`.
Seorang penyerang dapat membaca metada tersebut untuk mendapatkan informasi sensitif.

**Skenario #4:** Penyusupan layanan internal - Penyerang dapat menyalahgunakan layanan internal untuk melakukan serangan lebih lanjut seperti _Remote Code Execution (RCE)_ atau _Denial Of Service (DOS)_.

## Referensi

-   [OWASP - Server-Side Request Forgery Prevention Cheat
    Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

-   [PortSwigger - Server-side request forgery
    (SSRF)](https://portswigger.net/web-security/ssrf)

-   [Acunetix - What is Server-Side Request Forgery
    (SSRF)?](https://www.acunetix.com/blog/articles/server-side-request-forgery-vulnerability/)

-   [SSRF
    bible](https://cheatsheetseries.owasp.org/assets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet_SSRF_Bible.pdf)

-   [A New Era of SSRF - Exploiting URL Parser in Trending Programming
    Languages!](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)

## Daftar Klasifikasi CWE

[CWE-918 Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
