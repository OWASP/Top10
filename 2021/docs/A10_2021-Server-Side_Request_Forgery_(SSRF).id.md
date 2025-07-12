# A10:2021 – Server-Side Request Forgery (SSRF)    ![icon](assets/TOP_10_Icons_Final_SSRF.png){: style="height:80px;width:80px" align="right"}

## Faktor-Faktor

| CWE Dipetakan | Tingkat Kejadian Maksimum | Rata-rata Tingkat Kejadian | Rata-rata Exploitasi Terbobot | Rata-rata Dampak Terbobot | Cakupan Maximum | Rata-rata Cakupan | Total Kejadian | Total CVE |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 1           | 2,72%              | 2,72%              | 8,28                 | 6,72                | 67,72%       | 67,72%       | 9.503             | 385        |


## Ringkasan

Kategori ini ditambahkan dari survei komunitas Top 10 (#1). Data ini 
menunjukan tingkat insiden yang relatif rendah dengan cakupan pengujian 
di atas rata-rata serta nilai dampak dan potensial eksploitasi di atas 
rata-rata. Entri-entri baru kemungkinan besar menjadi cluster kecil atau 
tunggal dari Common Weakness Enumerations (CWE) karena tingkat atensi dan 
tingkat kesadarannya, harapannnya entri-entri baru ini dapat menjadi fokus 
dimasukkan ke dalam kategori yang lebih besar di edisi mendatang.

## Deskripsi

Cacat _SSRF_ muncul saat sebuah aplikasi web meminta _remote resource_ tanpa 
melakukan validasi URL yang diberikan oleh pengguna. Ini memperbolehkan 
penyerang untuk memaksa aplikasi untuk mengirim _crafted request_ ke destinasi
yang tidak diharapkan, meskipun sudah dilindungi oleh _firewall_, VPN, atau 
tipe lain dari _Access Control List_ (ACL) jaringan.

Karena aplikasi web saat ini menyediakan fitur yang nyaman bagi pengguna akhir, 
proses meminta URL menjadi hal yang lumrah. Oleh karena itu, insiden _SSRF_ 
semakin meningkat. Selain itu, tingkat keparahan _SSRF_ semakin meningkat 
karena layanan-layanan _cloud_ dan tingkat komplexitas arsitektur.

## Bagaimana Mencegah

Pengembang dapat mencegah terjadinya _SSRF_ dengan mengimplementasikan 
beberapa atau semua tindakan kontrol pertahanan berlapis berikut:

### **Dari Lapisan Jaringan**

- Segmentasikan fungsionalitas _remote resource access_ di jaringan yang 
  berbeda untuk mengurangi dampak dari _SSRF_.

- Terapkan kebijakan firewall _deny by default_ atau aturan kontrol akses 
  jaringan untuk memblokir semua lalu lintas eksternal kecuali lalu lintas
  intranet yang esensial.<br/>  
  *Petunjuk:*<br>  
  ~ Jalin kepemilikan dan siklus hidup untuk aturan firewall berdasarkan 
    aplikasinya.<br/>
  ~ Catat semua aliran jaringan pada firewall yang diterima *dan* yang diblokir
  (lihat [A09:2021-Security Logging and Monitoring 
  Failures](A09_2021-Security_Logging_and_Monitoring_Failures.id.md)).  

### **Dari Lapisan Aplikasi**

- Bersihkan dan validasi semua data masukan yang dimasukkan oleh klien

- Paksakan skema URL, port, dan destinasi dengan daftar izin positif

- Jangan mengirim respon mentah ke klien

- Nonaktifkan pengalihan HTTP

- Perhatikan konsistensi URL untuk menghindari serangan _DNS rebinding_ 
  dan serangan *race condition* _(TOCTOU) time of check, time of use_

Jangan gunakan daftar penolakan atau ekspresi reguler untuk mitigasi _SSRF_. 
Penyerang mempunyai daftar muatan, alat, dan kemampuan untuk melewati daftar 
penolakan.

### **Tindakan Lain yang dapat dipertimbangkan:**

- Jangan _deploy_ layanan yang berhubungan dengan keamanan pada sistem yang 
  berada di barisan depan (mis. _OpenId_). Kendalikan lalu lintas lokal pada 
  sistem ini (mis. localhost).

- Untuk _frontend_ dengan pengguna/grup pengguna berdedikasi serta dapat 
  dikelola gunakanlah enkripsi jaringan (mis. VPN) pada sistem independen 
  mengingat adanya kebutuhan proteksi yang sangat tinggi.

## Contoh Skenario Penyerangan

Penyerang dapat menggunakan _SSRF_ untuk menyerang sitem yang telah dilindungi 
di balik firewall aplikasi web, firewall, atau ACL jaringan dengan skenario 
sebagai berikut:

**Skenario #1:** Memindai port server internal – Apabila arsitektur jaringan 
tidak tersegmentasi, penyerang bisa memetakan jaringan internal dan dapat 
menentukan port-port mana yang terbuka atau tertutup pada server internal dari 
hasil koneksi atau waktu yang dibutuhkan untuk melakukan koneksi atau untuk 
menolak koneksi yang bermuatan _SSRF_.

**Skenario #2:** Pengungkapan data sensitif – Penyerang dapat mengakses file 
lokal atau layanan internal untuk memperoleh informasi sensitif seperti 
`file:///etc/passwd` dan `http://localhost:28017/`.

**Skenario #3:** Mengakses penyimpanan metadata dari layanan cloud – Mayoritas 
penyedia layanan cloud memiliki penyimpanan metadata seperti 
`http://169/254.169.254/`. Seorang penyerang dapat membaca metadata tersebut 
untuk mendapatkan informasi sensitif.

**Skenario #4:** Penyusupan layanan internal – Penyerang dapat menyalahgunakan 
layanan internal untuk melakukan serangan lebih lanjut seperti _Remote Code 
Execution (RCE)_ atau _Denial Of Service (DOS)_.

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
