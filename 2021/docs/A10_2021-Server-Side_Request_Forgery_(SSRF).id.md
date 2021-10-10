# A10:2021 – Server-Side Request Forgery (SSRF) - Pemalsuan Permintaan di Sisi Server
<img src="https://raw.githubusercontent.com/OWASP/Top10/master/2021/docs/assets/TOP_10_Icons_Final_SSRF.png" alt="icon" height=80px width=80px align="center">

## Faktor

| CWEs Mapped | Max Incidence Rate | Avg Incidence Rate | Avg Weighted Exploit | Avg Weighted Impact | Max Coverage | Avg Coverage | Total Occurrences | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 1           | 2.72%              | 2.72%              | 8.28                 | 6.72                | 67.72%       | 67.72%       | 9,503             | 385        |


| Klasifikasi CWE | Tingkat Kejadian Maksimum | Rata - Rata Tingkat Kejadian  | Cakupan Maximum | Rata - Rata Cakupan | Rata - Rata Bobot Exploitasi | Rata - Rata Bobot Dampak | Total Kejadian | Total CVEs |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 1           | 2.72%              | 2.72%              | 67.72%       | 67.72%       | 8.28                 | 6.72                | 9,503             | 385        |

## Penjelasan Singkat
_This category is added from the Top 10 community survey (#1). The data shows a relatively low incidence rate with above average testing coverage and above-average Exploit and Impact potential ratings. As new entries are likely to be a single or small cluster of Common Weakness Enumerations (CWEs) for attention and awareness, the hope is that they are subject to focus and can be rolled into a larger category in a future edition._

Kategori ini ditambahkan dari survei 10 komunitas teratas (#1). Data ini menunjukan tingkat insiden yang relatif rendah dengan cakupan pengujian di atas rata-rata serta
nilai dampak dan potensial eksploitasi di atas rata-rata. Entri-entri baru kemungkinan besar menjadi cluster kecil atau tunggal dari CWE - CWE karena tingkat atensi dan tingkat kesadarannya, harapannnya entri-entri baru ini dapat menjadi fokusan riset keamanan dan dapat digolongkan/dimasukkan kedalam kategori/cluster yang lebih besar di edisi mendatang.

## Deskripsi
_SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall, VPN, or another type of network access control list (ACL)._

Kecacatan _SSRF_ muncul saat sebuah aplikasi web meminta _remote resource_ tanpa melakukan validasi URL yang di berikan oleh pengguna. Ini memperbolehkan penyerang untuk memaksa aplikasi untuk mengirim _crafted request_ ke destinasi yang tidak diharapkan, meskipun sudah dilindungi oleh _firewall_, VPN, atau tipe lain dari daftar aturan akses jaringan - _Access Control List_ (ACL).

_As modern web applications provide end-users with convenient features, fetching a URL becomes a common scenario. As a result, the incidence of SSRF is increasing. Also, the severity of SSRF is becoming higher due to cloud services and the complexity of architectures._

Aplikasi web saat ini menyediakan fitur yang nyaman bagi pengguna akhir, sehingga proses meminta URL menjadi hal yang lumrah. Oleh karena itu, insiden _SSRF_ semakin meningkat. Selain itu, tingkat keparahan _SSRF_ semakin meningkat karena layanan-layanan _cloud_ dan tingkat komplexitas arsitektur _cloud_.

## Bagaimana Cara Mencegahnya

_Developers can prevent SSRF by implementing some or all the following defense in depth controls:_

Pengembang dapat mencegah terjadinya _SSRF_ dengan mengimplementasikan beberapa atau semua tindakan kontrol pertahanan berikut:

### Dari Network Layer

- _Segment remote resource access functionality in separate networks to reduce the impact of SSRF_
- Segmentasi fitur/fungsi _remote resource access_ di jaringan yang berbeda untuk mengurangi dampak dari _SSRF_.

- _Enforce “deny by default” firewall policies or network access control rules to block all but essential intranet traffic_  
  _Hints:_  
  ~ Establish an ownership and a life cycle for firewall rules based on applications.  
  ~ Log all accepted and blocked network flows on firewalls (see [A09:2021-Security Logging and Monitoring Failures](A09_2021-Security_Logging_and_Monitoring_Failures.md)).  
- Terapkan kebijakan firewall _deny by default_ atau aturan kontrol akses jaringan untuk memblokir semua lalu lintas eksternal kecuali lalu lintas intranet yang penting.  
  _Petunjuk:_  
  ~ Buat / Bangunlah siklus hidup dan hak kepemilikan untuk peraturan firewall berdasarkan aplikasinya.  
  ~ Catat semua akses jaringan yang melewati firewall baik akses jaringan yang diterima ataupun yang diblokir/tolak (lihat [A09:2021-Security Logging and Monitoring Failures](A09_2021-Security_Logging_and_Monitoring_Failures.md)).  

### Dari Application Layer

- _Sanitize and validate all client-supplied input data_
- Bersihkan dan validasi semua data inputan yang dimasukkan oleh klien

- _Enforce the URL schema, port, and destination with a positive allow list_
- Terapkan skema URL, port, dan destinasi dengan daftar izin positif

- _Do not send raw responses to clients_
- Jangan mengirim respon mentah ke klien

- _Disable HTTP redirections_
- Nonaktifkan pengalihan HTTP

- _Be aware of the URL consistency to avoid attacks such as DNS rebinding and “time of check, time of use” (TOCTOU) race conditions_
- Perhatikan konsistensi URL untuk menghindari serangan _DNS rebinding_ dan serangan _(TOCTOU) time of check, time of use_

_Do not mitigate SSRF via the use of a deny list or regular expression.  Attackers have payload lists, tools, and skills to bypass deny lists._
Jangan gunakan daftar penolakan atau ekspresi reguler untuk mitigasi _SSRF_. Penyerang mempunyai daftar muatan, alat, dan kemampuan untuk membobol/melewati daftar penolakan.

### Tindakan Lainnya Yang Dapat Dipertimbangkan
- _Don't deploy other security relevant services on front systems (e.g. OpenID). Control local traffic on these systems (e.g. localhost)_
- Jangan _deploy_ layanan yang berhubungan dengan keamanan pada sistem yang berada di barisan depan, contohnya _OpenId_. Kontrol lalu lintas lokal pada sistem ini (Localhost).

- _For frontends with dedicated and manageable user groups use network encryption (e.g. VPNs) on independent systems to consider very high protection needs_
- Khusus untuk _frontends_ dengan pengguna/grup pengguna yang loyal atau berdedikasi serta dapat dikelola gunakanlah enkripsi jaringan (VPN) pada sistem independen mengingat adanya kebutuhan proteksi yang sangat tinggi.

## Contoh Skenario Penyerangan

_Attackers can use SSRF to attack systems protected behind web
application firewalls, firewalls, or network ACLs, using scenarios such
as:_

Penyerang dapat menggunakan _SSRF_ untuk menyerang sitem yang telah dilindungi dibalik firewall aplikasi web, firewall,
atau jaringan ACL dengan skenario-skenario penyerangan sebagai berikut:

_**Scenario #1:** Port scan internal servers - If the network architecture is unsegmented, attackers can map out internal networks and determine if ports are open or closed on internal servers from connection results or elapsed time to connect or reject SSRF payload connections._

**Skenario #1:** Memindai port server internal. Apabila arsitektur jaringan tidak tersegmentasi, penyerang dapat mendapatkan gambaran bagaimana jaringan internal terbentuk
dan dapat menentukan port-port mana yang terbuka atau tertutup pada server internal berdasarkan hasil koneksi, waktu yang dibutuhkan untuk melakukan koneksi atau waktu yang dibutuhkan untuk menolak koneksi yang bermuatan _SSRF_.

_**Scenario #2:** Sensitive data exposure – Attackers can access local
files such as or internal services to gain sensitive information such
as `file:///etc/passwd</span>` and `http://localhost:28017/`._

**Skenario #2:** Kebocoran data sensitif. Penyerang dapat mengakses file lokal seperti `file:///etc/passwd</span>` dan `http://localhost:28017/`.

_**Scenario #3:** Access metadata storage of cloud services – Most cloud
providers have metadata storage such as `http://169.254.169.254/`. An
attacker can read the metadata to gain sensitive information._

**Skenario #3:** Akses penyimpanan metadata dari layanan cloud - Mayoritas penyedia layanan cloud memiliki penyimpanan metadata seperti `http://169/254.169.254/`.
Seorang penyerang dapat membaca metada tersebut untuk mendapatkan informasi sensitif.

_**Scenario #4:** Compromise internal services – The attacker can abuse
internal services to conduct further attacks such as Remote Code
Execution (RCE) or Denial of Service (DoS)._

**Skenario #4:** Penyusupan layanan internal - Penyerang dapat menyalahgunakan layanan internal untuk melakukan serangan lebih lanjut
seperti _Remote Code Execution (RCE)_ atau _Denial Of Service (DOS)_.

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
