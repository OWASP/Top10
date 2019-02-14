# A5:2017 Kontrol Akses Yang Buruk

| Agen ancaman / vektor serangan | Kelemahan Keamanan  | Dampak |
| -- | -- | -- |
| Akses Lvl : Exploitasi 2 | Prevalensi 2 : Deteksi 2 | Teknik 3 : Bisnis |
| Eksploitasi kontrol akses adalah keahlian inti pada penyerang [SAST](https://www.owasp.org/index.php/Source_Code_Analysis_Tools) dan [DAST](https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools) Tool ini dapat mendeteksi tidak adanya kontrol akses tetapi tidak dapat memverifikasi apakah itu berfungsi ketika serangan itu muncul. Kontrol akses dapat dideteksi menggunakan cara manual, atau mungkin melalui otomatisasi karena tidak adanya kontrol akses dalam framework tertentu| Kelemahan kontrol akses adalah umum karena kurangnya security assessment/deteksi awal, dan kurangnya pengujian fungsional yang efektif oleh pengembang aplikasi. Deteksi kontrol akses biasanya tidak menerima pengujian statis atau dinamis otomatis. Pengujian manual adalah cara terbaik untuk mendeteksi kontrol akses yang hilang atau tidak efektif, termasuk metode HTTP (GET vs PUT, dll), Kontrol, referensi objek langsung, dll.| Dampak teknisnya adalah penyerang bertindak sebagai pengguna atau administrator, atau pengguna yang menggunakan hak akses istimewa, atau membuat, mengakses, memperbarui, atau menghapus setiap catatan. Dampak bisnis tergantung pada kebutuhan perlindungan aplikasi dan data |

## Apakah Aplikasi itu Rentan?

Kontrol akses memberlakukan kebijakan sedemikian rupa sehingga pengguna tidak dapat bertindak di luar izin yang dimaksudkan. Kegagalan biasanya mengarah pada pengungkapan informasi yang tidak sah, modifikasi atau penghancuran semua data, atau melakukan fungsi bisnis di luar batas pengguna. Kerentanan kontrol akses yang umum termasuk:

* Memintas pemeriksaan kontrol akses dengan memodifikasi URL, status aplikasi internal, atau halaman HTML, atau hanya menggunakan alat serangan API khusus.
* Mengizinkan kunci utama untuk diubah ke catatan pengguna orang lain, memungkinkan melihat atau mengedit akun orang lain.
* Ketinggian hak istimewa. Bertindak sebagai pengguna tanpa login, atau bertindak sebagai admin saat login sebagai pengguna.
* Manipulasi metadata, seperti memutar ulang atau merusak token kontrol akses JSON Web Token (JWT) atau cookie atau bidang tersembunyi yang dimanipulasi untuk meningkatkan hak istimewa, atau menyalahgunakan pembatalan JWT
* Kesalahan konfigurasi CORS memungkinkan akses API yang tidak sah.
* Paksa penelusuran ke halaman yang diautentikasi sebagai pengguna yang tidak diauthentikasi atau ke halaman yang diistimewakan sebagai pengguna standar. Mengakses API dengan kontrol akses yang hilang untuk POST, PUT dan DELETE.

## Cara Pencegahan

Kontrol akses hanya efektif jika ditegakkan dalam kode sisi server tepercaya atau server-less API, di mana penyerang tidak dapat mengubah pemeriksaan kontrol akses atau metadata.

* Dengan pengecualian sumber daya publik, tolak secara default.
* Terapkan mekanisme kontrol akses satu kali dan gunakan kembali di seluruh aplikasi, termasuk meminimalkan penggunaan CORS.
* Kontrol akses model harus menegakkan kepemilikan catatan, daripada menerima bahwa pengguna dapat membuat, membaca, memperbarui, atau menghapus catatan apa pun.
* Persyaratan batas bisnis aplikasi unik harus diberlakukan oleh model domain.
* Nonaktifkan daftar direktori server web dan pastikan metadata file (mis. Git) dan file cadangan tidak ada dalam root web.
* Log kegagalan kontrol akses, admin waspada bila perlu (mis. Kegagalan berulang).
* API batas nilai dan akses pengontrol untuk meminimalkan bahaya dari perkakas serangan otomatis.
* Token JWT harus tidak valid di server setelah logout.
* Pengembang dan staf QA harus mencakup unit kontrol akses fungsional dan tes integrasi.

## Contoh Skenario Serangan

**Skenario #1**: Aplikasi menggunakan data yang tidak diverifikasi dalam panggilan SQL yang mengakses informasi akun:

```
  pstmt.setString(1, request.getParameter("acct"));
  ResultSet results = pstmt.executeQuery();
```

Seorang penyerang hanya memodifikasi parameter 'acct' di browser untuk mengirim nomor akun apa pun yang mereka inginkan. Jika tidak diverifikasi dengan benar, penyerang dapat mengakses akun pengguna mana pun.

`http://example.com/app/accountInfo?acct=notmyacct`

**Scenario #2**: Seorang penyerang cukup memaksa browser untuk menargetkan URL. Hak admin diperlukan untuk akses ke halaman admin.

```
  http://example.com/app/getappInfo
  http://example.com/app/admin_getappInfo
```

Jika pengguna yang tidak diautentikasi dapat mengakses halaman mana pun, itu adalah kontrol akses yang buruk. Jika non-admin dapat mengakses halaman admin, ini adalah otentifikasi yang buruk.

## Referensi

### OWASP

* [OWASP Proactive Controls: Access Controls](https://www.owasp.org/index.php/OWASP_Proactive_Controls#6:_Implement_Access_Controls)
* [OWASP Application Security Verification Standard: V4 Access Control](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide: Authorization Testing](https://www.owasp.org/index.php/Testing_for_Authorization)
* [OWASP Cheat Sheet: Access Control](https://www.owasp.org/index.php/Access_Control_Cheat_Sheet)

### Eksternal

* [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
* [CWE-284: Improper Access Control (Authorization)](https://cwe.mitre.org/data/definitions/284.html)
* [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
* [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
* [PortSwigger: Exploiting CORS misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
