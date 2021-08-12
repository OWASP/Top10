# A5:2017 Kontrol Akses Yang Buruk

| Agen ancaman / vektor serangan | Kelemahan Keamanan          | Dampak            |
| -- | -- | -- |
| Access Lvl : Eksploitasi 2 | Prevalensi 3: Deteksi 2 | Teknis 3: Bisnis |
| Eksploitasi kontrol akses adalah keahlian inti pada penyerang. [SAST](https://owasp.org/www-community/Source_Code_Analysis_Tools) dan [DAST](https://owasp.org/www-community/Vulnerability_Scanning_Tools) Tool ini dapat mendeteksi tidak adanya kontrol akses tetapi tidak dapat memverifikasi apakah itu berfungsi ketika serangan itu muncul. Kontrol akses dapat dideteksi menggunakan cara manual, atau mungkin melalui otomatisasi karena tidak adanya kontrol akses dalam framework tertentu | Kelemahan kontrol akses adalah umum karena kurangnya security assessment/deteksi awal, dan kurangnya pengujian fungsional yang efektif oleh pengembang aplikasi. Deteksi kontrol akses biasanya tidak menerima pengujian statis atau dinamis otomatis. Pengujian manual adalah cara terbaik untuk mendeteksi kontrol akses yang hilang atau tidak efektif, termasuk metode HTTP (GET vs PUT, dll), Kontrol, referensi objek langsung, dll. | Dampak teknisnya adalah penyerang bertindak sebagai pengguna atau administrator, atau pengguna yang menggunakan hak akses istimewa, atau membuat, mengakses, memperbarui, atau menghapus setiap catatan. Dampak bisnis tergantung pada kebutuhan perlindungan aplikasi dan data |

## Apakah Aplikasi itu Rentan?

Kontrol akses memberlakukan kebijakan sedemikian rupa sehingga pengguna tidak dapat bertindak di luar izin yang dimaksudkan. Kegagalan dalam mengimplementasikan kontrol akses akan mendampakkan pengeluaran sebuah informasi tanpa izin, modifikasi atau kerusakan semua data, atau melakukan sebuah fungsi bisnis diluar batasan yang telah diberikan kepada sebuah user / pengguna. Kerentanan kontrol akses yang umum termasuk:

- Melewati pemeriksaan kontrol akses dengan memodifikasi URL, status aplikasi internal, atau halaman HTML, atau hanya menggunakan sebuah alat khusus untuk menyerang API.
- Mengizinkan kunci utama atau primary key untuk diubah ke catatan pengguna orang lain, sehingga menyebabkan orang lain dapat melihat atau mengedit akun orang lain.
- Ketinggian hak istimewa. Bertindak sebagai pengguna tanpa login, atau bertindak sebagai admin saat login sebagai pengguna.
- Manipulasi metadata, seperti memutar ulang atau merusak token kontrol akses JSON Web Token (JWT) atau cookie atau bidang tersembunyi yang dimanipulasi untuk meningkatkan hak istimewa, atau menyalahgunakan pembatalan JWT
- Kesalahan konfigurasi CORS memungkinkan akses API yang tidak diizinkan.
- Paksa penelusuran ke halaman yang diautentikasi sebagai pengguna yang tidak diauthentikasi atau ke halaman yang diistimewakan sebagai pengguna standar. Mengakses API dengan kontrol akses yang hilang untuk POST, PUT dan DELETE.

## Cara Pencegahan

Kontrol akses hanya efektif jika ditegakkan dalam kode sisi server terpercaya atau server-less API, yang dimana penyerang tidak dapat mengubah pemeriksaan kontrol akses atau metadata.

- Dengan pengecualian sumber daya publik, tolak secara default.
- Terapkan mekanisme kontrol akses satu kali dan digunakan kembali di seluruh aplikasi, termasuk meminimalkan penggunaan CORS.
- Kontrol akses model harus menegakkan kepemilikan catatan, daripada membolehkan bahwa pengguna atau user dapat membuat, membaca, memperbarui, atau menghapus catatan apa pun.
- Persyaratan batas bisnis aplikasi unik harus diberlakukan oleh model domain.
- Nonaktifkan daftar direktori server web dan pastikan metadata file (mis. Git) dan file cadangan tidak ada dalam root web.
- Log kegagalan kontrol akses, admin waspada bila perlu (mis. Kegagalan berulang).
- Menentukan batas limit untuk akses API dan controller untuk meminimalkan bahaya dari perkakas serangan otomatis.
- Token JWT harus tidak valid di server setelah logout.
- Pengembang dan staf QA harus mencakup unit kontrol akses fungsional dan tes integrasi.

## Contoh Skenario Serangan

**Skenario #1**: Aplikasi menggunakan data yang tidak diverifikasi dalam panggilan SQL yang mengakses informasi akun:

```
  pstmt.setString(1, request.getParameter("acct"));
  ResultSet results = pstmt.executeQuery();
```

Seorang penyerang hanya memodifikasi parameter 'acct' di browser untuk mengirim nomor akun apa pun yang mereka inginkan. Jika tidak diverifikasi dengan benar, penyerang dapat mengakses akun pengguna mana pun.

`https://example.com/app/accountInfo?acct=notmyacct`

**Scenario #2**: Seorang penyerang cukup memaksa browser untuk menargetkan URL. Hak admin diperlukan untuk akses ke halaman admin.

```
  https://example.com/app/getappInfo
  https://example.com/app/admin_getappInfo
```

Jika pengguna yang tidak diautentikasi dapat mengakses halaman mana pun, itu adalah kontrol akses yang buruk. Jika non-admin dapat mengakses halaman admin, ini adalah otentifikasi yang buruk.

## Referensi

### OWASP

- [OWASP Proactive Controls: Access Controls](https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls)
- [OWASP Application Security Verification Standard: V4 Access Control](https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x12-V4-Access-Control.md)
- [OWASP Testing Guide: Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)
- [OWASP Cheat Sheet: Access Control](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)

### Eksternal

- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-284: Improper Access Control (Authorization)](https://cwe.mitre.org/data/definitions/284.html)
- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [PortSwigger: Exploiting CORS misconfiguration](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
