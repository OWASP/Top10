# A2:2017 Kerusakan Autentikasi

| Agen ancaman / vektor serangan | Kelemahan Keamanan           | Dampak               |
| -- | -- | -- |
| Akses Lvl: Eksploitasi 3 | Prevalensi 2: Deteksi 2 | Teknis 3: Bisnis |
|Penyerang memiliki akses ke ratusan juta kombinasi nama pengguna dan sandi yang valid untuk isian kredensial, daftar akun administratif default, brute force otomatis, dan alat dictionary attack. Serangan manajemen sesi dipahami dengan baik, terutama terkait dengan sesi token yang belum habis.| Prevalensi otentikasi yang terputus tersebar luas karena desain dan implementasi sebagian besar identitas dan kontrol akses. Manajemen sesi adalah fondasi otentikasi dan kontrol akses, dan hadir dalam semua aplikasi berstatus. Penyerang dapat mendeteksi autentikasi yang rusak menggunakan cara manual dan memanfaatkannya menggunakan alat otomatis dengan daftar kata sandi dan dictionary attack.|Penyerang harus mendapatkan akses pada beberapa akun, atau hanya satu akun admin untuk membahayakan sistem. Bergantung pada domain aplikasi, ini mungkin mengizinkan pencucian uang, penipuan keamanan sosial, dan pencurian identitas, atau mengungkapkan informasi sensitif yang dilindungi secara hukum.|

## Apakah Aplikasi itu Rentan?

Konfirmasi identitas pengguna, otentikasi, dan manajemen sesi sangat penting untuk melindungi terhadap serangan terkait otentifikasi.

Mungkin ada kelemahan otentikasi jika aplikasi:

* Izin serangan otomatis seperti [mengisi kredensial](https://owasp.org/www-community/attacks/Credential_stuffing), dimana penyerang memiliki daftar username dan password yang valid.
* Memungkinkan brute force atau serangan otomatis lainnya.
* Memungkinkan password default, lemah, atau terkenal, seperti "Password1" atau "admin / admin".
* Menggunakan proses pemulihan kredensial yang lemah atau tidak efektif dan proses lupa kata sandi, seperti "jawaban berbasis pengetahuan", yang tidak dapat dilakukan dengan aman.
* Menggunakan kata kunci plain text, encrypted, atau dengan hash yang lemah (lihat **A3: 2017-Sensitive Data Exposure**).
* Memiliki otentikasi multi faktor yang hilang atau tidak efektif.
* Memaparkan ID Sesi di URL (mis., Penulisan ulang URL).
* Tidak memutar Sesi ID setelah berhasil masuk.
* Membatalkan ID Sesi secara tidak benar. Sesi pengguna atau token otentikasi (terutama token single sign-on (SSO)) tidak benar-benar dianggap tidak berlaku saat logout atau periode tidak aktif.

## Bagaimana Cara Mencegahnya

* Bila memungkinkan, terapkan autentikasi multi-faktor untuk mencegah pengisian otomatis, credential stuffing, brute force, dan penggunaan kembali kredensial bekas pakai yang dicuri.
* Jangan mengirim atau menyebarkan dengan kredensial default, terutama untuk pengguna admin.
* Lakukan pengecekan password lemah, seperti menguji password baru atau yang telah diubah terhadap daftar [10000 password terburuk teratas](https://github.com/danielmiessler/SecLists/tree/master/Passwords).
* Sejajarkan panjang kata sandi, kompleksitas dan kebijakan rotasi dengan [NIST 800-63 B panduan di bagian 5.1.1 untuk Rahasia Memoris](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret) atau kebijakan sandi berbasis kebijakan yang modern lainnya.
* Pastikan pendaftaran, pemulihan kredensial, dan jalur API disulitkan melawan serangan akun satu per satu dengan menggunakan pesan yang sama untuk semua hasil.
* Batasi atau tingkatkan penundaan upaya login yang gagal. Log semua kegagalan dan peringatan administrator saat credential stuffing, brute force, atau serangan lain yang terdeteksi.
* Gunakan manajer sesi server-side, secure, built-in yang menghasilkan ID sesi acak baru dengan keunikan tinggi setelah login. Sesi ID tidak boleh berada di URL, disimpan dengan aman dan tidak valid setelah logout, idle, dan timeout absolut.

## Contoh Skenario Serangan

**Skenario  #1**: [Credential stuffing](https://owasp.org/www-community/attacks/Credential_stuffing), penggunaan [daftar kata sandi yang dikenal](https://github.com/danielmiessler/SecLists), adalah serangan yang umum. Jika sebuah aplikasi tidak menerapkan ancaman Credential stuffing atau ancaman otomatis, aplikasi tersebut dapat digunakan sebagai kata sandi untuk menentukan apakah kredensial tersebut valid.

**Skenario #2**: Sebagian besar serangan otentikasi terjadi karena terus menggunakan kata kunci sebagai satu-satunya faktor. Setelah dianggap sebagai praktik terbaik, persyaratan perumusan kata sandi dan kompleksitas dipandang mendorong pengguna untuk menggunakan, dan menggunakan kembali, kata kunci yang lemah. Organisasi merekomendasikan untuk menghentikan praktik ini per NIST 800-63 dan menggunakan autentikasi multi faktor.

**Skenario #3**: Batas waktu sesi aplikasi tidak diatur dengan benar. Pengguna menggunakan komputer umum untuk mengakses aplikasi. Alih-alih memilih "logout" pengguna cukup menutup tab browser dan berjalan pergi. Penyerang menggunakan browser yang sama satu jam kemudian, dan pengguna masih diotentifikasi.

## Referensi

### OWASP

* [OWASP Proactive Controls: Implement Identity and Authentication Controls](https://owasp.org/www-project-proactive-controls/v3/en/c6-digital-identity)
* [OWASP Application Security Verification Standard: V2 Authentication](https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x11-V2-Authentication.md)
* [OWASP Application Security Verification Standard: V3 Session Management](https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x12-V3-Session-management.md)
* [OWASP Testing Guide: Identity](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/README)
 and [Authentication](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/README)
* [OWASP Cheat Sheet: Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Credential Stuffing](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Forgot Password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
* [OWASP Automated Threats Handbook](https://owasp.org/www-project-automated-threats-to-web-applications/)

### External

* [NIST 800-63b: 5.1.1 Memorized Secrets](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret) - for thorough, modern, evidence-based advice on authentication. 
* [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
* [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
