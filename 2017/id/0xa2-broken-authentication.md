# A2:2017 Otentikasi yang rusak

| Agen ancaman / vektor serangan | Kelemahan Keamanan           | Dampak               |
| -- | -- | -- |
| Akses Lvl: Eksploitasi 3 | Prevalensi 2: Deteksi 2 | Teknis 3: Bisnis |
|Penyerang memiliki akses ke ratusan juta kombinasi nama pengguna dan sandi yang valid untuk isian kredensial, daftar akun administratif default, alat kekerasan otomatis, dan alat serangan kamus. Serangan manajemen sesi dipahami dengan baik, terutama terkait dengan token sesi yang belum habis.| Prevalensi otentikasi yang terputus tersebar luas karena desain dan implementasi sebagian besar identitas dan kontrol akses. Manajemen sesi adalah fondasi otentikasi dan kontrol akses, dan hadir dalam semua aplikasi stateful. Penyerang dapat mendeteksi autentikasi yang rusak menggunakan cara manual dan memanfaatkannya menggunakan alat otomatis dengan daftar kata sandi dan serangan kamus. Prevalensi otentikasi yang terputus tersebar luas karena desain dan implementasi sebagian besar identitas dan kontrol akses. Manajemen sesi adalah fondasi otentikasi dan kontrol akses, dan hadir dalam semua aplikasi stateful. Penyerang dapat mendeteksi autentikasi yang rusak menggunakan cara manual dan memanfaatkannya menggunakan alat otomatis dengan daftar kata sandi dan serangan kamus.|Penyerang harus mendapatkan akses hanya pada beberapa akun, atau hanya satu akun admin untuk kompromi sistem. Bergantung pada domain aplikasi, ini mungkin mengizinkan pencucian uang, penipuan keamanan sosial, dan pencurian identitas, atau mengungkapkan informasi sensitif yang dilindungi secara hukum.|

## Apakah Aplikasi itu Rentan?

Konfirmasi identitas pengguna, otentikasi, dan manajemen sesi sangat penting untuk melindungi terhadap serangan terkait otentifikasi.

Mungkin ada kelemahan otentikasi jika aplikasi:

* Izin serangan otomatis seperti [mengisi kredensial](https://www.owasp.org/index.php/Credential_stuffing), dimana penyerang memiliki daftar username dan password yang valid.
* Memungkinkan kekerasan atau serangan otomatis lainnya.
* Memungkinkan password default, lemah, atau terkenal, seperti "Password1" atau "admin / admin".
* Menggunakan proses pemulihan kredensial yang lemah atau tidak efektif dan lupa-proses kata sandi, seperti "jawaban berbasis pengetahuan", yang tidak dapat dilakukan dengan aman.
* Menggunakan kata kunci plain text, encrypted, atau weakhedhed (lihat ** A3: 2017-Sensitive Data Exposure **).
* Hsebagai otentikasi multi faktor yang hilang atau tidak efektif.
* Paparkan ID Sesi di URL (mis., Penulisan ulang URL).
* Tidak memutar Sesi ID setelah berhasil masuk.
* Tidak benar membatalkan ID Sesi. Sesi pengguna atau token otentikasi (terutama single sign on on (SSO) token) tidak dianggap salah saat logout atau periode tidak aktif.
adalah serangan yang umum. Jika sebuah aplikasi tidak menerapkan ancaman pengamanan ancaman atau ancaman otomatis, aplikasi tersebut dapat digunakan sebagai kata sandi untuk menentukan apakah kredensial tersebut valid.## Cara Mencegah

* Bila memungkinkan, terapkan autentikasi multi-faktor untuk mencegah pengisian otomatis, pengisian kata kunci, kekerasan, dan penggunaan kembali kredensial bekas pakai yang dicuri.
* Jangan mengirim atau menyebarkan dengan kredensial default, terutama untuk pengguna admin.
* Terapkan cek password lemah, seperti menguji password baru atau yang telah diubah terhadap daftar[10000 password terburuk teratas](https://github.com/danielmiessler/SecLists/tree/master/Passwords).
* Sejajarkan panjang kata sandi, kompleksitas dan kebijakan rotasi dengan [NIST 800-63 B panduan di bagian 5.1.1 untuk Rahasia Memoris](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret) atau kebijakan sandi berbasis bukti yang modern lainnya.
* Pastikan pendaftaran, pemulihan kredensial, dan jalur API dikeraskan melawan serangan pencacahan akun dengan menggunakan pesan yang sama untuk semua hasil.
* Batasi atau kian menunda upaya login gagal. Log semua kegagalan dan administrator peringatan saat pengisian barang, kekerasan, atau serangan lain terdeteksi.
* Gunakan manajer sesi server-side, secure, built-in yang menghasilkan ID sesi acak baru dengan entropi tinggi setelah login. Sesi ID tidak boleh berada di URL, disimpan dengan aman dan tidak valid setelah logout, idle, dan timeout absolut.

## Contoh Skenario Serangan

**Skenario  #1**: [mengisi kredensial](https://www.owasp.org/index.php/Credential_stuffing), penggunaan [daftar kata sandi yang dikenal](https://github.com/danielmiessler/SecLists), adalah serangan yang umum. Jika sebuah aplikasi tidak menerapkan ancaman pengamanan ancaman atau ancaman otomatis, aplikasi tersebut dapat digunakan sebagai kata sandi untuk menentukan apakah kredensial tersebut valid.

**Skenario #2**: ebagian besar serangan otentikasi terjadi karena terus menggunakan kata kunci sebagai satu-satunya faktor. Setelah dianggap sebagai praktik terbaik, persyaratan perumusan kata sandi dan kompleksitas dipandang mendorong pengguna untuk menggunakan, dan menggunakan kembali, kata kunci yang lemah. Organisasi direkomendasikan untuk menghentikan praktik ini per NIST 800-63 dan menggunakan autentikasi multi faktor.

**Skenario #3**: Batas waktu sesi aplikasi tidak diatur dengan benar. Pengguna menggunakan komputer umum untuk mengakses aplikasi. Alih-alih memilih "logout" pengguna cukup menutup tab browser dan berjalan pergi. Penyerang menggunakan peramban yang sama satu jam kemudian, dan pengguna masih diotentifikasi.

## Referensi

### OWASP

* [OWASP Proactive Controls: Implement Identity and Authentication Controls](https://www.owasp.org/index.php/OWASP_Proactive_Controls#5:_Implement_Identity_and_Authentication_Controls)
* [OWASP Application Security Verification Standard: V2 Authentication](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Application Security Verification Standard: V3 Session Management](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide: Identity](https://www.owasp.org/index.php/Testing_Identity_Management)
 and [Authentication](https://www.owasp.org/index.php/Testing_for_authentication)
* [OWASP Cheat Sheet: Authentication](https://www.owasp.org/index.php/Authentication_Cheat_Sheet)
* [OWASP Cheat Sheet: Credential Stuffing](https://www.owasp.org/index.php/Credential_Stuffing_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: Forgot Password](https://www.owasp.org/index.php/Forgot_Password_Cheat_Sheet)
* [OWASP Cheat Sheet: Session Management](https://www.owasp.org/index.php/Session_Management_Cheat_Sheet)
* [OWASP Automated Threats Handbook](https://www.owasp.org/index.php/OWASP_Automated_Threats_to_Web_Applications)

### External

* [NIST 800-63b: 5.1.1 Memorized Secrets](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret) - for thorough, modern, evidence-based advice on authentication. 
* [CWE-287: Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)
* [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
