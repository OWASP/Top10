# A07:2021 – Kegagalan Identifikasi dan Otentikasi

## Faktor

| Klasifikasi CWE | Tingkat Kejadian Maksimum | Rata - Rata Tingkat kejadian | Cakupan Maksimum | Rata - Rata Cakupan | Rata-rata Bobot Eksploitasi | Rata - Rata Bobot Dampak | Total Kejadian | Total CVE |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 22          | 14.84%             | 2.55%              | 79.51%       | 45.72%       | 7.40                 | 6.50                | 132,195           | 3,897      |

## Ikhtisar

Sebelumnya dikenal sebagai *Broken Authentication*, kategori ini turun
dari posisi kedua dan sekarang mencakup CWE yang terkait dengan kegagalan identifikasi. CWE terkenal yang disertakan adalah *CWE-297: Improper Validation of
Certificate with Host Mismatch*, *CWE-287: Improper Authentication*, dan
*CWE-384: Session Fixation*.

## Deskripsi 

Konfirmasi identitas pengguna, otentikasi, dan sesi manajemen sangat penting untuk melindungi dari serangan terkait otentikasi. 
Mungkin ada kelemahan otentikasi jika aplikasi:

-   Mengizinkan serangan otomatis seperti isian kredensial, di mana
    penyerang memiliki daftar nama pengguna dan kata sandi yang valid.

-   Mengizinkan brute force atau serangan otomatis lainnya.

-   Mengizinkan kata sandi bawaan, lemah, atau kata sandi yang terkenal, seperti "Password1" atau "admin/admin."

-   Menggunakan pemulihan kredensial yang lemah atau tidak efektif dan proses lupa kata sandi, seperti "jawaban berbasis pengetahuan", yang tidak dapat dibuat
    aman.

-   Menggunakan kata sandi teks biasa, terenkripsi, atau dengan hash yang lemah (lihat
    A3:2017-Sensitive Data Exposure).

-   Memiliki otentikasi multi-faktor yang hilang atau tidak efektif.

-   Mengekspos ID Sesi di URL (misalnya, penulisan ulang URL).

-   Jangan memutar ID Sesi setelah login berhasil.

-   Tidak membatalkan ID Sesi dengan benar. Sesi pengguna atau
    token autentikasi (terutama token single sign-on (SSO)) tidak
    divalidasi dengan benar selama logout atau periode tidak aktif.

## Cara Mencegah

-   Jika memungkinkan, terapkan otentikasi multi-faktor untuk mencegah
    pengisian kredensial otomatis, brute force, dan dan serangan penggunaan kembali kredensial yang dicuri.

-   Jangan mengirim atau menyebarkan dengan kredensial bawaan apa pun, terutama untuk
    pengguna admin.

-   Menerapkan pemeriksaan kata sandi yang lemah, seperti menguji kata sandi baru atau yang diubah terhadap 10.000 daftar kata sandi terburuk

-   Sejajarkan panjang sandi, kompleksitas, dan kebijakan rotasi dengan pedoman NIST
    800-63b di bagian 5.1.1 untuk Rahasia yang Dihafal atau kebijakan kata sandi modern berbasis bukti lainnya.

-   Pastikan pendaftaran, pemulihan kredensial, dan jalur API
    diperkuat terhadap serangan enumerasi akun dengan menggunakan pesan yang sama
    untuk semua hasil.

-   Batasi atau semakin tunda upaya login yang gagal. Catat semua kegagalan
    dan peringatkan administrator ketika pengisian kredensial, brute force, atau
    serangan lainnya terdeteksi.

-   Gunakan pengelola sesi built-in sisi server, aman, yang menghasilkan
    ID sesi acak baru dengan entropi tinggi setelah login. ID sesi
    tidak boleh ada di URL, disimpan dengan aman, dan tidak valid setelah
    keluar, idle, dan waktu tunggu absolut.

## Contoh Skenario Serangan

**Skenario #1:** Pengisian Kredensial, penggunaan daftar kata sandi yang diketahui
adalah serangan yang umum. Misalkan aplikasi tidak menerapkan
perlindungan terhadap ancaman atau pengisian kredensial otomatis. Dalam hal ini,
aplikasi dapat digunakan sebagai kata sandi oracle untuk menentukan apakah
kredensial itu valid.

**Skenario #2:** Sebagian besar serangan autentikasi terjadi karena terus
menggunakan sandi sebagai satu-satunya faktor. Setelah dipertimbangkan, praktik terbaik, rotasi kata sandi, dan persyaratan kompleksitas mendorong pengguna untuk menggunakan kembali kata sandi yang lemah. Organisasi disarankan untuk menghentikan praktik ini per NIST 800-63 dan menggunakan otentikasi multi-faktor.

**Skenario #3:** Waktu tunggu sesi aplikasi tidak disetel dengan benar. Seorang
pengguna menggunakan komputer publik untuk mengakses aplikasi. Alih-alih
memilih "logout", pengguna cukup menutup tab browser dan pergi. Penyerang menggunakan browser yang sama satu jam kemudian, dan pengguna masih diautentikasi.

## Referensi

-   [OWASP Proactive Controls: Implement Digital
    Identity](https://owasp.org/www-project-proactive-controls/v3/en/c6-digital-identity)

-   [OWASP Application Security Verification Standard: V2
    authentication](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Application Security Verification Standard: V3 Session
    Management](https://owasp.org/www-project-application-security-verification-standard)

-   OWASP Testing Guide: Identity, Authentication

-   [OWASP Cheat Sheet:
    Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

-   OWASP Cheat Sheet: Credential Stuffing

-   [OWASP Cheat Sheet: Forgot
    Password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)

-   OWASP Cheat Sheet: Session Management

-   [OWASP Automated Threats
    Handbook](https://owasp.org/www-project-automated-threats-to-web-applications/)

-   NIST 800-63b: 5.1.1 Memorized Secrets

## Daftar Klasifikasi CWE

CWE-255 Credentials Management Errors

CWE-259 Use of Hard-coded Password

CWE-287 Improper Authentication

CWE-288 Authentication Bypass Using an Alternate Path or Channel

CWE-290 Authentication Bypass by Spoofing

CWE-294 Authentication Bypass by Capture-replay

CWE-295 Improper Certificate Validation

CWE-297 Improper Validation of Certificate with Host Mismatch

CWE-300 Channel Accessible by Non-Endpoint

CWE-302 Authentication Bypass by Assumed-Immutable Data

CWE-304 Missing Critical Step in Authentication

CWE-306 Missing Authentication for Critical Function

CWE-307 Improper Restriction of Excessive Authentication Attempts

CWE-346 Origin Validation Error

CWE-384 Session Fixation

CWE-521 Weak Password Requirements

CWE-613 Insufficient Session Expiration

CWE-620 Unverified Password Change

CWE-640 Weak Password Recovery Mechanism for Forgotten Password

CWE-798 Use of Hard-coded Credentials

CWE-940 Improper Verification of Source of a Communication Channel

CWE-1216 Lockout Mechanism Errors
