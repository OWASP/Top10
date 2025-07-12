# A07:2021 – Kegagalan Identifikasi dan Otentikasi    ![icon](assets/TOP_10_Icons_Final_Identification_and_Authentication_Failures.png){: style="height:80px;width:80px" align="right"}

## Faktor

| CWE Dipetakan | Tingkat Kejadian Maksimum | Rata-rata Tingkat kejadian | Rata-rata Eksploitasi Terbobot | Rata-rata Dampak Terbobot | Cakupan Maksimum | Rata-rata Cakupan | Total Kejadian | Total CVE |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 22          | 14,84%             | 2,55%              | 7,40                 | 6,50                | 79,51%       | 45,72%       | 132.195           | 3.897      |
## Ikhtisar

Sebelumnya dikenal sebagai *Broken Authentication*, kategori ini turun
dari posisi kedua dan sekarang mencakup Common Weakness 
Enumerations (CWE) yang terkait dengan kegagalan identifikasi. CWE terkenal 
yang disertakan adalah *CWE-297: Improper Validation of
Certificate with Host Mismatch*, *CWE-287: Improper Authentication*, dan
*CWE-384: Session Fixation*.

## Deskripsi 

Konfirmasi identitas pengguna, otentikasi, dan sesi manajemen sangat penting 
untuk melindungi dari serangan terkait otentikasi. Mungkin ada kelemahan 
otentikasi jika aplikasi:

-   Mengizinkan serangan otomatis seperti credential stuffing, dimana
    penyerang memiliki daftar nama pengguna dan kata sandi yang valid.

-   Mengizinkan brute force atau serangan otomatis lainnya.

-   Mengizinkan kata sandi bawaan, lemah, atau kata sandi yang terkenal, 
    seperti "Password1" atau "admin/admin."

-   Menggunakan proses lupa kata sandi dan pemulihan kredensial yang lemah 
    atau tidak efektif, seperti "jawaban berbasis pengetahuan", yang tidak 
    dapat dibuat aman.

-   Menggunakan kata sandi teks polos, terenkripsi, atau dengan hash yang 
    lemah (lihat [A02:2021-Cryptographic 
    Failures](A02_2021-Cryptographic_Failures.id.md)).

-   Memiliki otentikasi multi-faktor tidak efektif, atau tidak memilikinya.

-   Mengekspos ID Sesi di URL.

-   Memakai kembali ID Sesi setelah login berhasil.

-   Tidak membatalkan ID Sesi dengan benar. Sesi pengguna atau
    token autentikasi (terutama token single sign-on (SSO)) tidak
    di-invalidasi dengan benar selama logout atau periode tidak aktif.

## Cara Mencegah

-   Jika memungkinkan, terapkan otentikasi multi-faktor untuk mencegah
    credential stuffing otomatis, brute force, dan dan serangan penggunaan 
    kembali kredensial curian.

-   Jangan mengirim atau menyebarkan dengan kredensial bawaan apa pun, 
    terutama untuk pengguna admin.

-   Menerapkan pemeriksaan kata sandi yang lemah, seperti menguji kata sandi 
    baru atau yang diubah terhadap 10.000 daftar kata sandi terburuk

-   Selaraskan kebijakan panjang kata sandi, kompleksitas, dan rotasi dengan 
    pedoman NIST 800-63b di bagian 5.1.1 untuk Rahasia yang Dihafal atau 
    kebijakan kata sandi modern berbasis bukti lainnya.

-   Pastikan pendaftaran, pemulihan kredensial, dan jalur API diperkuat 
    terhadap serangan enumerasi akun dengan menggunakan pesan yang sama
    untuk semua hasil.

-   Batasi atau semakin tunda upaya login yang gagal. Catat semua kegagalan
    dan peringatkan administrator ketika credential stuffing, brute force, 
    atau serangan lainnya terdeteksi.

-   Gunakan pengelola sesi built-in sisi server, aman, yang menghasilkan
    ID sesi acak baru dengan entropi tinggi setelah login. ID sesi
    tidak boleh ada di URL, disimpan dengan aman, dan tidak valid setelah
    keluar, idle, dan waktu tunggu absolut.

## Contoh Skenario Serangan

**Skenario #1:** Credential Stuffing, penggunaan daftar kata sandi yang 
diketahui adalah serangan yang umum. Misalkan aplikasi tidak menerapkan
perlindungan terhadap ancaman atau credential stuffing otomatis. Dalam hal 
ini, aplikasi dapat digunakan sebagai oracle kata sandi untuk menentukan 
apakah kredensial itu valid.

**Skenario #2:** Sebagian besar serangan autentikasi terjadi karena terus
menggunakan sandi sebagai satu-satunya faktor. Pernah dianggap sebagai, 
praktik terbaik, rotasi kata sandi, dan persyaratan kompleksitas mendorong 
pengguna untuk menggunakan kembali kata sandi yang lemah. Organisasi 
disarankan untuk menghentikan praktik ini per NIST 800-63 dan menggunakan 
otentikasi multi-faktor.

**Skenario #3:** Waktu tunggu sesi aplikasi tidak disetel dengan benar. Seorang
pengguna menggunakan komputer publik untuk mengakses aplikasi. Alih-alih
memilih "logout", pengguna cukup menutup tab browser dan pergi. Penyerang 
menggunakan browser yang sama satu jam kemudian, dan pengguna masih diautentikasi.

## Referensi

-   [OWASP Proactive Controls: Implement Digital
    Identity](https://owasp.org/www-project-proactive-controls/v3/en/c6-digital-identity)

-   [OWASP Application Security Verification Standard: V2
    authentication](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Application Security Verification Standard: V3 Session
    Management](https://owasp.org/www-project-application-security-verification-standard)

-   [OWASP Testing Guide: Identity](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/03-Identity_Management_Testing/README), [Authentication](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/README)

-   [OWASP Cheat Sheet:
    Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Credential Stuffing](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Forgot
    Password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

-   [OWASP Automated Threats
    Handbook](https://owasp.org/www-project-automated-threats-to-web-applications/)

-   NIST 800-63b: 5.1.1 Memorized Secrets

## Daftar CWE yang Dipetakan

[CWE-255 Credentials Management Errors](https://cwe.mitre.org/data/definitions/255.html)

[CWE-259 Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)

[CWE-287 Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

[CWE-288 Authentication Bypass Using an Alternate Path or Channel](https://cwe.mitre.org/data/definitions/288.html)

[CWE-290 Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)

[CWE-294 Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html)

[CWE-295 Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

[CWE-297 Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/297.html)

[CWE-300 Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html)

[CWE-302 Authentication Bypass by Assumed-Immutable Data](https://cwe.mitre.org/data/definitions/302.html)

[CWE-304 Missing Critical Step in Authentication](https://cwe.mitre.org/data/definitions/304.html)

[CWE-306 Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)

[CWE-307 Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)

[CWE-346 Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)

[CWE-384 Session Fixation](https://cwe.mitre.org/data/definitions/384.html)

[CWE-521 Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)

[CWE-613 Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html)

[CWE-620 Unverified Password Change](https://cwe.mitre.org/data/definitions/620.html)

[CWE-640 Weak Password Recovery Mechanism for Forgotten Password](https://cwe.mitre.org/data/definitions/640.html)

[CWE-798 Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

[CWE-940 Improper Verification of Source of a Communication Channel](https://cwe.mitre.org/data/definitions/940.html)

[CWE-1216 Lockout Mechanism Errors](https://cwe.mitre.org/data/definitions/1216.html)

