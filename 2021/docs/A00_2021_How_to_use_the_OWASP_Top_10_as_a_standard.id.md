# Bagaimana cara menggunakan OWASP Top 10 sebagai sebuah standar

OWASP Top 10 terutama merupakan dokumen kesadaran. Bagaimanapun, hal ini
tidak menghentikan organisasi untuk menggunakannya sebagai sebuah standar de 
facto pada industri keamanan aplikasi sejak kelahirannya pada tahun 2003.
Apabila Anda ingin menggunakan OWASP Top 10 sebagai standar dalam coding 
atau pengujian, ketahuilah bahwa ini adalah minimal dan hanya sebuah
titik awal.

Salah satu kesulitan dalam menggunakan OWASP Top 10 sebagai sebuah standar
adalah kita mendokumentasikan resiko keamanan aplikasi, dan belum tentu
sebuah masalah yang mudah diuji. Sebagai contoh, A04:2021-Insecure Design
berada di luar cakupan dari sebagian besar bentuk pengujian.
Contoh lain adalah pengujian di tempat, digunakan, serta pencatatan log dan
pemantauan yang efektif hanya dapat dilakukan dengan wawancara dan meminta
sebuah sampel dari respon tanggap insiden yang efektif. Sebuah alat analisa
kode statis dapat mencari ketidakhadiran pencatatan log, namun hal
ini mungkin mustahil untuk ditentukan apakah logika bisnis atau kontrol
akses mencatat pelanggaran keamanan yang kritis. Penguji penetrasi hanya dapat
menentukan bahwa mereka telah memanggil respons insiden di lingkungan pengujian, 
yang jarang dipantau dengan cara yang sama seperti pada produksi.

Berikut adalah rekomendasi kami mengenai kapan waktu yang tepat untuk
menggunakan OWASP Top 10:

| Use Case                | OWASP Top 10 2021 | OWASP Application Security Verification Standard |
|-------------------------|:-------------------:|:--------------------------------------------------:|
| Awareness               | Ya                |                                                  |
| Training                | Entry level       | Komprehensif                                     |
| Design and architecture | Kadang-kadang     | Ya                                               |
| Coding standard         | Minimal           | Ya                                               |
| Secure Code review      | Minimal           | Ya                                               |
| Peer review checklist   | Minimal           | Ya                                               |
| Unit testing            | Kadang-kadang     | Ya                                               |
| Integration testing     | Kadang-kadang     | Ya                                               |
| Penetration testing     | Minimal           | Ya                                               |
| Tool support            | Minimal           | Ya                                               |
| Secure Supply Chain     | Kadang-kadang     | Ya                                               |

Kami akan mendorong siapa pun yang ingin mengadopsi standar keamanan
aplikasi untuk menggunakan [OWASP Application Security Verification
Standar](https://owasp.org/www-project-application-security-verification-standard/) 
(ASVS), karena ini dirancang agar dapat diverifikasi dan
diuji, dan dapat digunakan di semua bagian dari siklus hidup
pengembangan yang aman. 

ASVS hanyalah sebuah pilihan yang dapat diterima untuk vendor alat.
Alat tidak bisa secara menyeluruh mendeteksi, menguji, ataupun melindungi
dari OWASP Top 10 dikarenakan sifat dari beberapa resiko OWASP Top 10,
dengan mengacu kepada A04:2021-Insecure Design. OWASP tidak menyarankan
cakupan penuh dari OWASP Top 10, karena hal itu sama sekali tidak benar.
