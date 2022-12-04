# Bagaimana cara menggunakan OWASP Top 10 sebagai sebuah standarisasi

OWASP Top 10 terutama merupakan dokumen kesadaran. Bagaimanapun, hal ini
tidak menutup organisasi untuk menggunakannya sebagai sebuah standar de 
facto pada industri keamanan aplikasi sejak kelahirannya pada tahun 2003.
Apabila Anda ingin menggunakan OWASP Top 10 sebagai standar dalam coding 
atau pengujian, ketahuilah bahwa ini adalah batas minimal dan hanya sebuah
tahap awal.

Salah satu kesulitan dalam menggunakan OWASP Top 10 sebagai sebuah standar
adalah kita mendokumentasikan resiko keamanan aplikasi, dan belum tentu
sebuah masalah yang mudah diuji. Sebagai contohnya, A04:2021-Insecure Design
yang mana berada di luar cakupan sebagian besar bentuk dari pengujian.
Contoh lainnya adalah pengujian di tempat, digunakan, dan pencatatan dan
pemantauan yang efektif hanya dapat dilakukan dengan wawancara dan meminta
sebuah sampel dari respon tanggapan insiden yang efektif. Sebuah alat analisa
kode statis dapat melihat mengenai ketidakhadiran pada pencatatan, namun hal
ini mungkin mustahil untuk ditentukan apabila business logic atau kontrol
akses mencatat penjebolan keamanan yang kritis. penguji penetrasi hanya dapat
menentukan bahwa mereka telah memanggil respons insiden di lingkungan pengujian, 
yang jarang dipantau dengan cara yang sama seperti pada produksi.

Berikut adalah rekomendasi kami mengenai kapan waktu yang tepat untuk
menggunakan OWASP Top 10:

| Use Case                | OWASP Top 10 2021 | OWASP Application Security Verification Standard |
|-------------------------|:-------------------:|:--------------------------------------------------:|
| Awareness               | Yes               |                                                  |
| Training                | Entry level       | Comprehensive                                    |
| Design and architecture | Occasionally      | Yes                                              |
| Coding standard         | Bare minimum      | Yes                                              |
| Secure Code review      | Bare minimum      | Yes                                              |
| Peer review checklist   | Bare minimum      | Yes                                              |
| Unit testing            | Occasionally      | Yes                                              |
| Integration testing     | Occasionally      | Yes                                              |
| Penetration testing     | Bare minimum      | Yes                                              |
| Tool support            | Bare minimum      | Yes                                              |
| Secure Supply Chain     | Occasionally      | Yes                                              |

Kami akan mendorong siapa pun yang ingin mengadopsi standar keamanan
aplikasi untuk menggunakan OWASP Application Security Verification
Standar (ASVS), yang mana ini dirancang agar dapat diverifikasi dan
diuji, dan dapat digunakan di berbagai bagian dari siklus hidup
pengembangan yang aman. 

ASVS hanyalah sebuah pilihan yang dapat diterima untuk vendor alat.
Alat tidak bisa secara menyeluruh mendeteksi, menguji, ataupun melindungi
dari OWASP Top 10 dikarenakan sifat dari beberapa resiko OWASP Top 10,
dengan mengacu kepada A04:2021-Insecure Design. OWASP tidak menyarankan
penangguhan penuh dari OWASP Top 10, dikarenakan hal itu tidak benar.
