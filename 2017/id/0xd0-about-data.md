# +Dat Metodologi dan Data

Di Konferensi Proyek OWASP, peserta aktif dan anggota komunitas memutuskan dalam konteks kerentanan, sampai dengan dua (2) kelas kerentanan ke depan, pengurutan didefinisikan sebagian oleh data kuantitatif, dan sebagian oleh survei kualitatif.

 
## Survei Peringkat Industri

Untuk survei, kami mengumpulkan kategori kerentanan yang telah diidentifikasi sebelumnya sebagai “di titik puncak” atau disebutkan dalam tanggapan untuk 2017 RC1 pada Top 10 mailing list. Kami memasukkan mereka ke dalam survei peringkat dan meminta responden untuk memberikan peringkat kepada empat kerentanan teratas yang mereka rasakan harus disertakan dalam OWASP Top 10 - 2017. Survei dibuka dari 2 Agustus - 18 September 2017. 516 tanggapan dikumpulkan dan kerentanan-kerentanan tersebut telah diberikan peringkat.

| Peringkat | Kategori Survei Kerentanan | Nilai |
| -- | -- | -- |
| 1 | Paparan Informasi Pribadi ('Pelanggaran Privasi') [CWE-359] | 748 |
| 2 | Kegagalan Kriptografi [CWE-310/311/312/326/327]| 584 |
| 3 | Deserialisasi Data yang Tidak Terpercaya [CWE-502] | 514 |
| 4 | Melewati Otorisasi Melalui Kunci yang Dikontrol Oleh Pengguna (IDOR & Path Traversal) [CWE-639] | 493 |
| 5 | Kurangnya Logging dan Pemantauan [CWE-223 / CWE-778]| 440 |

Paparan Informasi Pribadi jelas merupakan kerentanan dengan peringkat tertinggi, namun sangat cocok digunakan sebagai penekanan tambahan pada **A3:2017-Pengungkapan Data Sensitif**. Kegagalan Kriptografi dapat dimasukan dalam Pengungkapan Data Sensitif. Deserialisasi yang tidak aman berada di peringkat tiga, jadi ditambahkan ke Top 10 sebagai **A8:2017-Deserialization yang Tidak Aman** setelah penilaian resiko. Kunci yang Dikontrol Oleh Pengguna yang berada di posisi keempat diikutkan dalam **A5:2017-Akses Kontrol yang Rusak**; Adalah baik untuk melihatnya berperingkat tinggi dalam survei, karena tidak banyak data yang berkaitan dengan kerentanan otorisasi. Kategori peringkat nomor lima dalam survei ini adalah Kurangnya Logging dan Pemantauan, yang menurut kami sesuai untuk daftar Top 10, oleh karena itu, ini dijadikan **A10:2017-Kurangnya Logging dan Pemantauan**. Kami telah pindah ke titik di mana aplikasi harus dapat menentukan apa yang mungkin merupakan serangan dan menghasilkan penebangan, peringatan, eskalasi, dan respons yang tepat. 

## Panggilan Data Publik

Secara tradisional, data yang dikumpulkan dan dianalisis lebih sesuai dengan data frekuensi: berapa banyak kerentanan yang ditemukan pada aplikasi yang diuji. Seperti diketahui, alat yang secara tradisional melaporkan semua kasus ditemukan adanya kerentanan dan manusia secara tradisional melaporkan satu temuan dengan sejumlah contoh. Hal ini membuat sangat sulit untuk menggabungkan dua gaya pelaporan dengan cara yang sebanding.

Untuk tahun 2017, tingkat kejadian dihitung oleh berapa banyak aplikasi dalam kumpulan data tertentu yang memiliki satu atau lebih jenis kerentanan tertentu. Data dari banyak kontributor yang lebih besar diberikan dalam dua pandangan. Yang pertama adalah gaya frekuensi tradisional untuk menghitung setiap contoh yang menemukan kerentanan, sementara yang kedua adalah penghitungan aplikasi di mana setiap kerentanan ditemukan pada (satu atau beberapa kali). Meski tidak sempurna, ini cukup memungkinkan kita untuk membandingkan data dari Human Assisted Tools dan Tool Assisted Humans. Data mentah dan hasil analisisnya [tersedia di GitHub](https://github.com/OWASP/Top10/tree/master/2017/datacall). Kami bermaksud untuk memperluas ini dengan struktur tambahan untuk versi Top 10 di masa depan.

Kami menerima 40+ pengajuan dalam panggilan untuk data, dan karena banyak dari data asli yang difokuskan pada frekuensi, kami dapat menggunakan data dari 23 kontributor yang mencakup ~ 114.000 aplikasi. Kami menggunakan blok waktu satu tahun jika memungkinkan dan diidentifikasi oleh kontributor. Mayoritas aplikasi itu unik, meski kami mengetahui kemungkinan beberapa aplikasi pengulangan antara data tahunan dari Veracode. 23 kumpulan data yang digunakan diidentifikasi sebagai alat bantu pengujian manusia atau secara khusus memberikan tingkat kejadian dari alat bantu manusia. Anomali pada data terpilih kejadian 100% + disesuaikan sampai 100% maks. Untuk menghitung tingkat kejadian, kami menghitung persentase total aplikasi yang ditemukan mengandung masing-masing jenis kerentanan. Peringkat kejadian digunakan untuk perhitungan prevalensi dalam keseluruhan risiko untuk menentukan peringkat Top 10.
