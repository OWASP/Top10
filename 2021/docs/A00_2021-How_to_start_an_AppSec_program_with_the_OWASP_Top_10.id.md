# Bagaimana cara untuk memulai program AppSec dengan OWASP Top 10

Sebelumnya, OWASP Top 10 tidak pernah dirancang untuk menjadi basis dari sebuah
program AppSec. Bagaimanapun, hal ini diperlukan untuk memulai darimanapun bagi
berbagai organisasi yang baru saja memulai perjalanan mereka dalam keamanan
aplikasi OWASP Top 10 2021 merupakan awal yang baik sebagai landasan untuk daftar
periksa dan sebagainya, tapi itu sendiri tidak cukup.

## Tahap 1. Identifikasi kesenjangan dan tujuan dari program appsec anda

Banyak program Keamanan Aplikasi (AppSec) mencoba untuk berlali sebelum mereka
dapat merangkak atau berjalan. Usaha seperti ini pasti akan gagal. Kami sangat
mendorong pimpinan CISO dan AppSec untuk menggunakan Jaminan Perangkat Lunak OWASP
Model Kematangan (SAMM) \[<https://owaspsamm.org>\] untuk mengidentifikasi
kelemahan dan wilayah untuk perbaikan selama periode 1-3 tahun. Tahap pertama
adalah untuk evaluasi dimana anda sekarang, identifikasi kesenjangan pada
pemerintahan, perencanaan, implementasi, verifikasi, dan operasi yang anda
butuhkan untuk menyelesaikan segera versus yang bisa menunggu, dan memprioritaskan
implementasi atau memperbaiki lima belas praktik keamanan OWASP SAMM. OWASP SAMM
dapat membantu you build and measure improvements in your software assurance
efforts. anda membangun dan menimbang perbaikan dalam jaminan usaha perangkat
lunak anda.

## Tahap 2. Rencana untuk siklus hidup pengembangan yang aman

Secara tradisional melestarikan apa yang disebut dengan "unicorns," konsep
jalan beraspal adalah jalan termudah untuk membuat sumber daya Aplikasi Keamanan
yang sangat berdampak dan berskala dengan kecepatan pengembangan tim, yang mana
meningkat setiap tahun. 

Konsep pengembangan yang aman adalah "jalan termudah dan juga jalur teraman" dan harus
melibatkan budaya kemitraan yang mendalam antara team pengembang dan tim
keamanan, sebaiknya seperti mereka adalah satu dan dalam tim yang sama. Jalan
beraspal bertujuan untuk terus memperbaiki, menimbang, mendeteksi dan mengubah
alternatif yang tidak aman dengan memiliki sebuah perpustakaan dengan skala
seluruh perusahaan untuk menempatkan perubahan yang aman dengan alat untuk
membantu melihat dimana perbaikan dapat dibuat dengan mengadopsi konsep jalan
beraspal. Ini memungkinkan alat pengembangan yang ada untuk melaporkan pembuatan
dan membantu tim pengembang untuk mengoreksi kembali dari alternatif yang tidak
aman.

Konsep pengembangan yang aman mungkin tampak banyak yang harus dilalui, tetapi itu harus dibangun secara bertahap dari waktu ke waktu. Ada bentuk lain dari program keamanan aplikasi diluar sana, terutama Microsoft Agile Secure Development Lifecycle. Tidak semua metode program keamanan aplikasi sesuai dengan semua bisnis.

## Tahap 3. Mengimplementasikan konsep jalan beraspal dengan tim pengembang anda.

Konsep jalan beraspal dibentuk dengan persetujuan dan keterlibatan langsung dari tim pengembang dan operasi yang relevan. Pengembangan yang aman harus disejajarkan secara strategis dengan sisi bisnis dan membantu mengantarkan kembali aplikasi yang aman lebih cepat. Mengembangkan Konsep Pengembangan yang aman harus menjadi panduan penjagaan latihan yang mencakup seluruh perusahaan ataupun ekosistem aplikasi, bukan sebagai tambalan untuk aplikasi yang belum siap, seperti di hari-hari sebelumnya.

## Tahap 4. Migrasikan semua aplikasi yang akan datang dan yang sudah ada ke Konsep Pengembangan yang aman.

Tambahkan Alat pendeteksi pada Konsep Pengembangan yang aman saat anda mengembangkannya 
dan menyediakan informasi untuk tim pengembang untuk meningkatkan keamanan dari 
aplikasi mereka dengan bagaimana mereka bisa langsung mengadopsi elemen dari konsep 
jalan beraspal. Ketika sebuah aspekdari konsep jalan beraspal telah diadopsi, 
organisasi harus mengimplementasikan pemeriksaan integrasi yang berkelanjutan yang 
mana memeriksa kode yang telah ada dan check-in yang menggunakan alternatif terlarang 
dan memperingatkan atau menolak build program atau check-in. Hal ini mencegah opsi 
yang tidak aman dapat merayap ke dalam kode sepanjang waktu, mencegah hutang teknis 
dan aplikasi tidak aman yang rusak. Peringatan semacam itu harus terhubung kepada 
alternatif yang aman, sehingga tim pengembang dapat diberikan jawaban yang benar 
sesegera mungkin. Mereka dapat melakukan refactoring dan mengadopsi kompnen pada 
konsep jalan beraspal dengan cepat.

## Tahap 5. Uji apakah konsep Pengembangan yang aman telah mengurangi masalah yang ditemukan di OWASP Top 10

Komponen konsep Pengembangan yang aman harus mengatasi masalah  yang signifikan
dengan OWASP Top 10, sebagai contohnya, bagaimana untuk mendeteksi secara
otomatis atau memperbaiki komponen yang rentan, atau plugin IDE analisis
kode statis untuk mendeteksi injeksi atau bahkan lebih seperti perpustakaan
yang dikenal aman terhadap injeksi, seperti React atau Vue. Semakin banyak
penggantian pengiriman aman yang diberikan kepada tim, semakin baik. sebuah
tugas penting pada tim keamanan aplikasi adalah untuk memastikan bahwa
keamanan komponen-komponen ini adalah ditingkatkan dan dievaluasi secara
berkelanjutan. Setelah mereka diperbaiki, beberapa bentuk jalur komunikasi
dengan konsumen dari komponen harus mengindikasikan bahwa peningkatan harus
terjadi, sebaiknya secara otomatis, tapi apabila tidak, setidaknya disorot
pada sebuah tampilan dasar atau sejenisnya.

## Tahap 6. Bangun program anda menjadi program keamanan aplikasi yang matang

Anda tidak boleh berhenti hanya di OWASP Top 10. Itu hanya mencakup
10 kategori resiko. Kami sangat mendorong organisasi untuk mengadopsi
Application Security Verification Standard dan semakin menambah
komponen jalan beraspal dan menguji untuk tingkat 1, 2, dan 3,
tergantung pada pengembangan tingkat resiko pada aplikasi 

## Melampaui

Semua program aplikasi keamanan yang hebat pergi melampaui batas minimal.
Semua orang harus terus melaju jika kita akan berada di atas untuk
kerentanan keamanan aplikasi.

-   **Integritas Konseptual**. Program aplikasi keamanan yang matang
    harus mengandung beberapa konsep dari arsitektur keamanan,
    Apakah berupa cloud yang formal atau arsitektur keamanan
    perusahaan atau threat modeling.

-   **Skala dan otomasi**. Program aplikasi keamanan yang matang mencoba
    untuk mengotomasi sebanyak pengiriman yang dapat dilakukan,
    menggunakan skrip untuk meniru tahapan penetration testing yang
    kompleks, alat analisis kode statis tersedia secara langsung ke
    tim pengembang, membantu tim pengembang dalam membangun unit aplikasi
    keamanan dan pengujian integrasi, dan banyak lagi.

-   **Budaya**. Program Aplikasi Keamanan yang matang mencoba untuk
    membongkar rancangan yang tidak aman dan menghapuskan hutang teknis
    dari kode yang telah ada dengan menjadi bagian dari tim pengembang
    dan tidak menyampingkannya. tim aplikasi keamanan yang melihat tim
    pengembang sebagai "kami" atau "mereka" ditakdirkan untuk gagal.

-   **Peningkatan berkelanjutan**. Program Aplikasi Keamanan yang matang
    merujuk kepada peningkatan yang konstan. Apabila terjadi hal yang
    tidak bekerja atau berhenti melakukan hal tersebut. Apabila sesuatu
    kikuk atau tidak terukur, bekerjalah untuk meningkatkan nya. Apabila
    sesuatu tidak digunakan oleh tim pengembang dan tidak memiliki atau
    memiliki dampak yang terbatas, lakukan sesuatu yang berbeda. Hanya
    karena kita telah melakukan pengujian seperti desk checks sejak
    tahun 1970-an tidak berarti itu adalah ide bagus. Ukur, evaluasi, 
    lalu bangun atau tingkatkan.
