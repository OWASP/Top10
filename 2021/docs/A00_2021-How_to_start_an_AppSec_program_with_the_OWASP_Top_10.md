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

## Tahap 2. Rencana untuk siklus hidup pengembangan jalan beraspal yang aman

Secara tradisional melestarikan apa yang disebut dengan "unicorns," konsep
jalan beraspal adalah jalan termudah untuk membuat sumber daya Aplikasi Keamanan
yang sangat berdampak dan berskala dengan kecepatan pengembangan tim, yang mana
meningkat setiap tahun. 

Konsep jalan beraspal adalah "jalan termudah dan juga jalur teraman" dan harus
melibatkan budaya kemitraan yang mendalam antara team pengembang dan tim
keamanan, sebaiknya seperti mereka adalah satu dan dalam tim yang sama. Jalan
beraspal bertujuan untuk terus memperbaiki, menimbang, mendeteksi dan mengubah
alternatif yang tidak aman dengan memiliki sebuah perpustakaan dengan skala
seluruh perusahaan untuk menempatkan perubahan yang aman dengan alat untuk
membantu melihat dimana perbaikan dapat dibuat dengan mengadopsi konsep jalan
beraspal. Ini memungkinkan alat pengembangan yang ada untuk melaporkan pembuatan
dan membantu tim pengembang untuk mengoreksi kembali dari alternatif yang tidak
aman.

Konsep jalan beraspal mungkin tampak banyak yang harus dilalui, tetapi itu harus dibangun secara bertahap dari waktu ke waktu. Ada bentuk lain dari program keamanan aplikasi diluar sana, terutama Microsoft Agile Secure Development Lifecycle. Tidak semua metode program keamanan aplikasi sesuai dengan semua bisnis.

## Tahap 3. Mengimplementasikan konsep jalan beraspal dengan tim pengembang anda.

Konsep jalan beraspal dibentuk dengan persetujuan dan keterlibatan langsung dari tim pengembang dan operasi yang relevan. Konsep jalan beraspal harus disejajarkan secara strategis dengan sisi bisnis dan membantu mengantarkan kembali aplikasi yang aman lebih cepat. Mengembangkan konsep jalan beraspal harus menjadi panduan penjagaan latihan yang mencakup seluruh perusahaan ataupun ekosistem aplikasi, bukan sebagai tambalan untuk aplikasi yang belum siap, seperti di hari-hari sebelumnya.

## Tahap 4. Migrasikan semua aplikasi yang akan datang dan yang sudah ada ke jalan beraspal.

Tambahkan Alat pendeteksi pada Konsep Jalan Beraspal saat anda mengembangkannya 
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

## Tahap 5. Uji apakah konsep jalan beraspal telah mengurangi masalah yang ditemukan di OWASP Top 10

Komponen konsep jalan beraspal harus mengatasi masalah  yang signifikan
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

## Stage 6. Build your program into a mature AppSec program

You must not stop at the OWASP Top 10. It only covers 10 risk
categories. We strongly encourage organizations to adopt the Application
Security Verification Standard and progressively add paved road
components and tests for Level 1, 2, and 3, depending on the developed
applications' risk level.

## Going beyond

All great AppSec programs go beyond the bare minimum. Everyone must keep
going if we're ever going to get on top of appsec vulnerabilities.

-   **Conceptual integrity**. Mature AppSec programs must contain some
    concept of security architecture, whether a formal cloud or
    enterprise security architecture or threat modeling

-   **Automation and scale**. Mature AppSec programs try to automate as
    much of their deliverables as possible, using scripts to emulate
    complex penetration testing steps, static code analysis tools
    directly available to the development teams, assisting dev teams in
    building appsec unit and integration tests, and more.

-   **Culture**. Mature AppSec programs try to build out the insecure
    design and eliminate the technical debt of existing code by being a
    part of the development team and not to the side. AppSec teams who
    see development teams as "us" and "them" are doomed to failure.

-   **Continuous improvement**. Mature AppSec programs look to
    constantly improve. If something is not working, stop doing it. If
    something is clunky or not scalable, work to improve it. If
    something is not being used by the development teams and has no or
    limited impact, do something different. Just because we've done
    testing like desk checks since the 1970s doesn't mean it's a good
    idea. Measure, evaluate, and then build or improve.
