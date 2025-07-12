# Bagaimana cara untuk memulai Program AppSec dengan OWASP Top 10

Sebelumnya, OWASP Top 10 tidak pernah dirancang untuk menjadi basis dari sebuah
program AppSec. Namun, perlu untuk memulai darimanapun bagi berbagai organisasi
yang baru saja mengawali perjalanan mereka dalam keamanan aplikasi. OWASP Top 
10 2021 merupakan awal yang baik sebagai landasan untuk daftar periksa dan 
sebagainya, tapi itu sendiri tidak cukup.

## Tahap 1. Identifikasi kesenjangan dan tujuan dari program appsec Anda

Banyak program Keamanan Aplikasi (AppSec) mencoba untuk berlari sebelum mereka
dapat merangkak atau berjalan. Usaha seperti ini pasti akan gagal. Kami sangat
mendorong pimpinan CISO dan AppSec untuk menggunakan [OWASP Software Assurance
Maturity Model (SAMM)](https://owaspsamm.org>) untuk mengidentifikasi
kelemahan dan wilayah untuk perbaikan selama periode 1-3 tahun. Tahap pertama
adalah untuk evaluasi di mana Anda sekarang, identifikasi kesenjangan pada
pemerintahan, perencanaan, implementasi, verifikasi, dan operasi yang Anda
butuhkan untuk menyelesaikan segera versus yang bisa menunggu, dan memprioritaskan
implementasi atau memperbaiki lima belas praktik keamanan OWASP SAMM. OWASP SAMM
dapat membantu Anda membangun dan mengukur peningkatan dalam upaya penjaminan
perangkat lunak Anda.

## Tahap 2. Rencanakan untuk jalan beraspal siklus hidup pengembangan yang aman

Secara tradisional melestarikan apa yang disebut dengan "unicorns", konsep
jalan beraspal adalah cara termudah untuk membuat sumber daya Aplikasi Keamanan
yang sangat berdampak dan berskala dengan kecepatan pengembangan tim, yang makin 
meningkat setiap tahun. 

Konsep pengembangan yang aman adalah "jalan termudah dan juga jalur teraman" dan harus
melibatkan budaya kemitraan yang mendalam antara tim pengembang dan tim
keamanan, lebih disukai mereka adalah satu tim yang sama. Jalan
beraspal bertujuan untuk terus memperbaiki, mengukur, mendeteksi, dan mengganti
alternatif yang tidak aman dengan memiliki sebuah perpustakaan dengan skala
seluruh perusahaan untuk menempatkan perubahan yang aman dengan alat untuk
membantu melihat di mana perbaikan dapat dibuat dengan mengadopsi konsep jalan
beraspal. Ini memungkinkan alat pengembangan yang ada untuk melaporkan build
yang tidak aman dan membantu tim pengembang untuk mengoreksi diri sendiri dari 
alternatif yang tidak aman.

Konsep pengembangan yang aman mungkin tampak banyak yang harus dilalui, tetapi 
itu harus dibangun secara bertahap dari waktu ke waktu. Ada bentuk lain dari 
program keamanan aplikasi di luar sana, terutama Microsoft Agile Secure 
Development Lifecycle. Tidak semua metode program keamanan aplikasi sesuai 
dengan semua bisnis.

## Tahap 3. Mengimplementasikan konsep jalan beraspal dengan tim pengembang Anda

Konsep jalan beraspal dibentuk dengan persetujuan dan keterlibatan langsung 
dari tim pengembang dan operasi yang relevan. Pengembangan yang aman harus 
diselaraskan secara strategis dengan sisi bisnis dan membantu mengantarkan 
aplikasi yang aman lebih cepat. Mengembangkan konsep jalan beraspal
harus menjadi latihan holistik yang mencakup seluruh perusahaan ataupun 
ekosistem aplikasi, bukan sebagai tambalan untuk aplikasi yang belum siap, 
seperti di masa lalu.

## Tahap 4. Migrasikan semua aplikasi yang akan datang dan yang sudah ada ke konsep jalan beraspal

Tambahkan alat pendeteksi pada konsep jalan beraspal saat Anda mengembangkannya 
dan sediakan informasi bagi tim pengembang untuk meningkatkan keamanan dari 
aplikasi mereka dengan bagaimana mereka bisa langsung mengadopsi elemen dari konsep 
jalan beraspal. Sekali sebuah aspek dari konsep jalan beraspal telah diadopsi, 
organisasi harus mengimplementasikan pemeriksaan integrasi berkelanjutan yang 
memeriksa kode yang telah ada dan check-in yang menggunakan alternatif terlarang 
dan memperingatkan atau menolak build atau check-in tersebut. Hal ini mencegah opsi 
yang tidak aman dapat merayap ke dalam kode dengan berjalannya waktu, mencegah 
hutang teknis, dan aplikasi tidak aman yang rusak. Peringatan semacam itu harus 
menaut kepada alternatif yang aman, sehingga tim pengembang diberik jawaban 
yang benar seketika. Mereka dapat melakukan refactor dan mengadopsi komponen 
konsep jalan beraspal dengan cepat.

## Tahap 5. Uji apakah konsep jalan beraspal telah memitigasi masalah yang ditemukan di OWASP Top 10

Komponen konsep jalan beraspal harus mengatasi masalah yang signifikan
dengan OWASP Top 10, sebagai contoh, bagaimana untuk mendeteksi secara
otomatis atau memperbaiki komponen yang rentan, atau plugin IDE analisis
kode statis untuk mendeteksi injeksi, atau lebih baik lagi seperti perpustakaan
yang dikenal aman terhadap injeksi. Semakin banyak pengganti aman yang ini 
diberikan kepada tim, semakin baik. Sebuah tugas penting pada tim keamanan 
aplikasi adalah untuk memastikan bahwa keamanan komponen-komponen ini 
ditingkatkan dan dievaluasi secara berkelanjutan. Setelah mereka diperbaiki, 
beberapa bentuk jalur komunikasi dengan konsumen dari komponen harus 
mengindikasikan bahwa peningkatan harus terjadi, sebaiknya secara otomatis, 
tapi apabila tidak, setidaknya disorot pada sebuah tampilan dasbor atau sejenisnya.

## Tahap 6. Bangun program Anda menjadi program keamanan aplikasi yang matang

Anda tidak boleh berhenti hanya di OWASP Top 10. Itu hanya mencakup
10 kategori resiko. Kami sangat mendorong organisasi untuk mengadopsi
Application Security Verification Standard dan semakin menambah
komponen jalan beraspal dan menguji untuk tingkat 1, 2, dan 3,
tergantung pada tingkat resiko aplikasi yang dikembangkan.

## Lakukan yang terbaik 

Semua program aplikasi keamanan yang baik melakukan usaha yang lebih dari batas minimal.
Semua orang harus terus melaju jika kita akan berada di atas untuk
kerentanan keamanan aplikasi.

-   **Integritas Konseptual**. Program aplikasi keamanan yang matang
    harus mengandung beberapa konsep dari arsitektur keamanan,
    apakah berupa cloud yang formal atau arsitektur keamanan
    perusahaan, atau pemodelan ancaman.

-   **Skala dan otomasi**. Program aplikasi keamanan yang matang mencoba
    untuk mengotomasi sebanyak mungkin hasil mereka,
    menggunakan skrip untuk meniru tahapan penetration testing yang
    kompleks, alat analisis kode statis tersedia secara langsung ke
    tim pengembang, membantu tim pengembang dalam membangun unit aplikasi
    keamanan dan pengujian integrasi, dan banyak lagi.

-   **Budaya**. Program Aplikasi Keamanan yang matang mencoba untuk
    membongkar rancangan yang tidak aman dan menghapuskan hutang teknis
    dari kode yang telah ada dengan menjadi bagian dari tim pengembang
    dan tidak menyampingkannya. Tim aplikasi keamanan yang melihat tim
    pengembang sebagai "kami" dan "mereka" ditakdirkan untuk gagal.

-   **Peningkatan berkelanjutan**. Program Aplikasi Keamanan yang matang
    merujuk kepada peningkatan yang konstan. Apabila sesuatu
    tidak bekerja, berhenti melakukan hal tersebut. Apabila sesuatu
    kikuk atau tidak terukur, bekerjalah untuk meningkatkannya. Apabila
    sesuatu tidak digunakan oleh tim pengembang dan tidak punya atau
    memiliki dampak yang terbatas, lakukan sesuatu yang berbeda. Hanya
    karena kita telah melakukan pengujian seperti desk check sejak
    tahun 1970-an tidak berarti itu adalah ide bagus. Ukur, evaluasi, 
    lalu bangun atau tingkatkan.
