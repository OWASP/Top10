# Pengenalan

## Selamat datang di OWASP Top 10 - 2021

Selamat datang di pemasangan terbaru dari OWASP TOP 10! OWASP TOP 10 2021 semuanya baru, dengan desain grafis baru dan tersedia infografis satu halaman yang dapat anda cetak atau dapatkan dari halaman kami.

Terima kasih banyak untuk semuanya yang telah menyumbangkan waktu dan datanya untuk iterasi ini. Tanpa anda, instalasi ini tidak akan selesai. **Terima Kasih**

## Apa yang berubah di Top 10 untuk 2021

Terdapat tiga kategori baru, empat kategori dengan penamaan dan perbuahan ruang lingkup, dan beberapa konsolidasi baru di Top 10 untuk 2021

![license](assets/mapping.png)

- **A01:2021-Broken Access Control** naik dari posisi kelima; 94% dari aplikasi yang telah diuji dengan broken access kontrol dalam beberapa bentuk. 34 CWE yang dipetakan ke Broken Access Control memiliki lebih banyak kemunculan dalam aplikasi daripada kategori lainnya.
- **A02:2021-Cryptographic Failures** menggeser satu posisi menjadi #2, sebelumnya dikenal sebagai Paparan data sensitif, yang merupakan gejala luas dan bukan penyebab utama. Fokus baru di sini adalah pada kegagalan yang terkait dengan kriptografi yang sering mengarah pada Paparan Data Sensitif atau kompromi sistem.
- **A03:2021-Injection** turun ke posisi ketiga. 94% aplikasi diuji untuk beberapa bentuk injeksi, dan 33 CWE yang dipetakan ke dalam kategori ini memiliki kejadian terbanyak kedua dalam aplikasi. Skrip cross-site sekarang menjadi bagian dari kategori ini dalam edisi ini. 
- **A04:2021-Insecure Design** adalah kategori baru untuk tahun 2021, dengan fokus pada resiko yang terkait dengan kekurangan desain. Jika kita ingin benar-benar bergerak sebagai industri, itu membutuhkan lebih banyak penggunaan pemodelan ancaman, pola dan desain yang aman, dan arsitektur referensi
- **A05:2021-Security Misconfiguration** naik dari #6 di edisi sebelumnya; 90% aplikasi diuji untuk beberapa bentuk kesalahan konfigurasi. Dengan lebih banyak perubahan ke software dengan konfigurasi yang banyak, tidak mengherankan melihat kategori ini naik. Kategori sebelumnya untuk XML External Entities (XXE) sekarang menjadi bagian dari kategori ini.
- **A06:2021-Vulnerable and Outdated Components** sebelumnya berjudul Using Components with Known Vulnerabilities dan #2 dalam survei industri, tapi juga memiliki cukup data untuk masuk TOP 10 melalui analisis data. Kategori ini naik dari #9 di tahun 2017 dan merupakan masalah umum yang kami perjuangkan untuk menguji dan menilai resiko. Ini adalah satu-satunya kategori yang tidak memiliki CVE yang dipetakan ke CWE yang disertakan, jadi eksploitasi default dan bobot dampak 5.0 diperhitungkan dalam skornya.
- **A07:2021-Identification and Authentication Failures** sebelumnya dalah Broken Authentication dan turun dari posisi kedua, dan sekarang termasuk CWE yang lebih terkait dengan kegagalan identifikasi. Kategori ini masih merupakan bagian integral dari Top 10, tetapi peningkatan ketersediaan framework yang telah distandarisasi tampaknya membantu.
- **A08:2021-Software and Data Integrity Failures** adalah kategori baru untuk tahun 2021, yang berfokus pada pembuatan asusmsi terkait pembaruan perangkat lunak, data penting, dan pipeline CI/CD tanpa memverifikasi integritas. Salah satu dampak tertinggi dari CVE/CVSS yang dipetakan ke 10 CWE dalam kategori ini. Insecure Deserialization dari tahun 2017 sekarang menjadi bagian dari kategori yang lebih besar ini.
- **A09:2021-Security Logging and Monitoring Failures** sebelumnya Logging dan Monitoring tidak memadai dan ditambahkan dari survei industri (#3), naik dari #10 sebelumnya. Kategori ini diperluas untuk mencakup lebih banyak jenis kegagalan, menatang untuk diiuji, dan tidak terwakili dengan baik dalam data CVE/CVSS. Namun, kegagalan dalam kategori ini dapat secara langsung memengaruhi visibilita, peringatan insiden, dan forensik
- **A10:2021-Server-Side Request Forgery** ditambahkan dari survei industri (#1). Data menunjukkan tingkat insiden yang relatif rendah dengan cakupan pengujian di atas rata-rata, bersama dengan peringkat di atas rata-rata untuk potensi eksploitasi dan dampak. Kategori ini mewakili skenario di mana para profesional industri memberi tahu kami bahwa ini penting, meskipun tidak diilustrasikan dalam data saat ini.

## Metodologi

Pemasangan dari Top 10 ini lebih didorong oleh data daripada sebelumnya tetapi tidak didorong oleh data secara membabi buta. Kami memilih delapan dari sepuluh kategori dari kontribusi data dan 2 kategori dari survei industri tingkat tinggi. Kami melakukan ini karena alasan mendasar, melihat data yang disumbangkan berarti melihat ke masa lalu. Peneliti AppSec membutuhkan waktu untuk menemukan kerentanan baru dan cara baru untuk mengujinya. Dibutuhkan waktu untuk mengintegrasikan tes ini ke dalam alat dan proses. Pada saat kita dapat dengan andal menguji kelemahan dalam skala, tahun-tahun kemungkinan telah berlalu. Untuk menyeimbangkan pandangan itu, kami menggunakan survei industri untuk bertanya kepada orang-orang di garis depan apa yang mereka lihat sebagai kelemahan penting yang mungkin belum ditunjukkan oleh data.

Ada beberapa perubahan penting yang kami adopsi untuk terus mematangkan Top 10.

## Bagaimana kategori disusun

Beberapa kategori telah berubah dari pemasangan OWASP Top 10 sebelumnya. Berikut adalah ringkasan tingkat tinggi dari perubahan kategori

Upaya pengumpulan data sebelumnya difokuskan pada subset yang ditentukan sekitar 30 CWE dengan bidang yang meminta temuan tambahan. Kami mengetahui bahwa organisasi akan fokus hanya pada 30 CWE tersebut dan jarang menambahkan CWE tambahan yang mereka lihat. Dalam iterasi ini, kami membukanya dan hanya meminta data, tanpa batasan pada CWE. Kami meminta jumlah aplikasi yang diuji untuk tahun tertentu (mulai 2017), dan jumlah aplikasi dengan setidaknya satu contoh CWE yang ditemukan dalam pengujian. Format ini memungkinkan kami untuk melacak seberapa lazim setiap CWE dalam populasi aplikasi. Kami mengabaikan frekuensi untuk tujuan kami; sementara mungkin diperlukan untuk situasi lain, itu hanya menyembunyikan prevalensi aktual dalam populasi aplikasi. Apakah sebuah aplikasi memiliki empat instans CWE atau 4.000 instans bukanlah bagian dari perhitungan untuk 10 Besar. Kami beralih dari sekitar 30 CWE menjadi hampir 400 CWE untuk dianalisis dalam kumpulan data. Kami berencana untuk melakukan analisis data tambahan sebagai suplemen di masa depan. Peningkatan jumlah CWE yang signifikan ini memerlukan perubahan pada struktur kategori.

Kami menghabiskan beberapa bulan untuk mengelompokkan dan mengkategorikan CWE dan dapat melanjutkannya selama beberapa bulan lagi. Kami harus berhenti di beberapa titik. Ada akar penyebab dan jenis gejala CWE, di mana jenis akar penyebab seperti "Kegagalan Kriptografis" dan "Kesalahan Konfigurasi" kontras dengan jenis gejala seperti "Paparan Data Sensitif" dan "Penolakan Layanan." Kami memutuskan untuk fokus pada akar penyebab bila memungkinkan karena lebih logis untuk memberikan panduan identifikasi dan perbaikan. Berfokus pada akar penyebab di atas gejala bukanlah konsep baru; Sepuluh Besar telah menjadi campuran gejala dan akar penyebab. CWE juga merupakan campuran dari gejala dan akar penyebab; kami hanya menjadi lebih berhati-hati tentang hal itu dan menyebutnya. Ada rata-rata 19,6 CWE per kategori dalam pemasangan ini, dengan batas bawah pada 1 CWE untuk A10:2021-Server-Side Request Forgery (SSRF) hingga 40 CWE dalam A04:2021-Insecure Design. Struktur kategori yang diperbarui ini menawarkan manfaat pelatihan tambahan karena perusahaan dapat fokus pada CWE yang masuk akal untuk bahasa/kerangka kerja.    

## Bagaimana data digunakan untuk memilih kategori

Pada tahun 2017, kami memilih kategori berdasarkan tingkat insiden untuk menentukan kemungkinan, lalu memeringkatnya berdasarkan diskusi tim berdasarkan pengalaman puluhan tahun untuk Exploitability, Detectability (juga kemungkinan), dan Dampak Teknis. Untuk tahun 2021, kami ingin menggunakan data untuk Exploitability and Impact jika memungkinkan.

Kami mengunduh Pemeriksaan Ketergantungan OWASP dan mengekstrak Eksploitasi CVSS, dan skor Dampak yang dikelompokkan berdasarkan CWE terkait. Butuh sedikit riset dan usaha karena semua CVE memiliki skor CVSSv2, tetapi ada kekurangan dalam CVSSv2 yang harus diatasi oleh CVSSv3. Setelah titik waktu tertentu, semua CVE juga diberi skor CVSSv3. Selain itu, rentang penilaian dan formula diperbarui antara CVSSv2 dan CVSSv3.

Di CVSSv2, Eksploitasi dan Dampak bisa mencapai 10,0, tetapi rumusnya akan menjatuhkannya hingga 60% untuk Eksploitasi dan 40% untuk Dampak. Di CVSSv3, maks secara teori dibatasi hingga 6,0 untuk Eksploitasi dan 4,0 untuk Dampak. Dengan mempertimbangkan pembobotan, skor Dampak bergeser lebih tinggi, rata-rata hampir satu setengah poin di CVSSv3, dan kemampuan eksploitasi turun rata-rata hampir setengah poin.

Ada 125 ribu catatan CVE yang dipetakan ke CWE dalam data NVD yang diekstraksi dari OWASP Dependency Check, dan ada 241 CWE unik yang dipetakan ke CVE. Peta CWE 62 ribu memiliki skor CVSSv3, yang kira-kira setengah dari populasi dalam kumpulan data.

Untuk Top 10, kami menghitung rata-rata skor eksploitasi dan dampak dengan cara berikut. Kami mengelompokkan semua CVE dengan skor CVSS berdasarkan CWE dan memberi bobot pada skor eksploitasi dan dampak berdasarkan persentase populasi yang memiliki skor CVSSv3 + populasi yang tersisa dari skor CVSSv2 untuk mendapatkan rata-rata keseluruhan. Kami memetakan rata-rata ini ke CWE dalam kumpulan data untuk digunakan sebagai skor Eksploitasi dan Dampak untuk separuh persamaan risiko lainnya.

## Kenapa tidak hanya data statistik murni?

Hasil dalam data utamanya terbatas pada apa yang dapat kami uji secara otomatis. Bicaralah dengan AppSec berpengalaman, dan mereka akan memberi tahu Anda tentang hal-hal yang mereka temukan dan tren yang mereka lihat yang belum ada dalam data. Dibutuhkan waktu bagi orang untuk mengembangkan metodologi pengujian untuk jenis kerentanan tertentu dan kemudian lebih banyak waktu agar pengujian tersebut diotomatisasi dan dijalankan terhadap populasi aplikasi yang besar. Semua yang kami temukan adalah melihat kembali ke masa lalu dan mungkin kehilangan tren dari tahun lalu, yang tidak ada dalam data.

Oleh karena itu, kami hanya memilih delapan dari sepuluh kategori dari data karena tidak lengkap. Dua kategori lainnya berasal dari survei industri. Hal ini memungkinkan para praktisi di garis depan untuk memilih apa yang mereka lihat sebagai risiko tertinggi yang mungkin tidak ada dalam data (dan mungkin tidak pernah diungkapkan dalam data).

## Mengapa tingkat insiden bukan frekuensi?

Ada tiga sumber data utama. Kami mengidentifikasi mereka sebagai Human-assisted Tooling (HaT), Tool-assisted Human (TaH), dan raw Tooling.

Tooling dan HaT adalah generator pencarian frekuensi tinggi. Alat akan mencari kerentanan tertentu dan tanpa lelah berusaha untuk menemukan setiap contoh kerentanan itu dan akan menghasilkan jumlah temuan yang tinggi untuk beberapa jenis kerentanan. Lihatlah Cross-Site Scripting, yang biasanya merupakan salah satu dari dua rasa: itu kesalahan kecil yang terisolasi atau masalah sistemik. Jika ini merupakan masalah sistemik, jumlah temuan bisa mencapai ribuan untuk sebuah aplikasi. Frekuensi tinggi ini menenggelamkan sebagian besar kerentanan lain yang ditemukan dalam laporan atau data.
TaH, di sisi lain, akan menemukan jenis kerentanan yang lebih luas tetapi pada frekuensi yang jauh lebih rendah karena kendala waktu. Ketika manusia menguji aplikasi dan melihat sesuatu seperti Cross-Site Scripting, mereka biasanya akan menemukan tiga atau empat instance dan berhenti. Mereka dapat menentukan temuan sistemik dan menuliskannya dengan rekomendasi untuk diperbaiki pada skala aplikasi yang luas. Tidak perlu (atau waktu) untuk menemukan setiap contoh.

Misalkan kita mengambil dua kumpulan data yang berbeda ini dan mencoba menggabungkannya pada frekuensi. Dalam hal ini, data Tooling dan HaT akan menenggelamkan data TaH yang lebih akurat (tetapi luas) dan merupakan bagian yang baik dari mengapa sesuatu seperti Cross-Site Scripting memiliki peringkat yang sangat tinggi di banyak daftar ketika dampaknya umumnya rendah hingga sedang. Itu karena banyaknya temuan. (Cross-Site Scripting juga cukup mudah untuk diuji, jadi ada lebih banyak tes untuk itu juga).
Pada tahun 2017, kami memperkenalkan penggunaan tingkat insiden sebagai gantinya untuk melihat data baru dan menggabungkan data Tooling dan HaT dengan data TaH dengan rapi. Tingkat insiden menanyakan berapa persentase populasi aplikasi yang memiliki setidaknya satu contoh jenis kerentanan. Kami tidak peduli apakah itu satu kali atau sistemik. Itu tidak relevan untuk tujuan kita; kita hanya perlu mengetahui berapa banyak aplikasi yang memiliki setidaknya satu instance, yang membantu memberikan pandangan yang lebih jelas tentang pengujian temuan di beberapa jenis pengujian tanpa menenggelamkan data dalam hasil frekuensi tinggi.

## Apa proses pengumpulan dan analisis data Anda?

Kami meresmikan proses pengumpulan data OWASP Top 10 di Open Security Summit pada 2017. Para pemimpin OWASP Top 10 dan komunitas menghabiskan dua hari untuk memformalkan proses pengumpulan data yang transparan. Edisi 2021 adalah kedua kalinya kami menggunakan metodologi ini.
Kami mempublikasikan panggilan untuk data melalui saluran media sosial yang tersedia untuk kami, baik proyek maupun OWASP. Pada halaman Proyek OWASP, kami mencantumkan elemen dan struktur data yang kami cari dan cara mengirimkannya. Dalam proyek GitHub, kami memiliki file contoh yang berfungsi sebagai template. Kami bekerja dengan organisasi yang diperlukan untuk membantu mengetahui struktur dan pemetaan ke CWE.
Kami mendapatkan data dari organisasi yang menguji vendor berdasarkan perdagangan, vendor bug bounty, dan organisasi yang menyumbangkan data pengujian internal. Setelah kami memiliki data, kami memuatnya bersama dan menjalankan analisis fundamental tentang apa yang dipetakan CWE ke kategori risiko. Ada tumpang tindih antara beberapa CWE, dan yang lainnya sangat erat kaitannya (mis. Kerentanan kriptografis). Setiap keputusan yang terkait dengan data mentah yang dikirimkan didokumentasikan dan dipublikasikan agar terbuka dan transparan dengan cara kami menormalkan data.

Kami melihat delapan kategori dengan tingkat insiden tertinggi untuk dimasukkan dalam Top 10. Kami juga melihat hasil survei industri untuk melihat mana yang mungkin sudah ada dalam data. Dua suara teratas yang belum ada dalam data akan dipilih untuk dua tempat lainnya di Top 10. Setelah kesepuluh dipilih, kami menerapkan faktor umum untuk eksploitabilitas dan dampak; untuk membantu menentukan peringkat 10 Besar secara berurutan.

## Faktor-faktor Data

Ada data faktor yang dicantumkan untuk masing-masing dari 10 Kategori Teratas, berikut artinya:

- CWEs Mapped: Jumlah CWE yang dipetakan ke kategori oleh 10 tim teratas.
- Incidence Rate: Tingkat insiden adalah persentase aplikasi yang rentan terhadap CWE tersebut dari populasi yang diuji oleh organisasi tersebut untuk tahun tersebut.
- (Pengujian) Cakupan: Persentase aplikasi yang diuji oleh semua organisasi untuk CWE tertentu.
- Weighted Exploit: Sub-skor Eksploitasi dari skor CVSSv2 dan CVSSv3 yang ditetapkan ke CVE yang dipetakan ke CWE, dinormalisasi, dan ditempatkan pada skala 10pt.
- Weighted Impact: Sub-skor Dampak dari skor CVSSv2 dan CVSSv3 yang ditetapkan ke CVE dipetakan ke CWE, dinormalisasi, dan ditempatkan pada skala 10pt.
- Total Kejadian: Jumlah total aplikasi yang ditemukan memiliki CWE yang dipetakan ke suatu kategori.
- Total CVE: Jumlah total CVE dalam NVD DB yang dipetakan ke CWE yang dipetakan ke suatu kategori.

### Hubungan Kategori dari 2017

Ada banyak pembicaraan tentang tumpang tindih antara risiko Top 10. Menurut definisi masing-masing (daftar CWE yang termasuk), sebenarnya tidak ada tumpang tindih. Namun, secara konseptual, dapat terjadi tumpang tindih atau interaksi berdasarkan penamaan tingkat yang lebih tinggi. Diagram Venn berkali-kali digunakan untuk menunjukkan tumpang tindih seperti ini.

Diagram Venn di atas merepresentasikan interaksi antara Sepuluh Kategori Risiko Teratas 2017. Saat melakukannya, beberapa poin penting menjadi jelas:

1. Orang bisa berargumen bahwa Cross-Site Scripting pada akhirnya termasuk dalam Injeksi karena pada dasarnya adalah Injeksi Konten. Melihat data tahun 2021, semakin jelas bahwa XSS perlu pindah ke Injeksi.
2. Tumpang tindih hanya satu arah. Kita akan sering mengklasifikasikan kerentanan berdasarkan manifestasi akhir atau "gejala", bukan akar penyebab (yang berpotensi dalam). Misalnya, "Eksposur Data Sensitif" mungkin merupakan hasil dari "Kesalahan Konfigurasi Keamanan"; namun, Anda tidak akan melihatnya ke arah lain. Akibatnya, panah digambar di zona interaksi untuk menunjukkan arah mana itu terjadi.
3. Terkadang diagram ini digambar dengan semua yang ada di A06:2021 Menggunakan Komponen dengan Kerentanan yang Diketahui. Sementara beberapa kategori risiko ini mungkin menjadi akar penyebab kerentanan pihak ketiga, mereka umumnya dikelola secara berbeda dan dengan tanggung jawab yang berbeda. Jenis lainnya biasanya mewakili risiko pihak pertama.

### Terima kasih kepada kontributor data kami

Organisasi berikut (bersama dengan beberapa donor anonim) dengan baik hati menyumbangkan data untuk lebih dari 500.000 aplikasi untuk menjadikan ini kumpulan data keamanan aplikasi terbesar dan terlengkap. Tanpa Anda, ini tidak akan mungkin.

- AppSec Labs
- Cobalt.io
- Contrast Security
- GitLab
- HackerOne
- HCL Technologies
- Micro Focus
- PenTest-Tools
- Probely
- Sqreen
- Veracode
- WhiteHat (NTT)
