# Pengantar

## Selamat datang ke OWASP Top 10 - 2021

![OWASP Top 10 Logo](./assets/TOP_10_logo_Final_Logo_Colour.png){:class="img-responsive"}

Selamat datang ke versi terakhir dari OWASP Top 10! OWASP Top 10 2021 semua baru, dengan desain grafis baru dan suatu infografis satu-halaman yang dapat Anda cetak atau dapatkan dari beranda kami.

Terima kasih sebesar-besarnya ke semua orang yang menyumbangkan waktu dan data mereka ke iterasi ini. Tanpa Anda, versi ini tidak akan ada. **TERIMA KASIH**

## Apa yang berubah di Top 10 untuk 2021

Terdapat tiga kategori baru, empat kategori dengan penamaan dan perubahan ruang lingkup, dan beberapa konsolidasi baru di Top 10 untuk 2021. Kami telah mengubah nama ketika diperlukan untuk berfokus pada akar masalah daripada gejala.

![Mapping](assets/mapping.png)

- **A01:2021-Broken Access Control** naik dari posisi kelima ke kategori dengan risiko keamanan aplikasi web paling serius; data yang disumbangkan mengindikasikan bahwa rata-rata, 3,81% aplikasi yang diuji memiliki satu atau lebih Common Weakness Enumeration (CWE) dengan lebih dari 318k kemunculan CWE dalam kategori risiko ini. 34 CWE yang dipetakan ke Broken Access Control memiliki lebih banyak kemunculan dalam aplikasi daripada kategori lainnya.
- **A02:2021-Cryptographic Failures** naik satu posisi menjadi #2, sebelumnya dikenal sebagai **A3:2017-Pengungkapan Data Sensitif**, yang merupakan gejala luas dan bukan akar masalah. Nama yang diperbarui di sini berfokus pada kegagalan yang terkait dengan kriptografi seperti yang sebelumnya tersirat. Kategori ini sering mengarah pada pengungkapan data sensitif atau sistem terkompromi.
- **A03:2021-Injection** turun ke posisi ketiga. 94% aplikasi diuji untuk beberapa bentuk injeksi dengan laju insidensi maks 19%, laju insidensi rata-rata 3,37%, dan 33 CWE yang dipetakan ke dalam kategori ini memiliki kejadian terbanyak kedua dalam aplikasi dengan 274k kemunculan. Cross-site Scripting sekarang menjadi bagian dari kategori ini dalam edisi ini. 
- **A04:2021-Insecure Design** adalah kategori baru untuk tahun 2021, dengan fokus pada risiko yang terkait dengan cacat desain. Jika kita ingin benar-benar "bergerak ke kiri" sebagai industri, itu membutuhkan lebih banyak pemodelan ancaman, prinsip dan pola desain yang aman, dan arsitektur referensi. Suatu desain yang tidak aman tidak bisa diperbaiki dengan suatu implementasi sempurna karena secara definisi, kendali keamanan yang diperlukan tidak pernah diciptakan untuk bertahan atas serangan spesifik.
- **A05:2021-Security Misconfiguration** naik dari #6 di edisi sebelumnya; 90% aplikasi diuji untuk beberapa bentuk kesalahan konfigurasi, dengan laju insidensi rata-rata 4,5%, dan lebih dari 208k kemunculan dari CWE yang dipetakan ke kategori risiko ini. Dengan lebih banyak pergeseran ke software yang sangat bisa dikonfigurasi, tidak mengherankan melihat kategori ini naik. Kategori sebelumnya untuk **A4:2017-XML External Entities (XXE)** sekarang menjadi bagian dari kategori risiko ini.
- **A06:2021-Vulnerable and Outdated Components** sebelumnya berjudul Using Components with Known Vulnerabilities dan #2 dalam survei komunitas, tapi juga memiliki cukup data untuk masuk TOP 10 melalui analisis data. Kategori ini naik dari #9 di tahun 2017 dan merupakan masalah yang telah dikenal, yang kami mengalami kesulitan untuk menguji dan menilai risikonya. Ini adalah satu-satunya kategori yang tidak memiliki CVE yang dipetakan ke CWE yang disertakan, jadi eksploitasi default dan bobot dampak 5.0 diperhitungkan dalam skornya.
- **A07:2021-Identification and Authentication Failures** sebelumnya dalah **A2:2017-Broken Authentication** dan turun dari posisi kedua, dan sekarang termasuk CWE yang lebih terkait dengan kegagalan identifikasi. Kategori ini masih merupakan bagian integral dari Top 10, tetapi peningkatan ketersediaan framework yang telah distandarisasi tampaknya membantu.
- **A08:2021-Software and Data Integrity Failures** adalah kategori baru untuk tahun 2021, yang berfokus pada pembuatan asumsi terkait pembaruan perangkat lunak, data penting, dan pipeline CI/CD tanpa memverifikasi integritas. Salah satu dampak tertinggi dari Common Vulnerability and Exposures/Common Vulnerability Scoring System (CVE/CVSS) yang dipetakan ke 10 CWE dalam kategori ini. **A8:2017-Insecure Deserialization** dari tahun 2017 sekarang menjadi bagian dari kategori yang lebih besar ini.
- **A09:2021-Security Logging and Monitoring Failures** sebelumnya **A10:2017-Logging dan Monitoring** dan ditambahkan dari survei komunitas Top 10 (#3), naik dari #10 sebelumnya. Kategori ini diperluas untuk mencakup lebih banyak jenis kegagalan, suatu tantangan untuk diiuji, dan tidak terwakili dengan baik dalam data CVE/CVSS. Namun, kegagalan dalam kategori ini dapat secara langsung mempengaruhi visibilitas, alert atas insiden, dan forensik.
- **A10:2021-Server-Side Request Forgery** ditambahkan dari survei komunitas Top 10 (#1). Data menunjukkan tingkat insiden yang relatif rendah dengan cakupan pengujian di atas rata-rata, bersama dengan peringkat di atas rata-rata untuk potensi Eksploitasi dan Dampak. Kategori ini mewakili skenario di mana para anggota komunitas keamanan memberi tahu kami bahwa ini penting, meskipun tidak diilustrasikan dalam data saat ini.

## Metodologi

Penyusunan dari Top 10 ini lebih didorong oleh data daripada sebelumnya tetapi tidak membabi-buta didorong data. Kami memilih delapan dari sepuluh kategori dari kontribusi data dan 2 kategori dari survei komunitas Top 10 pada tingkat tinggi. Kami melakukan ini karena alasan mendasar, melihat data yang telah dikumpulkan sama dengan melihat ke masa lalu. Peneliti AppSec membutuhkan waktu untuk menemukan kerentanan baru dan cara-cara baru untuk mengujinya. Dibutuhkan waktu untuk mengintegrasikan tes ini ke dalam alat dan proses. Pada saat kita dapat dengan andal menguji kelemahan dalam skala, mungkin beberapa tahun telah berlalu. Untuk menyeimbangkan pandangan itu, kami menggunakan survei komunitas untuk bertanya kepada para pakar pengembangan dan keamanan aplikasi di garis depan, apa yang mereka lihat sebagai kelemahan penting yang mungkin belum ditunjukkan oleh data.

Ada beberapa perubahan penting yang kami adopsi untuk terus mematangkan Top 10.

## Bagaimana kategori distrukturkan

Beberapa kategori telah berubah dari pemasangan OWASP Top 10 sebelumnya. Berikut adalah ringkasan tingkat tinggi dari perubahan kategori.

Upaya pengumpulan data sebelumnya difokuskan pada subset yang ditentukan dari sekitar 30 CWE dengan bidang yang meminta temuan tambahan. Kami mengetahui bahwa organisasi akan fokus hanya pada 30 CWE tersebut dan jarang menambahkan CWE lain yang mereka lihat. Dalam iterasi ini, kami membukanya dan hanya meminta data, tanpa batasan pada CWE. Kami meminta jumlah aplikasi yang diuji untuk tahun tertentu (mulai 2017), dan jumlah aplikasi dengan setidaknya satu contoh CWE yang ditemukan dalam pengujian. Format ini memungkinkan kami untuk melacak seberapa lazim setiap CWE dalam populasi aplikasi. Kami mengabaikan frekuensi untuk tujuan kami; sementara mungkin diperlukan untuk situasi lain, itu hanya menyembunyikan prevalensi aktual dalam populasi aplikasi. Apakah sebuah aplikasi memiliki empat instansi CWE atau 4.000 instansi bukanlah bagian dari perhitungan untuk Top 10. Kami berubah dari sekitar 30 CWE menjadi hampir 400 CWE untuk dianalisis dalam kumpulan data. Kami berrencana untuk melakukan analisis data tambahan sebagai suplemen di masa depan. Peningkatan jumlah CWE yang signifikan ini memerlukan perubahan pada bagaimana kategori distrukturkan.

Kami menghabiskan beberapa bulan untuk mengelompokkan dan mengkategorikan CWE dan dapat melanjutkannya selama beberapa bulan lagi. Kami harus berhenti di beberapa titik. Ada tipe CWE *akar masalah* dan *gejala*, di mana jenis *akar masalah* adalah seperti "Kegagalan Kriptografis" dan "Kesalahan Konfigurasi" dibandingkan dengan jenis *gejala* seperti "Pengungkapan Data Sensitif" dan "Penolakan Layanan." Kami memutuskan untuk fokus pada *akar masalah* bila memungkinkan karena lebih logis untuk memberikan panduan identifikasi dan perbaikan. Berfokus pada *akar masalah* di atas *gejala* bukanlah konsep baru; Top 10 telah menjadi campuran *gejala* dan *akar masalah*. CWE juga merupakan campuran dari *gejala* dan *akar masalah*; kami hanya menjadi lebih berhati-hati tentang hal itu dan menyebutnya. Ada rata-rata 19,6 CWE per kategori dalam pemasangan ini, dengan batas bawah pada 1 CWE untuk **A10:2021-Server-Side Request Forgery (SSRF)** hingga 40 CWE dalam **A04:2021-Insecure Design**. Struktur kategori yang diperbarui ini menawarkan manfaat pelatihan tambahan karena perusahaan dapat fokus pada CWE yang masuk akal untuk bahasa/kerangka kerja.    

## Bagaimana data digunakan untuk memilih kategori

Pada tahun 2017, kami memilih kategori berdasarkan tingkat insiden untuk menentukan kemungkinan, lalu memeringkatnya menurut diskusi tim berdasarkan pengalaman puluhan tahun untuk *Exploitability, Detectability* (juga *kemungkinan*), dan *Dampak Teknis*. Untuk tahun 2021, kami ingin menggunakan data untuk *Exploitability* and *Impact (Teknis)* jika memungkinkan.

Kami mengunduh Pemeriksaan Ketergantungan OWASP dan mengekstrak Eksploitasi CVSS, dan skor Dampak yang dikelompokkan berdasarkan CWE terkait. Butuh sedikit riset dan usaha karena semua CVE memiliki skor CVSSv2, tetapi ada kekurangan dalam CVSSv2 yang harus diatasi oleh CVSSv3. Setelah titik waktu tertentu, semua CVE juga diberi skor CVSSv3. Selain itu, rentang penilaian dan formula diperbarui antara CVSSv2 dan CVSSv3.

Di CVSSv2, *Eksploitasi* dan *Dampak (Teknis)* bisa mencapai 10,0, tetapi rumusnya akan menjatuhkannya hingga 60% untuk *Eksploitasi* dan 40% untuk *Dampak*. Di CVSSv3, maks secara teori dibatasi hingga 6,0 untuk *Eksploitasi* dan 4,0 untuk *Dampak*. Dengan mempertimbangkan pembobotan, skor Dampak bergeser lebih tinggi, rata-rata hampir satu setengah poin di CVSSv3, dan kemampuan eksploitasi turun rata-rata hampir setengah poin.

Ada 125 ribu catatan CVE yang dipetakan ke CWE dalam data NVD yang diekstraksi dari OWASP Dependency Check, dan ada 241 CWE unik yang dipetakan ke CVE. 62 ribu peta CWE memiliki skor CVSSv3, yang kira-kira setengah dari populasi dalam kumpulan data.

Untuk Top 10 2021, kami menghitung rata-rata skor *eksploitasi* dan *dampak* dengan cara berikut. Kami mengelompokkan semua CVE dengan skor CVSS berdasarkan CWE dan memberi bobot pada skor *eksploitasi* dan *dampak* berdasarkan persentase populasi yang memiliki skor CVSSv3 + populasi yang tersisa dari skor CVSSv2 untuk mendapatkan rata-rata keseluruhan. Kami memetakan rata-rata ini ke CWE dalam kumpulan data untuk digunakan sebagai skor *Eksploitasi* dan *Dampak (Teknis)* untuk separuh persamaan risiko lainnya.

## Kenapa tidak hanya data statistik murni?

Hasil dalam data utamanya terbatas pada apa yang dapat kami uji secara otomatis. Bicaralah dengan seorang Profesional AppSec yang berpengalaman, dan mereka akan memberi tahu Anda tentang hal-hal yang mereka temukan dan tren yang mereka lihat yang belum ada dalam data. Dibutuhkan waktu bagi orang untuk mengembangkan metodologi pengujian untuk jenis kerentanan tertentu dan kemudian lebih banyak waktu agar pengujian tersebut diotomatisasi dan dijalankan terhadap populasi aplikasi yang besar. Semua yang kami temukan adalah melihat kembali ke masa lalu dan mungkin kehilangan tren dari tahun lalu, yang tidak ada dalam data.

Oleh karena itu, kami hanya memilih delapan dari sepuluh kategori dari data karena tidak lengkap. Dua kategori lainnya berasal dari survei komunitas Top 10. Hal ini memungkinkan para praktisi di garis depan untuk memilih apa yang mereka lihat sebagai risiko tertinggi yang mungkin tidak ada dalam data (dan mungkin tidak akan pernah diungkapkan dalam data).

## Mengapa tingkatan insiden, bukan frekuensi?

Ada tiga sumber data utama. Kami mengidentifikasi mereka sebagai Human-assisted Tooling (HaT), Tool-assisted Human (TaH), dan raw Tooling.

Tooling dan HaT adalah generator pencarian frekuensi tinggi. Alat akan mencari kerentanan tertentu dan tanpa lelah berusaha untuk menemukan setiap contoh kerentanan itu dan akan menghasilkan jumlah temuan yang tinggi untuk beberapa jenis kerentanan. Lihatlah Cross-Site Scripting, yang biasanya merupakan salah satu dari dua rasa: itu kesalahan kecil yang terisolasi atau masalah sistemik. Jika ini merupakan masalah sistemik, jumlah temuan bisa mencapai ribuan untuk sebuah aplikasi. Frekuensi tinggi ini menenggelamkan sebagian besar kerentanan lain yang ditemukan dalam laporan atau data.

TaH, di sisi lain, akan menemukan jenis kerentanan yang lebih luas tetapi pada frekuensi yang jauh lebih rendah karena kendala waktu. Ketika manusia menguji aplikasi dan melihat sesuatu seperti Cross-Site Scripting, mereka biasanya akan menemukan tiga atau empat instansi dan berhenti. Mereka dapat menentukan temuan sistemik dan menuliskannya dengan rekomendasi untuk diperbaiki pada skala seluruh aplikasi. Tidak ada kebutuhan (atau waktu) untuk menemukan setiap instansi.

Misalkan kita mengambil dua kumpulan data yang berbeda ini dan mencoba menggabungkannya pada frekuensi. Dalam hal ini, data Tooling dan HaT akan menenggelamkan data TaH yang lebih akurat (tetapi luas) dan merupakan bagian yang baik dari mengapa sesuatu seperti Cross-Site Scripting memiliki peringkat yang sangat tinggi di banyak daftar ketika dampaknya umumnya rendah hingga sedang. Itu karena demikian banyaknya temuan. (Cross-Site Scripting juga cukup mudah untuk diuji, jadi ada lebih banyak tes untuk itu juga).

Pada tahun 2017, kami memperkenalkan penggunaan tingkat insiden sebagai gantinya untuk melihat data baru dan menggabungkan data Tooling dan HaT dengan data TaH secara bersih. Tingkat insiden menanyakan berapa persentase populasi aplikasi yang memiliki setidaknya satu instansi jenis kerentanan. Kami tidak peduli apakah itu satu kali atau sistemik. Itu tidak relevan untuk tujuan kita; kita hanya perlu mengetahui berapa banyak aplikasi yang memiliki setidaknya satu instansi, yang membantu memberikan pandangan yang lebih jelas tentang pengujian temuan di beberapa jenis pengujian tanpa menenggelamkan data dalam hasil frekuensi tinggi. Ini sesuai dengan pandangan terkait risiko karena penyerang hanya membutuhkan satu instansi untuk menyerang aplikasi dengan sukses melalui kategori.

## Apa proses pengumpulan dan analisis data Anda?

Kami meresmikan proses pengumpulan data OWASP Top 10 di Open Security Summit pada 2017. Para leader OWASP Top 10 dan komunitas telah menghabiskan dua hari untuk memformalkan proses pengumpulan data yang transparan. Edisi 2021 adalah kedua kalinya kami menggunakan metodologi ini.

Kami mempublikasikan panggilan untuk data melalui saluran media sosial yang tersedia untuk kami, baik projek maupun OWASP. Pada halaman Projek OWASP, kami mencantumkan elemen dan struktur data yang kami cari dan cara mengirimkannya. Dalam proyek GitHub, kami memiliki file contoh yang berfungsi sebagai template. Kami bekerja dengan organisasi yang diperlukan untuk membantu mengetahui struktur dan pemetaan ke CWE.

Kami mendapatkan data dari organisasi vendor pengujian, vendor bug bounty, dan organisasi yang menyumbangkan data pengujian internal. Setelah kami memiliki data, kami memuatnya bersama dan menjalankan analisis fundamental tentang apa yang dipetakan CWE ke kategori risiko. Ada tumpang tindih antara beberapa CWE, dan yang lainnya sangat erat kaitannya (mis. Kerentanan kriptografis). Setiap keputusan yang terkait dengan data mentah yang dikirimkan didokumentasikan dan dipublikasikan agar terbuka dan transparan dengan cara kami menormalkan data.

Kami melihat delapan kategori dengan tingkat insiden tertinggi untuk dimasukkan dalam Top 10. Kami juga melihat hasil survei komunitas Top 10 untuk melihat mana yang mungkin sudah ada dalam data. Dua suara teratas yang belum ada dalam data akan dipilih untuk dua tempat lainnya di Top 10. Setelah sepuluh dipilih, kami menerapkan faktor umum untuk eksploitabilitas dan dampak; untuk membantu menentukan peringkat Top 10 2021 dalam urutan berbasis risiko.

## Faktor-faktor Data

Ada data faktor yang dicantumkan untuk masing-masing dari 10 Kategori Teratas, berikut artinya:

- CWE Dipetakan: Jumlah CWE yang dipetakan ke kategori oleh tim Top 10.
- Laju Insidensi: Tingkat insiden adalah persentase aplikasi yang rentan terhadap CWE tersebut dari populasi yang diuji oleh organisasi tersebut untuk tahun tersebut.
- Cakupan (Pengujian): Persentase aplikasi yang diuji oleh semua organisasi untuk CWE tertentu.
- Ekslpoitasi Terbobot: Sub-skor Eksploitasi dari skor CVSSv2 dan CVSSv3 yang ditetapkan ke CVE yang dipetakan ke CWE, dinormalisasi, dan ditempatkan pada skala 10.
- Dampak Terbobot: Sub-skor Dampak dari skor CVSSv2 dan CVSSv3 yang ditetapkan ke CVE dipetakan ke CWE, dinormalisasi, dan ditempatkan pada skala 10.
- Total Kejadian: Jumlah total aplikasi yang ditemukan memiliki CWE yang dipetakan ke suatu kategori.
- Total CVE: Jumlah total CVE dalam NVD DB yang dipetakan ke CWE yang dipetakan ke suatu kategori.

## Terima kasih kepada kontributor data kami

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

## Terima kasih kepada sponsor kami

Tim OWASP Top 10 2021 berterimakasih atas dukungan finansial dari Secure Code Warrior dan Just Eat.

[![Secure Code Warrior](assets/securecodewarrior.png){ width="256" }](https://securecodewarrior.com)

[![Just Eat](assets/JustEat.png){ width="256" }](https://www.just-eat.co.uk)
