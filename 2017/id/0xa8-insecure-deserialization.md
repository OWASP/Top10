# A8:2017 Deserialisasi yang Tidak Aman

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Akses Lvl: Eksploitasi 1 | Prevalensi 2 : Deteksi 2 | Teknis 3: Bisnis |
| Penyerang dapat mengeksploitasi prosesor XML yang rentan jika mereka dapat mengunggah XML atau menyertakan konten yang tidak bersahabat dalam dokumen XML, mengeksploitasi kode yang rentan, ketergantungan, atau integrasi. | Masalah ini termasuk dalam Top 10 berdasarkan [Survei Industri ](https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html) dan bukan pada data yang dapat dihitung. Beberapa alat dapat menemukan kekurangan deserialisasi, tetapi bantuan manusia sering kali diperlukan untuk memvalidasi masalah. Diharapkan bahwa data prevalensi untuk kekurangan deserialisasi akan meningkat seiring dengan pengembangan perangkat untuk membantu mengidentifikasi dan mengatasinya. | Dampak kelemahan deserialisasi tidak bisa dilebih-lebihkan. Cacat ini dapat menyebabkan serangan eksekusi kode jarak jauh, salah satu serangan paling serius yang mungkin terjadi. Dampak bisnis bergantung pada kebutuhan perlindungan aplikasi dan data.|

## Apakah Aplikasi itu Rentan?

Aplikasi dan API akan menjadi rentan jika mereka menghilangkan identitas objek yang dimusuhi atau dirusak yang disediakan oleh penyerang.

Ini dapat mengakibatkan dua jenis serangan utama:

* Serangan terkait objek dan struktur data di mana penyerang mengubah logika aplikasi atau mencapai eksekusi kode jarak jauh arbitrer jika ada kelas yang tersedia untuk aplikasi yang dapat mengubah perilaku selama atau setelah deserialisasi.
* Serangan perusakan data tipikal seperti serangan terkait kontrol akses di mana struktur data yang ada digunakan tetapi kontennya diubah.

Serialisasi dapat digunakan dalam aplikasi untuk:

* _Remote_ dan komunikasi antar proses (RPC/IPC) 
* Protokol kawat, layanan web, perantara pesan
* Caching / Persistensi
* Database, server cache, sistem file
* Cookie pada HTTP, HTML form parameter, otentikasi token pada API

## Bagaimana Cara Pencegahannya

Satu-satunya pola arsitektur yang aman adalah tidak menerima objek serialisasi dari sumber yang tidak terpercaya atau menggunakan media serialisasi yang hanya mengizinkan tipe data primitif.

Jika memungkinkan, pertimbangkan salah satu cara pencegahan dibawah ini :

* Menerapkan pemeriksaan integritas seperti tanda tangan digital pada objek serial apa pun untuk mencegah pembuatan objek yang tidak terpecaya  atau gangguan data. 
* Menerapkan batasan tipe yang ketat selama desentralisasi sebelum pembuatan objek karena kode biasanya mengharapkan sekumpulan kelas yang dapat ditentukan. Pengabaian  
  terhadap teknik ini telah dibuktikan, jadi tidak disarankan untuk mengandalkan hanya pada teknik ini.
* Mengisolasi dan menjalankan kode yang deserialisasi dengan hak Environment lebih rendah jika memungkinkan
* Pengecualian dan kegagalan deserialisasi log, seperti saat jenis yang masuk bukan jenis yang diharapkan, atau deserialisasi melontarkan pengecualian.
* Membatasi atau memantau konektivitas jaringan masuk dan keluar dari kontainer atau server yang deserialisasi
* Monitoring deserialisasi, memberikan _alert_ jika ada _user_ terus menerus melakukan deserialisasi.


## Contoh Skenario Serangan

**Scenario #1**: Aplikasi React memanggil satu set layanan mikro Spring Boot. Sebagai programmer fungsional, mereka mencoba memastikan bahwa kode mereka tidak dapat diubah. Solusi yang mereka hasilkan adalah membuat serial status pengguna dan meneruskannya bolak-balik dengan setiap permintaan. Seorang penyerang memperhatikan tanda tangan objek Java "R00", dan menggunakan alat Pembunuh Serial Java untuk mendapatkan eksekusi kode jarak jauh pada server aplikasi.
**Scenario #2**: Sebuah kode PHP menggunakan serialisasi objek PHP untuk menyimpan sebuah "super" cookie, berisi user's user ID, role, password hash, dan bagian yang lain:

`a:4:{i:0;i:132;i:1;s:7:"Mallory";i:2;s:4:"user";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}`

Seorang Penyerang mengubah object serialisasi untuk mengubah aksesnya menjadi hak akses admin:
`a:4:{i:0;i:1;i:1;s:5:"Alice";i:2;s:5:"admin";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}`

## Referensi

### OWASP

* [OWASP Cheat Sheet: Deserialization](https://www.owasp.org/index.php/Deserialization_Cheat_Sheet)
* [OWASP Proactive Controls: Validate All Inputs](https://www.owasp.org/index.php/OWASP_Proactive_Controls#4:_Validate_All_Inputs)
* [OWASP Application Security Verification Standard: TBA](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP AppSecEU 2016: Surviving the Java Deserialization Apocalypse](https://speakerdeck.com/pwntester/surviving-the-java-deserialization-apocalypse)
* [OWASP AppSecUSA 2017: Friday the 13th JSON Attacks](https://speakerdeck.com/pwntester/friday-the-13th-json-attacks)

### External

* [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
* [Java Unmarshaller Security](https://github.com/mbechler/marshalsec)
* [OWASP AppSec Cali 2015: Marshalling Pickles](http://frohoff.github.io/appseccali-marshalling-pickles/)
