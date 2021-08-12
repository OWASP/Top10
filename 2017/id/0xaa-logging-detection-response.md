# A10:2017 Kurangnya dalam Melakukan Logging dan Monitoring

| Ancaman/Vektor Serangan | Kelemahan Keamanan           | Dampak               |
| -- | -- | -- |
| Lvl Akses : Dapat Dieksploitasi 2 | Prevalence 3 : Detectability 1 | Technical 2 : Business |
| Eksploitasi logging dan pemantauan/monitoring yang tidak memadai adalah awal/fondasi dari hampir setiap insiden besar. Penyerang bergantung pada kurangnya pemantauan/monitoring dan respon yang tepat waktu untuk mencapai tujuan mereka tanpa terdeteksi. | Issue tersebut termasuk dalam top 10 berdasarkan [industry survey](https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html). Salah satu strategi untuk menentukan apakah Anda memiliki pemantauan(monitoring) yang memadai adalah dengan memeriksa log setelah pengujian penetrasi(penetration testing). Tindakan tester/penguji harus direkam secukupnya untuk memahami kerusakan apa yang mungkin mereka timbulkan | Serangan yang paling sukses dimulai dengan pemeriksaan kerentanan. Membiarkan probe/pemeriksaan seperti itu terus-menerus dapat meningkatkan kemungkinan eksploitasi yang berhasil hingga hampir 100%. Pada tahun 2016, mengidentifikasi pelanggaran membutuhkan rata-rata 191 hari – banyak waktu untuk menimbulkan kerusakan. |

## Apakah Aplikasi Tersebut Rentan?

Pencatatan(logging), deteksi, pemantauan(monitoring), dan respons aktif yang tidak memadai terjadi saat:

* Kejadian yang dapat diaudit, seperti login, kegagalan login, dan transaksi bernilai tinggi tidak dicatat.
* Pesan Log untuk peringatan dan kesalahan tidak ada, tidak memadai, atau tidak jelas.
* Logs hanya disimpan secara local.
* Ambang peringatan yang tepat dan proses eskalasi respons tidak tersedia atau efektif. Appropriate alerting thresholds and response escalation processes are not in place or effective.
* Penetrasi Testing dan scan dengan [DAST](https://owasp.org/www-community/Vulnerability_Scanning_Tools) tools (seperti [OWASP ZAP](https://owasp.org/www-project-zap/)) tidak memacu peringatan.
* Aplikasi tidak dapat mendeteksi, meningkatkan, atau memperingatkan serangan aktif dalam waktu real-time atau mendekati real-time.

Anda rentan terhadap kebocoran informasi jika Anda membuat pencatatan log dan peringatan event terlihat oleh pengguna atau penyerang (lihat A3: Keterpaparan Informasi Sensitif 2017).

## Bagaimana Cara Mencegah?

Pada setiap resiko dari data yang disetorkan atau diproses oleh aplikasi :

* Pastikan semua login, kegagalan kontrol akses, dan kegagalan validasi input dari sisi server dapat dapat dimasukkan dengan konteks yang cukup dari user untuk mengidentifikasi akun mencurigakan atau berbahaya, dan ditahan untuk waktu yang cukup untuk mengizinkan analisa forensik yang tertunda.
* Pastikan bahwa log dibuat dalam format yang dapat dengan mudah digunakan oleh solusi log manajemen utama.
* Pastikan transaksi bernilai tinggi memiliki jejak audit dengan kontrol integritas untuk mencegah kerusakan atau terhapus, seperti tabel database yang hanya bisa menambahkan data atau semacamnya.
* Buat monitoring dan peringatan yang efektif agar aktivitas mencurigakan dapat terdeteksi dan direspon secara tepat waktu.
* Buat atau adopsi sebuah respon kejadian dan rencana pemulihan, seperti [NIST 800-61 rev 2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) atau nanti.

Tersedia aplikasi framework proteksi baik komersial maupun opensource seperti [OWASP AppSensor](https://owasp.org/www-project-appsensor/), aplikasi web firewalls seperti [OWASP ModSecurity Core Rule Set](https://owasp.org/www-project-modsecurity-core-rule-set/), dan perangkat lunak korelasi log dengan dasboard dan peringatan yang bisa dibuat sesuai keinginan. 

## Contoh Skenario Serangan

**Skenario #1**: Sebuah forum proyek Open Source Perangkat lunak yang dijalankan oleh tim kecil diretas menggunakan kecacatan pada perangkat lunaknya. Para penyerang berhasil menghapus repositori kode sumber internal yang berisi versi berikutnya, dan semua konten forum. Meskipun sumber dapat dipulihkan, kurangnya pemantauan, penebangan, atau peringatan menyebabkan pelanggaran yang jauh lebih buruk.Forum proyek perangkat lunak tidak lagi aktif karena masalah ini.

**Skenario #2**: Penyerang menggunakan pemindaian untuk pengguna menggunakan sandi umum. Mereka dapat mengambil alih semua akun menggunakan kata sandi ini. Untuk semua pengguna lain, pemindaian ini hanya menyisakan satu login palsu. Setelah beberapa hari, ini mungkin akan diulangi dengan sandi yang berbeda.

**Skenario #3**: Sebuah pengecer besar AS dilaporkan memiliki analisis malware internal Sandbox menganalisis lampiran. Perangkat lunak Sandbox telah mendeteksi perangkat lunak yang mungkin tidak diinginkan, tetapi tidak ada yang menanggapi deteksi ini. Sandbox telah mengeluarkan peringatan untuk beberapa waktu sebelum pelanggaran terdeteksi karena transaksi kartu yang curang oleh bank eksternal.

## Referensi

### OWASP

- [OWASP Proactive Controls: Implement Logging and Intrusion Detection](https://owasp.org/www-project-proactive-controls/v3/en/c9-security-logging)
- [OWASP Application Security Verification Standard: V8 Logging and Monitoring](https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x11-V2-Authentication.md)
- [OWASP Testing Guide: Testing for Detailed Error Code](https://github.com/OWASP/ASVS/blob/v4.0.2/4.0/en/0x11-V2-Authentication.md)
- [OWASP Cheat Sheet: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

### Eksternal

- [CWE-223: Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)
- [CWE-778: Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)

