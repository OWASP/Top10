# A10:2017 Insufficient Logging and Monitoring

| Ancaman/Vektor Serangan | Kelemahan Keamanan           | Dampak               |
| -- | -- | -- |
| Lvl Akses : Dapat Dieksploitasi 2 | Prevalence 3 : Detectability 1 | Technical 2 : Business |
| Eksploitasi logging dan pemantauan/monitoring yang tidak memadai adalah awal/fondasi dari hampir setiap insiden besar. Penyerang bergantung pada kurangnya pemantauan/monitoring dan respon yang tepat waktu untuk mencapai tujuan mereka tanpa terdeteksi. | Issue tersebut termasuk dalam top 10 berdasarkan [industry survey](https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html). Salah satu strategi untuk menentukan apakah Anda memiliki pemantauan(monitoring) yang memadai adalah dengan memeriksa log setelah pengujian penetrasi(penetration testing). Tindakan tester/penguji harus direkam secukupnya untuk memahami kerusakan apa yang mungkin mereka timbulkan | Serangan yang paling sukses dimulai dengan pemeriksaan kerentanan. Membiarkan probe/pemeriksaan seperti itu terus-menerus dapat meningkatkan kemungkinan eksploitasi yang berhasil hingga hampir 100%. Pada tahun 2016, mengidentifikasi pelanggaran membutuhkan [rata-rata 191 hari](https://www-01.ibm.com/common/ssi/cgi-bin/ssialias?htmlfid=SEL03130WWEN&) – banyak waktu untuk menimbulkan kerusakan. |

## Apakah Aplikasi Tersebut Rentan?

Pencatatan(logging), deteksi, pemantauan(monitoring), dan respons aktif yang tidak memadai terjadi saat:

* Kejadian yang dapat diaudit, seperti login, kegagalan login, dan transaksi bernilai tinggi tidak dicatat.
* Pesan Log untuk peringatan dan kesalahan tidak ada, tidak memadai, atau tidak jelas.
* Logs hanya disimpan secara local.
* Ambang peringatan yang tepat dan proses eskalasi respons tidak tersedia atau efektif. Appropriate alerting thresholds and response escalation processes are not in place or effective.
* Penetrasi Testing dan scan dengan [DAST](https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools) tools (seperti [OWASP ZAP](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)) tidak memacu peringatan.
* Aplikasi tidak dapat mendeteksi, meningkatkan, atau memperingatkan serangan aktif dalam waktu real-time atau mendekati real-time.

Anda rentan terhadap kebocoran informasi jika Anda membuat pencatatan log dan peringatan event terlihat oleh pengguna atau penyerang (lihat A3: Keterpaparan Informasi Sensitif 2017).

## Bagaimana Mencegahnya

Sesuai dengan risiko data yang disimpan atau diproses oleh aplikasi:

* Pastikan semua login, kegagalan kontrol akses, dan kegagalan validasi input pada sisi server dapat dicatat dengan konteks pengguna yang memadai untuk mengidentifikasi akun yang mencurigakan atau berbahaya, dan ditahan untuk waktu yang cukup untuk memungkinkan analisis forensik yang tertunda.
* Pastikan bahwa log dibuat dalam format yang dapat dengan mudah digunakan oleh centralized log management solutions.
* Pastikan transaksi bernilai tinggi memiliki jejak audit dengan kontrol integritas untuk mencegah gangguan atau penghapusan, seperti append-only tabel database atau yang serupa. E
* Buat pemantauan dan peringatan yang efektif sehingga aktivitas mencurigakan terdeteksi dan ditanggapi secara tepat waktu. Establish effective monitoring and alerting such that suspicious activities are detected and responded to in a timely fashion.
* Menetapkan atau mengadopsi respons insiden dan rencana pemulihan, seperti [NIST 800-61 rev 2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) atau yang lebih baru.

Terdapat komersial dan aplikasi open source proteksi framework seperti [OWASP AppSensor](https://www.owasp.org/index.php/OWASP_AppSensor_Project), web aplikasi firewall seperti [ModSecurity with the OWASP ModSecurity Core Rule Set](https://www.owasp.org/index.php/Category:OWASP_ModSecurity_Core_Rule_Set_Project), dan perangkat lunak korelasi log dengan kostum dashboard dan peringatan. 

## Contoh Skenario Serangan

**Skenario #1**: Sebuah forum proyek Open Source Perangkat lunak yang dijalankan oleh tim kecil diretas menggunakan kecacatan pada perangkat lunaknya. Para penyerang berhasil menghapus repositori kode sumber internal yang berisi versi berikutnya, dan semua konten forum. Meskipun sumber dapat dipulihkan, kurangnya pemantauan, penebangan, atau peringatan menyebabkan pelanggaran yang jauh lebih buruk.Forum proyek perangkat lunak tidak lagi aktif karena masalah ini.

**Skenario #2**: Penyerang menggunakan pemindaian untuk pengguna menggunakan sandi umum. Mereka dapat mengambil alih semua akun menggunakan kata sandi ini. Untuk semua pengguna lain, pemindaian ini hanya menyisakan satu login palsu. Setelah beberapa hari, ini mungkin akan diulangi dengan sandi yang berbeda.

**Skenario #3**: Sebuah pengecer besar AS dilaporkan memiliki analisis malware internal Sandbox menganalisis lampiran. Perangkat lunak Sandbox telah mendeteksi perangkat lunak yang mungkin tidak diinginkan, tetapi tidak ada yang menanggapi deteksi ini. Sandbox telah mengeluarkan peringatan untuk beberapa waktu sebelum pelanggaran terdeteksi karena transaksi kartu yang curang oleh bank eksternal.


## Referensi

### OWASP

- [OWASP Proactive Controls: Implement Logging and Intrusion Detection](https://www.owasp.org/index.php/OWASP_Proactive_Controls#8:_Implement_Logging_and_Intrusion_Detection)
- [OWASP Application Security Verification Standard: V8 Logging and Monitoring](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
- [OWASP Testing Guide: Testing for Detailed Error Code](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
- [OWASP Cheat Sheet: Logging](https://www.owasp.org/index.php/Logging_Cheat_Sheet)

### External

- [CWE-223: Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)
- [CWE-778: Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
