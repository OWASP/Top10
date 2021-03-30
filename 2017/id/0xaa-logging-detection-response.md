# A10:2017 Insufficient Logging and Monitoring

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl : Exploitability 2 | Prevalence 3 : Detectability 2 | Technical 2 : Business |
| Exploitation of insufficient logging and monitoring is the bedrock of nearly every major incident. Attackers rely on the lack of monitoring and timely response to achieve their goals without being detected. | This issue is included in the Top 10 based on an [industry survey](https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html). One strategy for determining if you have sufficient monitoring is to examine the logs following penetration testing. The testers' actions should be recorded sufficiently to understand what damages they may have inflicted. | Most successful attacks start with vulnerability probing. Allowing such probes to continue can raise the likelihood of successful exploit to nearly 100%. In 2016, identifying a breach took an [average of 191 days](https://www-01.ibm.com/common/ssi/cgi-bin/ssialias?htmlfid=SEL03130WWEN&) – plenty of time for damage to be inflicted. |

## Apakah Aplikasi Rentan ?

Tidak cukupnya logging, deteksi, monitoring dan respon aktif akan terjadi jika :

- Segala proses yang memerlukan pemeriksaan / audit, seperti login, login yang gagal, dan transaksi yang bernilai tinggi tidak dimasukkan ke log.
- Peringatan dan error menampilkan message no, inadequate, atau unclear log.
- Tidak memonitor aktivitas mencurigakan pada log aplikasi dan APIs.
- Log hanya disimpan secara local.
- Tidak bekerjanya atau kurang efektifnya alerting thresholds dan response escalation processes.
- Testing Pembobolan (Penetration Testing) dan scan dengan menggunakan [DAST](https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools) tools (seperti [OWASP ZAP](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)) tidak menimbulkan sebuah peringatan.
- Aplikasi tidak dapat mendeteksi atau memberitahu serangan aktif secara real time atau mendekati real time.

Anda akan rentan terhadap bocornya informasi jika event logging dan pemberitahuan (alerting) dapat dilihat oleh seorang user atau attacker (dapat dilihat : A3:2017-Sensitive Information Exposure).

## How To Prevent

As per the risk of the data stored or processed by the application:

- Ensure all login, access control failures, and server-side input validation failures can be logged with sufficient user context to identify suspicious or malicious accounts, and held for sufficient time to allow delayed forensic analysis.
- Ensure that logs are generated in a format that can be easily consumed by a centralized log management solutions.
- Ensure high-value transactions have an audit trail with integrity controls to prevent tampering or deletion, such as append-only database tables or similar.
- Establish effective monitoring and alerting such that suspicious activities are detected and responded to in a timely fashion.
- Establish or adopt an incident response and recovery plan, such as [NIST 800-61 rev 2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) or later.

There are commercial and open source application protection frameworks such as [OWASP AppSensor](https://www.owasp.org/index.php/OWASP_AppSensor_Project), web application firewalls such as [ModSecurity with the OWASP ModSecurity Core Rule Set](https://www.owasp.org/index.php/Category:OWASP_ModSecurity_Core_Rule_Set_Project), and log correlation software with custom dashboards and alerting.

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
