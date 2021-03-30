# A10:2017 Insufficient Logging and Monitoring

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl : Exploitability 2 | Prevalence 3 : Detectability 1 | Technical 2 : Business |
| Exploitation of insufficient logging and monitoring is the bedrock of nearly every major incident. Attackers rely on the lack of monitoring and timely response to achieve their goals without being detected. | This issue is included in the Top 10 based on an [industry survey](https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html). One strategy for determining if you have sufficient monitoring is to examine the logs following penetration testing. The testers' actions should be recorded sufficiently to understand what damages they may have inflicted. | Most successful attacks start with vulnerability probing. Allowing such probes to continue can raise the likelihood of successful exploit to nearly 100%. In 2016, identifying a breach took an [average of 191 days](https://www-01.ibm.com/common/ssi/cgi-bin/ssialias?htmlfid=SEL03130WWEN&) – plenty of time for damage to be inflicted. |

## Is the Application Vulnerable?

Insufficient logging, detection, monitoring and active response occurs any time:

* Auditable events, such as logins, failed logins, and high-value transactions are not logged.
* Warnings and errors generate no, inadequate, or unclear log messages.
* Logs of applications and APIs are not monitored for suspicious activity.
* Logs are only stored locally.
* Appropriate alerting thresholds and response escalation processes are not in place or effective.
* Penetration testing and scans by [DAST](https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools) tools (such as [OWASP ZAP](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project)) do not trigger alerts.
* The application is unable to detect, escalate, or alert for active attacks in real time or near real time.

You are vulnerable to information leakage if you make logging and alerting events visible to a user or an attacker (see A3:2017-Sensitive Information Exposure).

## Bagaimana Cara Mencegah?

Pada setiap resiko dari data yang disetorkan atau diproses oleh aplikasi :

* Pastikan semua login, kegagalan kontrol akses, dan kegagalan validasi input dari sisi server dapat dapat dimasukkan dengan konteks yang cukup dari user untuk mengidentifikasi akun mencurigakan atau berbahaya, dan ditahan untuk waktu yang cukup untuk mengizinkan analisa forensik yang tertunda.
* Pastikan bahwa log dibuat dalam format yang dapat dengan mudah digunakan oleh solusi log manajemen utama.
* Pastikan transaksi bernilai tinggi memiliki jejak audit dengan kontrol integritas untuk mencegah kerusakan atau terhapus, seperti tabel database yang hanya bisa menambahkan data atau semacamnya.
* Buat monitoring dan peringatan yang efektif agar aktivitas mencurigakan dapat terdeteksi dan direspon secara tepat waktu.
* Buat atau adopsi sebuah respon kejadian dan rencana pemulihan, seperti [NIST 800-61 rev 2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) atau nanti.

Tersedia aplikasi framework proteksi baik komersial maupun opensource seperti [OWASP AppSensor](https://www.owasp.org/index.php/OWASP_AppSensor_Project), aplikasi web firewalls seperti [ModSecurity with the OWASP ModSecurity Core Rule Set](https://www.owasp.org/index.php/Category:OWASP_ModSecurity_Core_Rule_Set_Project), dan perangkat lunak korelasi log dengan dasboard dan peringatan yang bisa dibuat sesuai keinginan. 

## Example Attack Scenarios

**Scenario #1**: An open source project forum software run by a small team was hacked using a flaw in its software. The attackers managed to wipe out the internal source code repository containing the next version, and all of the forum contents. Although source could be recovered, the lack of monitoring, logging or alerting led to a far worse breach. The forum software project is no longer active as a result of this issue.

**Scenario #2**: An attacker uses scans for users using a common password. They can take over all accounts using this password. For all other users, this scan leaves only one false login behind. After some days, this may be repeated with a different password.

**Scenario #3**: A major US retailer reportedly had an internal malware analysis sandbox analyzing attachments. The sandbox software had detected potentially unwanted software, but no one responded to this detection. The sandbox had been producing warnings for some time before the breach was detected due to fraudulent card transactions by an external bank.

## References

### OWASP

* [OWASP Proactive Controls: Implement Logging and Intrusion Detection](https://www.owasp.org/index.php/OWASP_Proactive_Controls#8:_Implement_Logging_and_Intrusion_Detection)
* [OWASP Application Security Verification Standard: V8 Logging and Monitoring](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide: Testing for Detailed Error Code](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Cheat Sheet: Logging](https://www.owasp.org/index.php/Logging_Cheat_Sheet)

### External

* [CWE-223: Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)
* [CWE-778: Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
