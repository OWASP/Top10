# A9:2017 Menggunakan Komponen yang Diketahui Rentan

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Access Lvl : Exploitability 2 | Prevalence 3 : Detectability 2 | Technical 2 : Business |
| Meskipun mudah untuk menemukan eksploitasi yang telah tercatat dalam banyak kasus kerentanan yang telah diketahui, kerentanan lain yang belum diketahui membutuhkan usaha yang lebih dalam mengembangkan sebuah Custom Exploit. | Tingkat kelaziman mengenai permasalahan ini sangat luas. Komponen yang sulit dalam pola pengembangan dapat menyebabkan tim pengembangan bahkan kurang mengerti mengenai komponen yang mereka gunakan dalam aplikasi mereka atau pada API, apalagi menjaganya agar tetap mutakhir. beberapa sistem pemindai seperti retire.js dapat membantu dalam pendeteksian, tetapi dalam mengetahui exploitability membutuhkan upaya tambahan | sementara itu, dalam beberapa kasus kerentanan yang diketahui hanya menyebabkan dampak kecil, beberapa pelanggaran terbesar hingga saat ini mengandalkan pengeksploitasian kerentanan yang ada dalam komponen, bergantung dalam aset yang anda sedang lindungi, kemungkinan resiko seperti ini harus berada pada urutan teratas dalam daftar kerentanan |

## Is the Application Vulnerable?

You are likely vulnerable:

* If you do not know the versions of all components you use (both client-side and server-side). This includes components you directly use as well as nested dependencies.
* If software is vulnerable, unsupported, or out of date. This includes the OS, web/application server, database management system (DBMS), applications, APIs and all components, runtime environments, and libraries.
* If you do not scan for vulnerabilities regularly and subscribe to security bulletins related to the components you use.
* If you do not fix or upgrade the underlying platform, frameworks, and dependencies in a risk-based, timely fashion. This commonly happens in environments when patching is a monthly or quarterly task under change control, which leaves organizations open to many days or months of unnecessary exposure to fixed vulnerabilities.
* If software developers do not test the compatibility of updated, upgraded, or patched libraries.
* If you do not secure the components' configurations (see **A6:2017-Security Misconfiguration**).

## Cara Untuk Mencegah

Seharusnya ada proses manajemen patch untuk:

* Menghapus dependensi yang tidak digunakan, fitur, komponen, file, dan dokumentasi yang tidak perlu.
* Secara terus menerus meninventarisasi versi komponen dari sisi klien dan sisi server (contoh: framework, library) dan dependensi mereka menggunakan alat seperti versions, DependencyCheck, retire.js, dll. 
* Secara terus menerus memonitor sumber seperti CVE dan NVD untuk menemukan kerentanan dalam komponen. Gunakan software composition analysis tools untuk mengotomatiskan proses. Berlangganan pada email peringatan untuk kerentanan keamanan yang berkaitan dengan komponen yang anda gunakan.
* Hanya dapatkan komponen dari sumber resmi dari tautan aman. Utamakan signed packages untuk mengurangi kemungkinan menyertakan komponen yang dimodifikasi dan berbahaya.
* Monitor library dan komponen yang tidak dikelola atau tidak membuat patch keamanan untuk versi lama. Jika patching tidak memungkinkan, pertimbangkan deploying patch virtual untuk memonitor, mendeteksi, atau melindungi dari masalah yang ditemukan.

Setiap organisasi harus memastikan bahwa ada rencana berkelanjutan untuk memonitoring, triaging, dan menerapkan update atau perubahan konfigurasi selama masa pakai aplikasi atau portfolio.

## Example Attack Scenarios

**Scenario #1**: Components typically run with the same privileges as the application itself, so flaws in any component can result in serious impact. Such flaws can be accidental (e.g. coding error) or intentional (e.g. backdoor in component). Some example exploitable component vulnerabilities discovered are:

* [CVE-2017-5638](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638), a Struts 2 remote code execution vulnerability that enables execution of arbitrary code on the server, has been blamed for significant breaches.
* While [internet of things (IoT)](https://en.wikipedia.org/wiki/Internet_of_things) are frequently difficult or impossible to patch, the importance of patching them can be great (e.g. biomedical devices).

There are automated tools to help attackers find unpatched or misconfigured systems. For example, the [Shodan IoT search engine](https://www.shodan.io/report/89bnfUyJ) can help you find devices that still suffer from [Heartbleed](https://en.wikipedia.org/wiki/Heartbleed) vulnerability that was patched in April 2014.

## References

### OWASP

* [OWASP Application Security Verification Standard: V1 Architecture, design and threat modelling](https://www.owasp.org/index.php/ASVS_V1_Architecture)
* [OWASP Dependency Check (for Java and .NET libraries)](https://www.owasp.org/index.php/OWASP_Dependency_Check)
* [OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)](https://www.owasp.org/index.php/Map_Application_Architecture_(OTG-INFO-010))
* [OWASP Virtual Patching Best Practices](https://www.owasp.org/index.php/Virtual_Patching_Best_Practices)

### External

* [The Unfortunate Reality of Insecure Libraries](https://www.aspectsecurity.com/research-presentations/the-unfortunate-reality-of-insecure-libraries)
* [MITRE Common Vulnerabilities and Exposures (CVE) search](https://www.cvedetails.com/version-search.php)
* [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
* [Retire.js for detecting known vulnerable JavaScript libraries](https://github.com/retirejs/retire.js/)
* [Node Libraries Security Advisories](https://nodesecurity.io/advisories)
* [Ruby Libraries Security Advisory Database and Tools](https://rubysec.com/)
