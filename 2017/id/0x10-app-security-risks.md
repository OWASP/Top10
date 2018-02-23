# Risk - Risiko-Risiko Keamanan Aplikasi

## Apa Saja Risiko-Risiko Keamanan Aplikasi??

Penyerang berpotensi menggunakan beragam cara melalui aplikasi Anda untuk membahayakan bisnis atau organisasi Anda. Setiap cara mewakili risiko, yang mungkin, cukup serius untuk memperoleh perhatian.

![App Security Risks](images/0x10-risk-1.png)

Terkadang cara ini mudah ditemukan dan dieksploitasi, namun kadang-kadang sulit. Demikian juga, kerusakan yang diakibatkan
dapat berkisar dari tidak ada apa-apa hingga membuat Anda keluar dari bisnis. Untuk menentukan risiko di organisasi Anda, Anda
dapat mengevaluasi kemungkinan yang diasosiasikan untuk setiap agen ancaman, vektor serangan, kelemahan keamanan, dan
mengkombinasikan dengan estimasi dampak teknis dan bisnis bagi organisasi Anda. Semua faktor ini menentukan risiko
keseluruhan.

## Apa Risiko Saya?

[OWASP Top 10](https://www.owasp.org/index.php/Top10) ini berfokus pada identifikasi risiko yang paling serius bagi sebagian besar organisasi. Untuk setiap risiko, kami memberikan informasi umum mengenai kemungkiinan dan dampak teknis dengan menggunakan skema penilaian sederhana berikut, yang berdasarkan pada  OWASP Risk Rating Methodology.  

| Agen Ancaman| Vektor Serangan | Keberadaan kelemahan| Deteksi Kelemahan | Dampak Teknis | Dampak Bisnis |
| -- | -- | -- | -- | -- | -- |
| Appli-   | Easy 3 | Widespread 3 | Easy 3 | Severe 3 | Business     |
| cation   | Average 2 | Common 2 | Average 2 | Moderate 2 | Specific |
| Specific | Difficult 1 | Uncommon 1 | Difficult 1 | Minor 1 |       |

In this edition, we have updated the risk rating system to assist in calculating the likelihood and impact of any given risk. For more details, please see [Note About Risks](0xc0-note-about-risks.md). 

Each organization is unique, and so are the threat actors for that organization, their goals, and the impact of any breach. If a public interest organization uses a content management system (CMS) for public information and a health system uses that same exact CMS for sensitive health records, the threat actors and business impacts can be very different for the same software. It is critical to understand the risk to your organization based on applicable threat agents and business impacts.

Where possible, the names of the risks in the Top 10 are aligned with [Common Weakness Enumeration](https://cwe.mitre.org/) (CWE) weaknesses to promote generally accepted naming conventions and to reduce confusion.

## References

### OWASP

* [OWASP Risk Rating Methodology](https://www.owasp.org/index.php/OWASP_Risk_Rating_Methodology)
* [Article on Threat/Risk Modeling](https://www.owasp.org/index.php/Threat_Risk_Modeling)

### External

* [ISO 31000: Risk Management Std](https://www.iso.org/iso-31000-risk-management.html)
* [ISO 27001: ISMS](https://www.iso.org/isoiec-27001-information-security.html)
* [NIST Cyber Framework (US)](https://www.nist.gov/cyberframework)
* [ASD Strategic Mitigations (AU)](https://www.asd.gov.au/infosec/mitigationstrategies.htm)
* [NIST CVSS 3.0](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator)
* [Microsoft Threat Modelling Tool](https://www.microsoft.com/en-us/download/details.aspx?id=49168)
