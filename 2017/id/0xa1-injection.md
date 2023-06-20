# A1:2017 Injection

| Agen ancaman / vektor serangan | Kelemahan Keamanan          | Dampak              |
| -- | -- | -- |
| Akses Lvl: Eksploitasi 3 | Prevalensi 2: Deteksi 3 | Teknis 3: Bisnis |
| Hampir semua sumber data bisa berupa vektor injeksi, variabel lingkungan, parameter, layanan web eksternal dan internal, dan semua jenis pengguna. [Kekurangan injeksi](https://www.owasp.org/index.php/Injection_Flaws) terjadi ketika penyerang bisa mengirim data yang tidak bersahabat ke penerjemah. | Cacat   injeksi sangat lazim, terutama dalam kode warisan. Kerentanan injeksi sering ditemukan di query SQL, LDAP, XPath, atau NoSQL, perintah OS, parser XML, header SMTP, ekspresi bahasa, dan kueri ORM. Kelemahan injeksi mudah ditemukan saat memeriksa kode. Pemindai dan fuzzers dapat membantu penyerang menemukan kekurangan injeksi. |Injeksi dapat mengakibatkan kehilangan data, rusak, atau pengungkapan kepada pihak yang tidak berwenang, kehilangan pertanggungjawaban, atau penolakan akses. Injeksi terkadang bisa mengakibatkan pengambilalihan host seacara keseluruhan. Dampak bisnis tergantung dari kebutuhan aplikasi dan data.|


## Apakah Aplikasi itu Rentan?

Aplikasi rentan terhadap serangan saat:

* Data yang dipasok pengguna tidak divalidasi, disaring, atau disterilkan oleh aplikasi.
* Permintaan dinamis atau panggilan non-parameter tanpa tanpa sadar konteks digunakan langsung di penerjemah. 
* Data yang tidak bersahabat digunakan dalam parameter pencarian pemetaan objek-relasional (ORM) untuk mengekstrak catatan sensitif tambahan.
* Data yang tidak bersahabat langsung digunakan atau digabungkan, sehingga SQL atau perintah berisi data struktur dan data yang tidak bersahabat dalam query dinamis, perintah, atau prosedur tersimpan.
* Beberapa injeksi yang lebih umum adalah perintah SQL, NoSQL, OS, pemetaan Object Relational Mapping (ORM), LDAP, dan Expression Language (EL) atau Object Graph Navigation Library (OGNL). Konsepnya identik diantara semua penafsir. Source code review adalah metode terbaik untuk mendeteksi jika aplikasi rentan terhadap injeksi, diikuti dengan pengujian otomatis secara menyeluruh terhadap semua parameter, header, URL, cookies, JSON, SOAP, dan data XML. Organisasi dapat menyertakan sumber statis ([SAST](https://www.owasp.org/index.php/Source_Code_Analysis_Tools)) dan uji aplikasi dinamis ([DAST](https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools)) alat ke dalam pipa CI / CD untuk mengidentifikasi kelemahan injeksi yang baru diperkenalkan sebelum penggelaran produksi.

## Bagaimana Cara Pencegahannya

Mencegah injeksi membutuhkan data terpisah dari perintah dan query.

* Pilihan yang lebih disukai adalah menggunakan API yang aman, yang menghindari penggunaan penafsir sepenuhnya atau menyediakan parameter antarmuka, atau bermigrasi untuk menggunakan Object Relational Mapping Tools (ORMs). ** Catatan **: Meskipun parameter, prosedur yang tersimpan masih dapat mengenalkan injeksi SQL jika PL / SQL atau T-SQL menggabungkan query dan data, atau mengeksekusi data yang bentrok dengan EXECUTE IMMEDIATE atau exec ().
* Gunakan validasi masukan positive server-side atau "whitelist". Ini bukan pertahanan yang lengkap karena banyak aplikasi memerlukan karakter khusus, seperti area teks atau API untuk aplikasi mobile.
* Untuk setiap sisa query dinamis, lepaskan karakter khusus menggunakan sintaks keluar khusus untuk penerjemah itu. ** Catatan **: Struktur SQL seperti nama tabel, nama kolom, dan sebagainya tidak dapat diloloskan, dan dengan demikian nama-nama struktur pengguna yang diberikan berbahaya. Ini adalah masalah umum dalam perangkat lunak penulisan laporan.
* Gunakan LIMIT dan kontrol SQL lainnya dalam query untuk mencegah penyebaran rekaman secara massal jika terjadi injeksi SQL.

## Contoh Skenario Serangan

**Skenario #1**: Aplikasi menggunakan data yang tidak terpercaya dalam pembuatan panggilan SQL yang rentan berikut ini:

`String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";`

**Skenario #2**: Demikian pula, kepercayaan buta huruf aplikasi dalam kerangka kerja dapat menghasilkan query yang masih rentan, (misalnya Hibernate Query Language (HQL)):

`Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");`

Dalam kedua kasus tersebut, penyerang memodifikasi nilai parameter 'id' di browser mereka untuk mengirim: 'atau' 1 '=' 1. Sebagai contoh:

`http://example.com/app/accountView?id=' UNION SELECT SLEEP(10);--`

Ini mengubah arti kedua query untuk mengembalikan semua catatan dari tabel akun. Serangan yang lebih berbahaya bisa mengubah atau menghapus data, atau bahkan memanggil prosedur yang tersimpan.

## Referensi

### OWASP

* [OWASP Proactive Controls: Parameterize Queries](https://www.owasp.org/index.php/OWASP_Proactive_Controls#2:_Parameterize_Queries)
* [OWASP ASVS: V5 Input Validation and Encoding](https://www.owasp.org/index.php/ASVS_V5_Input_validation_and_output_encoding)
* [OWASP Testing Guide: SQL Injection](https://www.owasp.org/index.php/Testing_for_SQL_Injection_(OTG-INPVAL-005)), [Command Injection](https://www.owasp.org/index.php/Testing_for_Command_Injection_(OTG-INPVAL-013)), [ORM injection](https://www.owasp.org/index.php/Testing_for_ORM_Injection_(OTG-INPVAL-007))
* [OWASP Cheat Sheet: Injection Prevention](https://www.owasp.org/index.php/Injection_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: SQL Injection Prevention](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: Injection Prevention in Java](https://www.owasp.org/index.php/Injection_Prevention_Cheat_Sheet_in_Java)
* [OWASP Cheat Sheet: Query Parameterization](https://www.owasp.org/index.php/Query_Parameterization_Cheat_Sheet)
* [OWASP Automated Threats to Web Applications – OAT-014](https://www.owasp.org/index.php/OWASP_Automated_Threats_to_Web_Applications)

### External

* [CWE-77: Command Injection](https://cwe.mitre.org/data/definitions/77.html)
* [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
* [CWE-564: Hibernate Injection](https://cwe.mitre.org/data/definitions/564.html)
* [CWE-917: Expression Language Injection](https://cwe.mitre.org/data/definitions/917.html)
* [PortSwigger: Server-side template injection](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)
