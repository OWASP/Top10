# A4:2017 XML External Entities (XXE)

| Agen ancaman / vektor serangan | Kelemahan Keamanan          | Dampak            |
| -- | -- | -- |
| Access Lvl : Eksploitasi 2 | Prevalensi 3: Deteksi 2 | Teknis 3: Bisnis |
| Penyerang dapat mengeksploitasi yaitu pemproses XML yang rentan jika mereka dapat mengunggah XML atau menyertakan konten yang jelek atau tidak sesuai dalam dokumen sebuah XML, mereka dapat mengeksploitasi kode yang rentan, dependencies atau integrasi. | Secara default, banyak pemproses XML yang lebih lama untuk memperbolehkan spesifikasi entitas eksternal, URI yang direferensikan dan dievaluasi selama pemrosesan XML. [SAST](https://www.owasp.org/index.php/Source_Code_Analysis_Tools) tool apat dapat menemukan masalah ini dengan memeriksa dependensi dan konfigurasi. [DAST](https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools) tool memerlukan langkah manual tambahan untuk mendeteksi dan memanfaatkan masalah ini. Manual tester perlu untuk dilatih tentang cara menguji XXE, karena hal ini tidak umum diuji pada tahun 2017. | Kelemahan ini dapat digunakan untuk mengekstrak data, menjalankan permintaan jarak jauh dari server, scan sistem internal, melakukan metode denial-of-service attack, serta melakukan serangan lainnya. |

## Apakah Aplikasi itu Rentan?

Aplikasi dan layanan web berbasis XML tertentu atau integrasi downstream mungkin rentan terhadap serangan bilamana:

* Aplikasi menerima XML secara langsung atau unggahan XML, terutama dari sumber yang tidak tepercaya, atau menyisipkan data yang tidak tepercaya ke dalam dokumen XML, yang kemudian diurai oleh pemroses XML.
* Setiap prosesor XML dalam aplikasi atau layanan web berbasis SOAP memiliki [_document type definitions (DTDs_)](https://en.wikipedia.org/wiki/Document_type_definition) yang diperbolehkan. Karena mekanisme yang tepat untuk menonaktifkan pemrosesan DTD cukup bervariasi berdasarkan pemprosesan XML, praktik yang baik untuk mempelajari dapat menggunakan referensi seperti [OWASP Cheat Sheet 'XXE Prevention'](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet). 
* bilamana aplikasi tersebut menggunakan SAML untuk tools dalam pemrosesan identitas dalam keamanan yang telah difederalkan atau dengan single sign on(SSO). SAML menggunakan XML untuk asersi identitas, dan sangat mungkin bahwa hal itu rentan.
* bilamana aplikasi tersebut menggunakan versi SOAP sebelumnya hingga versi 1.2, biasanya hal yang rentan serangan XXE adalah saat entitas XML dikirim atau dioper menuju framework SOAP.
* Untuk menjadi rentan dari serangan XXE biasanya berarti aplikasi tersebut cukup rentan untuk menolak serangan service termasuk metode Billion Laughs Attack.
## Cara untuk mencegah

Pelatihan untuk Developer sangatlah esensial untuk mengidentifikasi dan memitigasi serangan XXE. Tak hanya itu, mencegah serangan XXE membutuhkan hal sebagai berikut : 

* Bila memungkinkan, gunakan data format yang tidak terlalu kompleks seperti JSON, dan hindari serialisasi dari data yang bersifat sensitif.
* patch atau tingkatkan seluru pemroses XML dan library yang digunakan oleh aplikasi tersebut atau yang berada diatas Sistem Operasi(OS). Gunakan Pemeriksa dependency. Kemudian update SOAP ke SOAP dengan versi 1.2 atau yang lebih tinggi
* Nonaktifkan Eksternal Entitas XML dan Pemrosesan DTD di semua pengurai XML dalam aplikasi, sesuai dengan referensi [OWASP Cheat Sheet 'Pencegahan XXE'](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet). 
* Implementasikan daftar putih positif yang berada pada sisi server untuk validator input, pemfilteran atau sanitasi untuk mencegah data yang tidak bersahabat yang berada didalam dokumen XML.
* Verifikasikan XML tersebut atau unggah file XSL fungsionalitas untuk memvalidasi XML yang akan masuk menggunakan validator seperti XSD atau yang lain yang persis.
* Alat seperti SAST dapat membantu mendeteksi serangan XXE didalam sebuah source code, walau review code manual adalah alternatif terbaik dalam jumlah yang besar seperti aplikasi kompleks dengan banyak integrasi.

bila kontrol ini tidak dimungkinkan maka dengan mempertimbangkan untuk menggunakan virtual patching, Gateway keamanan API, atau Firewall dari APlikasi (WAFs) untuk mendeteksi, memonitor dan melakukan blocking pada serangan XXE.

## Contoh Skenario Serangan

Banyak sekali serangan XXE pada publik yang telah ditemukan, termasuk serangan pada perangkat tanam. XXE dapat terjadi dibanyak tempat yang tidak diekspektasikan, termasuk dependencies bersarang yang sangat dalam. Hal yang paling mudah adalah dengan mengupload sebuah file XML yang mencurigakan, bila diterima maka: 

**Skenario #1**: Penyerang berupaya untuk mengekstrak data dari sebuah server:

```
  <?xml version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE foo [
    <!ELEMENT foo ANY >
    <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
    <foo>&xxe;</foo>
```

**Skenario #2**: Sebuah penyerang menyelidiki server pribadi dengan mengganti kode entitas di atas menjadi:
```
   <!ENTITY xxe SYSTEM "https://192.168.1.1/private" >]>
```

**Skenario #3**: Sebuah penyerang berupaya untuk melakukan metode serangan denial-of-service dan berpotensial menggunakan endless file atau file yang tidak ada habisnya dengan seperti berikut:

```
   <!ENTITY xxe SYSTEM "file:///dev/random" >]>
```

## Referensi

### OWASP

* [OWASP Application Security Verification Standard](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide: Testing for XML Injection](https://www.owasp.org/index.php/Testing_for_XML_Injection_(OTG-INPVAL-008))
* [OWASP XXE Vulnerability](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Processing)
* [OWASP Cheat Sheet: XXE Prevention](https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet)
* [OWASP Cheat Sheet: XML Security](https://www.owasp.org/index.php/XML_Security_Cheat_Sheet)

### External

* [CWE-611: Improper Restriction of XXE](https://cwe.mitre.org/data/definitions/611.html)
* [Billion Laughs Attack](https://en.wikipedia.org/wiki/Billion_laughs_attack)
* [SAML Security XML External Entity Attack](https://secretsofappsecurity.blogspot.tw/2017/01/saml-security-xml-external-entity-attack.html)
* [Detecting and exploiting XXE in SAML Interfaces](https://web-in-security.blogspot.tw/2014/11/detecting-and-exploiting-xxe-in-saml.html)
