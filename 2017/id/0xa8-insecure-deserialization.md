# A8:2017 Deserialisasi yang Tidak Aman

| Threat agents/Attack vectors | Security Weakness           | Impacts               |
| -- | -- | -- |
| Akses Lvl: Eksploitasi 1 | Prevalensi 2 : Deteksi 2 | Teknis 3: Bisnis |
| Penyerang dapat mengeksploitasi prosesor XML yang rentan jika mereka dapat mengunggah XML atau menyertakan konten yang tidak bersahabat dalam dokumen XML, mengeksploitasi kode yang rentan, ketergantungan, atau integrasi. | Masalah ini termasuk dalam Top 10 berdasarkan [Survei Industri ](https://owasp.blogspot.com/2017/08/owasp-top-10-2017-project-update.html) and bukan pada data yang dapat dihitung. Beberapa alat dapat menemukan kekurangan deserialisasi, tetapi bantuan manusia sering kali diperlukan untuk memvalidasi masalah. Diharapkan bahwa data prevalensi untuk kekurangan deserialisasi akan meningkat seiring dengan pengembangan perangkat untuk membantu mengidentifikasi dan mengatasinya. | Dampak kelemahan deserialisasi tidak bisa dilebih-lebihkan. Cacat ini dapat menyebabkan serangan eksekusi kode jarak jauh, salah satu serangan paling serius yang mungkin terjadi. Dampak bisnis bergantung pada kebutuhan perlindungan aplikasi dan data.|

## Apakah Aplikasi itu Rentan?

Applikasi dan API akan menjadi rentan jika mereka menghilangkan identitas objek yang dimusuhi atau dirusak yang disediakan oleh penyerang.

Ini dapat mengakibatkan dua jenis serangan utama:

* Serangan terkait objek dan struktur data di mana penyerang mengubah logika aplikasi atau mencapai eksekusi kode jarak jauh arbitrer jika ada kelas yang tersedia untuk aplikasi yang dapat mengubah perilaku selama atau setelah deserialisasi.
* Serangan perusakan data tipikal seperti serangan terkait kontrol akses di mana struktur data yang ada digunakan tetapi kontennya diubah.

Serialisasi dapat digunakan dalam aplikasi untuk:

* Remote- dan komunikasi antar proses (RPC/IPC) 
* Protokol kawat, layanan web, perantara pesan
* Caching / Persistence
* Database, server cache, sistem file
* Cookie pada HTTP, HTML form parameter, otentikasi token pada API

## How To Prevent

The only safe architectural pattern is not to accept serialized objects from untrusted sources or to use serialization mediums that only permit primitive data types.

If that is not possible, consider one of more of the following:

* Implementing integrity checks such as digital signatures on any serialized objects to prevent hostile object creation or data tampering.
* Enforcing strict type constraints during deserialization before object creation as the code typically expects a definable set of classes. Bypasses to this technique have been demonstrated, so reliance solely on this is not advisable.
* Isolating and running code that deserializes in low privilege environments when possible.
* Log deserialization exceptions and failures, such as where the incoming type is not the expected type, or the deserialization throws exceptions.
* Restricting or monitoring incoming and outgoing network connectivity from containers or servers that deserialize.
* Monitoring deserialization, alerting if a user deserializes constantly.


## Example Attack Scenarios

**Scenario #1**: A React application calls a set of Spring Boot microservices. Being functional programmers, they tried to ensure that their code is immutable. The solution they came up with is serializing user state and passing it back and forth with each request. An attacker notices the "R00" Java object signature, and uses the Java Serial Killer tool to gain remote code execution on the application server.

**Scenario #2**: A PHP forum uses PHP object serialization to save a "super" cookie, containing the user's user ID, role, password hash, and other state:

`a:4:{i:0;i:132;i:1;s:7:"Mallory";i:2;s:4:"user";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}`

An attacker changes the serialized object to give themselves admin privileges:
`a:4:{i:0;i:1;i:1;s:5:"Alice";i:2;s:5:"admin";i:3;s:32:"b6a8b3bea87fe0e05022f8f3c88bc960";}`

## References

### OWASP

* [OWASP Cheat Sheet: Deserialization](https://www.owasp.org/index.php/Deserialization_Cheat_Sheet)
* [OWASP Proactive Controls: Validate All Inputs](https://www.owasp.org/index.php/OWASP_Proactive_Controls#4:_Validate_All_Inputs)
* [OWASP Application Security Verification Standard: TBA](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP AppSecEU 2016: Surviving the Java Deserialization Apocalypse](https://speakerdeck.com/pwntester/surviving-the-java-deserialization-apocalypse)
* [OWASP AppSecUSA 2017: Friday the 13th JSON Attacks](https://speakerdeck.com/pwntester/friday-the-13th-json-attacks)

### External

* [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
* [Java Unmarshaller Security](https://github.com/mbechler/marshalsec)
* [OWASP AppSec Cali 2015: Marshalling Pickles](http://frohoff.github.io/appseccali-marshalling-pickles/)
