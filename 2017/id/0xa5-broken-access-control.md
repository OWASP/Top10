# A5:2017 Kontrol Akses Yang Buruk

| Agen ancaman / vektor serangan | Kelemahan Keamanan  | Dampak |
| -- | -- | -- |
| Akses Lvl : Exploitasi 2 | Prevalensi 2 : Deteksi 2 | Teknik 3 : Bisnis |
| Eksploitasi kontrol akses adalah keahlian inti pada penyerang [SAST](https://www.owasp.org/index.php/Source_Code_Analysis_Tools) dan [DAST](https://www.owasp.org/index.php/Category:Vulnerability_Scanning_Tools) Tool dapat mendeteksi tidak adanya kontrol akses tetapi tidak dapat memverifikasi apakah itu berfungsi ketika serangan itu muncul. Kontrol akses dapat dideteksi menggunakan cara manual, atau mungkin melalui otomatisasi karena tidak adanya kontrol akses dalam framework tertentu| Kelemahan kontrol akses adalah umum karena kurangnya security assessment/deteksi awal, dan kurangnya pengujian fungsional yang efektif oleh pengembang aplikasi. Deteksi kontrol akses biasanya tidak menerima pengujian statis atau dinamis otomatis. Pengujian manual adalah cara terbaik untuk mendeteksi kontrol akses yang hilang atau tidak efektif, termasuk metode HTTP (GET vs PUT, dll), Kontrol, referensi objek langsung, dll.| The technical impact is attackers acting as users or administrators, or users using privileged functions, or creating, accessing, updating or deleting every record. The business impact depends on the protection needs of the application and data. Dampak teknisnya adalah penyerang bertindak sebagai pengguna atau administrator, atau pengguna yang menggunakan hak akses istimewa, atau membuat, mengakses, memperbarui, atau menghapus setiap catatan. Dampak bisnis tergantung pada kebutuhan perlindungan aplikasi dan data |

## Apakah Aplikasi itu Rentan?

Kontrol akses memberlakukan kebijakan sedemikian rupa sehingga pengguna tidak dapat bertindak di luar izin yang dimaksudkan. Kegagalan biasanya mengarah pada pengungkapan informasi yang tidak sah, modifikasi atau penghancuran semua data, atau melakukan fungsi bisnis di luar batas pengguna. Kerentanan kontrol akses yang umum termasuk:

* Bypassing access control checks by modifying the URL, internal application state, or the HTML page, or simply using a custom API attack tool.
* Allowing the primary key to be changed to another's users record, permitting viewing or editing someone else's account.
* Elevation of privilege. Acting as a user without being logged in, or acting as an admin when logged in as a user.
* Metadata manipulation, such as replaying or tampering with a JSON Web Token (JWT) access control token or a cookie or hidden field manipulated to elevate privileges, or abusing JWT invalidation
* CORS misconfiguration allows unauthorized API access.
* Force browsing to authenticated pages as an unauthenticated user or to privileged pages as a standard user. Accessing API with missing access controls for POST, PUT and DELETE.

## Cara Mencegah

Access control is only effective if enforced in trusted server-side code or server-less API, where the attacker cannot modify the access control check or metadata.

* With the exception of public resources, deny by default.
* Implement access control mechanisms once and re-use them throughout the application, including minimizing CORS usage.
* Model access controls should enforce record ownership, rather than accepting that the user can create, read, update, or delete any record.
* Unique application business limit requirements should be enforced by domain models.
* Disable web server directory listing and ensure file metadata (e.g. .git) and backup files are not present within web roots.
* Log access control failures, alert admins when appropriate (e.g. repeated failures).
* Rate limit API and controller access to minimize the harm from automated attack tooling.
* JWT tokens should be invalidated on the server after logout.
* Developers and QA staff should include functional access control unit and integration tests.

## Contoh Skenario Serangan

**Skenario #1**: The application uses unverified data in a SQL call that is accessing account information:

```
  pstmt.setString(1, request.getParameter("acct"));
  ResultSet results = pstmt.executeQuery();
```

An attacker simply modifies the 'acct' parameter in the browser to send whatever account number they want. If not properly verified, the attacker can access any user's account.

`http://example.com/app/accountInfo?acct=notmyacct`

**Scenario #2**: An attacker simply force browses to target URLs. Admin rights are required for access to the admin page.

```
  http://example.com/app/getappInfo
  http://example.com/app/admin_getappInfo
```

If an unauthenticated user can access either page, it’s a flaw. If a non-admin can access the admin page, this is a flaw.

## Referensi

### OWASP

* [OWASP Proactive Controls: Access Controls](https://www.owasp.org/index.php/OWASP_Proactive_Controls#6:_Implement_Access_Controls)
* [OWASP Application Security Verification Standard: V4 Access Control](https://www.owasp.org/index.php/Category:OWASP_Application_Security_Verification_Standard_Project#tab=Home)
* [OWASP Testing Guide: Authorization Testing](https://www.owasp.org/index.php/Testing_for_Authorization)
* [OWASP Cheat Sheet: Access Control](https://www.owasp.org/index.php/Access_Control_Cheat_Sheet)

### Eksternal

* [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
* [CWE-284: Improper Access Control (Authorization)](https://cwe.mitre.org/data/definitions/284.html)
* [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
* [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
* [PortSwigger: Exploiting CORS misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
