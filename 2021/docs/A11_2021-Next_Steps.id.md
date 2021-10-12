# A11:2021 – Langkah Selanjutnya

By design, the OWASP Top 10 is innately limited to the ten most
significant risks. Every OWASP Top 10 has “on the cusp” risks considered
at length for inclusion, but in the end, they didn’t make it. No matter
how we tried to interpret or twist the data, the other risks were more
prevalent and impactful.

Organizations working towards a mature appsec program or security
consultancies or tool vendors wishing to expand coverage for their
offerings, the following four issues are well worth the effort to
identify and remediate.

## Masalah-masalah Kualitas Kode

| Klasifikasi CWE | Tingkat Kejadian Maks | Rerata Tingkat kejadian | Rerate Eksploatasi Terbobot | Rerata Dampak Terbobot | Cakupan Maks | Rerata Cakupan | Total Kejadian | Total CVE |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 38           | 49.46%              | 2.22%               | 7.1                   | 6.7                  | 60.85%        | 23.42%        | 101736             | 7564        |

-   **Deskripsi.** Code quality issues include known security defects
    or patterns, reusing variables for multiple purposes, exposure of
    sensitive information in debugging output, off-by-one errors, time
    of check/time of use (TOCTOU) race conditions, unsigned or signed
    conversion errors, use after free, and more. The hallmark of this
    section is that they can usually be identified with stringent
    compiler flags, static code analysis tools, and linter IDE plugins.
    Modern languages by design eliminated many of these issues, such as
    Rust’s memory ownership and borrowing concept, Rust’s threading
    design, and Go’s strict typing and bounds checking.

-   **Bagaimana mencegahnya**. Enable and use your editor and language’s static
    code analysis options. Consider using a static code analysis tool.
    Consider if it might be possible to use or migrate to a language or
    framework that eliminates bug classes, such as Rust or Go.

-   **Contoh skenario serangan**. An attacker might obtain or update
    sensitive information by exploiting a race condition using a
    statically shared variable across multiple threads.

-   **Referensi**
    - [OWASP Code Review Guide](https://owasp.org/www-pdf-archive/OWASP_Code_Review_Guide_v2.pdf)

    - [Google Code Review Guide](https://google.github.io/eng-practices/review/)


## Denial of Service

| Klasifikasi CWE | Tingkat Kejadian Maks | Rerata Tingkat kejadian | Rerate Eksploatasi Terbobot | Rerata Dampak Terbobot | Cakupan Maks | Rerata Cakupan | Total Kejadian | Total CVE |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 8            | 17.54%              | 4.89%               | 8.3                   | 5.9                  | 79.58%        | 33.26%        | 66985              | 973         |

-   **Deskripsi**. Denial of service is always possible given
    sufficient resources. However, design and coding practices have a
    significant bearing on the magnitude of the denial of service.
    Suppose anyone with the link can access a large file, or a
    computationally expensive transaction occurs on every page. In that
    case, denial of service requires less effort to conduct.

-   **Bagaimana mencegahnya**. Performance test code for CPU, I/O, and memory
    usage, re-architect, optimize, or cache expensive operations.
    Consider access controls for larger objects to ensure that only
    authorized individuals can access huge files or objects or serve
    them by an edge caching network. 

-   **Contoh skenario serangan**. An attacker might determine that an
    operation takes 5-10 seconds to complete. When running four
    concurrent threads, the server seems to stop responding. The
    attacker uses 1000 threads and takes the entire system offline.

-   **Referensi**
    - [OWASP Cheet Sheet: Denial of Service](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
    
    - [OWASP Attacks: Denial of Service](https://owasp.org/www-community/attacks/Denial_of_Service)

## Kesalahan Manajemen Memori

| Klasifikasi CWE | Tingkat Kejadian Maks | Rerata Tingkat kejadian | Rerate Eksploatasi Terbobot | Rerata Dampak Terbobot | Cakupan Maks | Rerata Cakupan | Total Kejadian | Total CVE |
|:-------------:|:--------------------:|:--------------------:|:--------------:|:--------------:|:----------------------:|:---------------------:|:-------------------:|:------------:|
| 14           | 7.03%               | 1.16%               | 6.7                   | 8.1                  | 56.06%        | 31.74%        | 26576              | 16184       |

-   **Deskripsi**. Aplikasi web cenderung ditulis dalam bahasa-bahasa yang memorinya dikelola, seperti Java, .NET, atau node.js (JavaScript atau TypeScript). Namun, bahasa-bahasa ini ditulis dalam bahasa sistem yang memiliki masalah-masalah manajemen memori, seperti buffer overflow atau heap overflow, use after free, integer overflow, dan lebih banyak lagi. Ada banyak 'sandbox escape' selama bertahun-tahun yang membuktikan bahwa karena bahasa aplikasi web secara nominal "aman" memori, landasannya tidak.

-   **Bagaimana mencegahnya**. Banyak API modern yang kini ditulis dalam bahasa-bahasa yang aman-memori seperti Rust atau Go. Dalam kasus Rust, keamanan memori adalah fitur sangat penting dari bahasa. Untuk kode yang telah ada, penggunaan flag compiler yang ketat, penentuan tipe yang kuat, analisis kode statik, dan uji fuzz bisa menguntungkan dalam mengidentifikasi kebocoran memori, memori, dan array overrun, dan lebih banyak lagi.

-   **Contoh skenario serangan**. Buffer overflow dan heap overflow masih menjadi andalah para penyerang selama bertahun-tahun. Penyerang mengirim data ke suatu program, yang disimpannya dalam buffer stack yang berukuran terlalu kecil. Hasilnya adalah informasi pada call stack ditimpa, termasuk pointer balik fungsi. Data menata nilai pointer balik sehingga ketika fungsi kembali, itu memindah kendali ke kode jahat yang dimuat dalam data penyerang.

-   **Referensi**
    - [OWASP Vulnerabilities: Buffer Overflow](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)
    
    - [OWASP Attacks: Buffer Overflow](https://owasp.org/www-community/attacks/Buffer_overflow_attack)
    
    - [Science Direct: Integer Overflow](https://www.sciencedirect.com/topics/computer-science/integer-overflow)
