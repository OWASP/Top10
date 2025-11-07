# OWASP Top 10’u bir standart olarak nasıl kullanmalı

OWASP Top 10 öncelikle bir farkındalık dokümanıdır. Ancak bu durum, kuruluşların 2003’teki başlangıcından beri onu fiilî bir AppSec endüstri standardı olarak kullanmasını engellemedi. OWASP Top 10’u bir coding veya testing standardı olarak kullanmak istiyorsanız, bunun asgari seviye olduğunu ve sadece bir başlangıç noktası olduğunu bilin.

OWASP Top 10’u bir standart olarak kullanmanın zorluklarından biri, kolay test edilebilir konulardan ziyade AppSec risklerini dokümante etmemizdir. Örneğin, A04:2021–Insecure Design çoğu testing biçiminin kapsamı dışındadır. Başka bir örnek olarak, aktif, kullanımda ve etkili logging ve monitoring’in uygulanıp uygulanmadığını test etmek yalnızca mülakatlarla ve etkili incident response örnekleri talep edilerek yapılabilir. Bir static code analysis tool, logging’in yokluğunu arayabilir; ancak business logic veya access control’ün kritik security breach’leri loglayıp loglamadığını belirlemek imkânsız olabilir. Penetration tester’lar yalnızca test ortamında incident response’u tetiklediklerini belirleyebilirler ki bu ortam da nadiren production ile aynı şekilde izlenir.

OWASP Top 10’un ne zaman kullanılmasının uygun olduğuna dair önerilerimiz:

| Use Case                | OWASP Top 10 2021 | OWASP Application Security Verification Standard |
| ----------------------- | :---------------: | :----------------------------------------------: |
| Awareness               |        Yes        |                                                  |
| Training                |    Entry level    |                   Comprehensive                  |
| Design and architecture |    Occasionally   |                        Yes                       |
| Coding standard         |    Bare minimum   |                        Yes                       |
| Secure Code review      |    Bare minimum   |                        Yes                       |
| Peer review checklist   |    Bare minimum   |                        Yes                       |
| Unit testing            |    Occasionally   |                        Yes                       |
| Integration testing     |    Occasionally   |                        Yes                       |
| Penetration testing     |    Bare minimum   |                        Yes                       |
| Tool support            |    Bare minimum   |                        Yes                       |
| Secure Supply Chain     |    Occasionally   |                        Yes                       |

Bir application security standardı benimsemek isteyen herkesi [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/)’ı (ASVS) kullanmaya teşvik ederiz; çünkü bu standart doğrulanabilir ve test edilebilir olacak şekilde tasarlanmıştır ve secure development lifecycle’ın tüm bölümlerinde kullanılabilir.

ASVS, tool vendor’lar için tek kabul edilebilir seçimdir. Tool’lar, OWASP Top 10’daki bazı risklerin doğası gereği (A04:2021–Insecure Design’a atıfla) OWASP Top 10’a karşı kapsamlı şekilde detect, test veya protect sağlayamaz. OWASP, OWASP Top 10’un tam kapsamına ilişkin her türlü iddiayı caydırır; çünkü bu basitçe doğru değildir.

