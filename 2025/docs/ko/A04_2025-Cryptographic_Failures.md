# A04:2025 암호 실패 ![icon](../assets/TOP_10_Icons_Final_Crypto_Failures.png){: style="height:80px;width:80px" align="right"}

> 옮긴이: 본 문서에서는 "cryptographic"을 "암호"로 번역한다. 이는 종종 "암호화"로 번역되나, 해당 용어는 암호화뿐 아니라 복호화, 해시, 전자서명 등 암호 기술 전반을 포괄하므로 본 문서의 번역어를 "암호"로 통일한다.


## 배경 

암호 실패 카테고리는 이전 버전에서 2단계 내려가 4위가 되었다. 이 카테고리는 암호 부재, 불충분한 암호 강도, 암호키 유출 및 관련 오류에 중점을 둔다. 이 위험에서 가장 흔한 CWE 3개는 약한 의사 난수 생성기(PRNG) 사용과 관련이 있다: *CWE-327: 취약하거나 위험한 암호 알고리즘 사용*, *CWE-331: 불충분한 엔트로피*, *CWE-1241: 난수 생성기 내 예측 가능한 알고리즘 사용*, *CWE-338: 암호학적으로 약한 의사 난수 생성기(PRNG) 사용*.


## 점수표


<table>
  <tr>
   <td>해당 CWE 개수
   </td>
   <td>최대 발생률
   </td>
   <td>평균 발생률
   </td>
   <td>최대 커버리지
   </td>
   <td>평균 커버리지
   </td>
   <td>평균 가중 익스플로잇 점수
   </td>
   <td>평균 가중 영향 점수
   </td>
   <td>총 발생 건수
   </td>
   <td>총 CVE 건수
   </td>
  </tr>
  <tr>
   <td>32
   </td>
   <td>13.77%
   </td>
   <td>3.80%
   </td>
   <td>100.00%
   </td>
   <td>47.74%
   </td>
   <td>7.23
   </td>
   <td>3.90
   </td>
   <td>1,665,348
   </td>
   <td>2,185
   </td>
  </tr>
</table>



## 설명

일반적으로, [전송 계층](https://en.wikipedia.org/wiki/Transport_layer) ([OSI 4계층](https://en.wikipedia.org/wiki/OSI_model))에서의 모든 데이터는 암호화되어 전송해야 한다. 과거에는 CPU 성능과 프라이빗 키/인증서 관리가 장벽이었다. 현재는 암호 연산 가속을 위한 CPU 전용 명령어(예: [AES support](https://en.wikipedia.org/wiki/AES_instruction_set))가 도입되었고, [LetsEncrypt.org](https://letsencrypt.org/) 같은 서비스와 대형 클라우드 공급업체가 자사 플랫폼에 긴밀히 통합된 인증서 관리 서비스를 제공하면서 프라이빗 키와 인증서 관리도 간소화되었다.

전송 계층 보안 외에도 어떤 데이터가 저장 시 암호화가 필요한지, 그리고 전송 중([애플리케이션 계층](https://en.wikipedia.org/wiki/Application_layer), OSI 7계층)에 추가적인 암호화가 필요한지 결정하는 것이 중요하다. 예를 들어 패스워드, 신용카드 번호, 건강 기록, 개인 정보, 비즈니스 기밀은 추가 보호가 필요하다. 특히 해당 데이터가 개인정보 보호법(예: EU의 GDPR)이나 규정(예: PCI-DSS)의 적용을 받는 경우 더욱 중요하다. 이러한 모든 데이터에 대해 다음을 확인해야 한다.



* 약하거나 오래된 암호 알고리즘 또는 프로토콜이 기본값으로 사용되거나 레거시 코드에서 사용되고 있는가?
* 기본 암호키가 사용되는가? 약한 암호키가 생성되는가? 키가 재사용되는가? 적절한 키 관리 및 키 순환 주기가 없는가?
* 사용되는 암호키가 소스코드 저장소에 커밋되어 있는가?
* 암호화가 강제되지 않는가? (예: HTTP 헤더[브라우저]의 보안 지시문이 누락되어 있는가?)
* 수신한 서버 인증서와 신뢰 체인이 적절히 검증되는가?
* 초기화 벡터(IV)가 무시되거나, 재사용되거나, 암호 운영 모드에 맞게 충분히 안전하게 생성되지 않는가? ECB 같은 안전하지 않은 운영 모드를 사용하는가? 인증 암호화(Authenticated Encryption)가 더 적절한 상황에서 기본 암호화를 사용하는가?
* 패스워드 기반 키 파생 함수 없이 패스워드를 암호키로 직접 사용하는가?
* 암호 요구사항을 충족하도록 설계되지 않은 난수를 사용하는가? 올바른 함수를 선택하더라도 개발자가 시드를 지정해야 하는가? 그렇지 않다면, 내장된 강력한 시드 기능을 엔트로피(무작위성)가 부족한 시드로 덮어쓰지 않았는가?
* MD5, SHA1 같은 더 이상 사용하지 않는 해시 함수를 사용하는가? 암호학적 해시 함수가 필요한 곳에 비암호학적 해시 함수를 사용하는가?
* 암호 오류 메시지나 사이드 채널 정보가 패딩 오라클 공격 등으로 악용될 수 있는가?
* 암호 알고리즘이 다운그레이드되거나 우회될 수 있는가?

레퍼런스 참고 ASVS: Cryptography (V11), Secure Communication (V12) and Data Protection (V14).


## 대응 방안

최소한 다음 사항들을 수행하고 레퍼런스를 참고한다.



* 애플리케이션이 처리, 저장, 전송하는 데이터를 분류하고 라벨링한다. 개인정보 보호법, 규제 요구사항, 비즈니스 필요에 따라 어떤 데이터가 민감한지 식별한다.
* 가장 민감한 키는 하드웨어 또는 클라우드 기반 HSM(하드웨어 보안 모듈)에 보관한다.
* 암호 알고리즘은 가능하면 신뢰할 수 있는 구현체(라이브러리)를 사용한다.
* 불필요한 민감 데이터는 저장하지 않는다. 저장 시 가능한 한 빨리 폐기하거나 PCI DSS 준수 토큰화(PCI DSS compliant tokenization) 또는 마스킹(truncation)을 적용한다. 저장하지 않은 데이터는 탈취될 수 없다.
* 저장된 모든 민감 데이터가 암호화되었는지 확인한다.
* 최신의 강력한 표준 알고리즘, 프로토콜, 키가 적용되어 있는지 확인하고, 적절한 키 관리를 수행한다.
* 전송 중인 모든 데이터는 TLS 1.2 이상의 프로토콜로만 암호화하고, 전방향 비밀성(Forward Secrecy) 암호를 사용하며, CBC(Cipher Block Chaining) 암호에 대한 지원을 중단하고, 양자 내성 키 교환 알고리즘을 지원한다. HTTPS는 HSTS(HTTP Strict Transport Security)를 사용해 강제한다. 도구를 활용해 모든 항목을 검사한다.
* 민감 데이터가 포함된 응답의 캐싱을 비활성화한다. 이는 콘텐츠 전송 네트워크(CDN), 웹 서버, 모든 애플리케이션 캐싱(예: Redis)을 포함한다. 
* 데이터 분류에 따라 필요한 보안 통제를 적용한다.
* FTP 나 STARTTLS 같은 암호화되지 않는 프로토콜을 사용하지 않는다. SMTP로 기밀 정보를 전송하는 것은 피한다.
* 패스워드는 작업 요소(지연 요소)를 갖춘 강력한 적응형 솔트 해싱 함수를 사용해 저장한다. Argon2, yescrypt, scrypt, PBKDF2-HMAC-SHA-512 등이 있다. 레거시 시스템에서 bcrypt를 사용하는 경우 [OWASP Cheat Sheet: Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)를 참고한다.
* 초기화 벡터(IV)는 운영 모드에 적합하게 선택해야 한다. 이는 CSPRNG(Cryptographically Secure Pseudo Random Number Generator) 사용을 의미할 수 있다. 논스(nonce)를 요구하는 모드의 경우 IV에 CSPRNG가 필요하지 않다. 모든 경우에 IV는 고정 키에 대해 두 번 사용해서는 안 된다.
* 기본 암호화 대신 항상 인증 암호화(Authenticated Encryption)를 사용한다.
* 키는 암호학적으로 무작위로 생성하고, 메모리에 바이트 배열로 저장해야 한다. 패스워드를 암호키로 사용하는 경우 적절한 패스워드 기반 키 파생 함수(PBKDF)를 통해 키로 변환해야 한다.
* 적절한 곳에서 암호학적 무작위성이 사용되는지, 그리고 예측 가능하거나 엔트로피가 낮은 방식으로 시드되지 않았는지 확인한다. 대부분의 최신 API는 보안을 위해 개발자가 CSPRNG에 시드를 설정할 필요가 없다.
* MD5, SHA1, CBC(Cipher Block Chaining), PKCS #1 v1.5 등 더 이상 사용되지 않는 암호 함수, 블록 빌딩 메서드, 패딩 스키마 사용을 피한다.
* 보안 전문가, 전용 도구, 또는 둘 다를 활용해 설정과 구성이 보안 요구사항을 충족하는지 검토한다.
* 지금부터 양자 내성 암호(PQC)를 준비해야 한다(ENISA 참고). 고위험 시스템은 늦어도 2030년 말까지 안전하게 보호되도록 해야 한다.


## 공격 시나리오 예시

**시나리오 1:** 어떤 사이트가 모든 페이지에 TLS를 사용하지 않거나 강제하지 않고, 약한 암호화를 지원한다. 공격자는 네트워크 트래픽을 모니터링하고(예: 안전하지 않은 무선 네트워크), HTTPS 연결을 HTTP로 다운그레이드한 뒤, 요청을 가로채 사용자의 세션 쿠키를 탈취한다. 공격자는 이 쿠키를 재전송해 사용자의 인증된 세션을 하이재킹하여 개인 데이터에 접근하거나 수정한다. 위 방법 외에도 전송되는 모든 데이터를 변조할 수 있다(예: 송금 수신자).

**시나리오 2:** 패스워드 데이터베이스가 솔트 없이 또는 단순한 해시로 모든 사용자의 패스워드를 저장한다. 파일 업로드 취약점으로 공격자가 패스워드 데이터베이스를 탈취할 수 있다. 솔트가 없는 해시는 사전 계산된 레인보우 테이블로 노출될 수 있다. 단순하거나 빠른 해시 함수로 생성된 해시는 솔트가 있더라도 GPU로 크랙할 수 있다.


## 참조


* [OWASP Proactive Controls: C2: Use Cryptography to Protect Data ](https://top10proactive.owasp.org/archive/2024/the-top-10/c2-crypto/)
* [OWASP Application Security Verification Standard (ASVS): ](https://owasp.org/www-project-application-security-verification-standard) [V11,](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x20-V11-Cryptography.md) [12, ](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x21-V12-Secure-Communication.md) [14](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x23-V14-Data-Protection.md)
* [OWASP Cheat Sheet: Transport Layer Protection](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
* [OWASP Cheat Sheet: User Privacy Protection](https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
* [OWASP Cheat Sheet: HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)
* [OWASP Testing Guide: Testing for weak cryptography](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README)
* [ENISA: A Coordinated Implementation Roadmap for the Transition to Post-Quantum Cryptography](https://digital-strategy.ec.europa.eu/en/library/coordinated-implementation-roadmap-transition-post-quantum-cryptography)
* [NIST Releases First 3 Finalized Post-Quantum Encryption Standards](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards)


## 해당되는 CWE 목록

* [CWE-261 Weak Encoding for Password](https://cwe.mitre.org/data/definitions/261.html)

* [CWE-296 Improper Following of a Certificate's Chain of Trust](https://cwe.mitre.org/data/definitions/296.html)

* [CWE-319 Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

* [CWE-320 Key Management Errors (Prohibited)](https://cwe.mitre.org/data/definitions/320.html)

* [CWE-321 Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)

* [CWE-322 Key Exchange without Entity Authentication](https://cwe.mitre.org/data/definitions/322.html)

* [CWE-323 Reusing a Nonce, Key Pair in Encryption](https://cwe.mitre.org/data/definitions/323.html)

* [CWE-324 Use of a Key Past its Expiration Date](https://cwe.mitre.org/data/definitions/324.html)

* [CWE-325 Missing Required Cryptographic Step](https://cwe.mitre.org/data/definitions/325.html)

* [CWE-326 Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

* [CWE-327 Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

* [CWE-328 Reversible One-Way Hash](https://cwe.mitre.org/data/definitions/328.html)

* [CWE-329 Not Using a Random IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html)

* [CWE-330 Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)

* [CWE-331 Insufficient Entropy](https://cwe.mitre.org/data/definitions/331.html)

* [CWE-332 Insufficient Entropy in PRNG](https://cwe.mitre.org/data/definitions/332.html)

* [CWE-334 Small Space of Random Values](https://cwe.mitre.org/data/definitions/334.html)

* [CWE-335 Incorrect Usage of Seeds in Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/335.html)

* [CWE-336 Same Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/336.html)

* [CWE-337 Predictable Seed in Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/337.html)

* [CWE-338 Use of Cryptographically Weak Pseudo-Random Number Generator(PRNG)](https://cwe.mitre.org/data/definitions/338.html)

* [CWE-340 Generation of Predictable Numbers or Identifiers](https://cwe.mitre.org/data/definitions/340.html)

* [CWE-342 Predictable Exact Value from Previous Values](https://cwe.mitre.org/data/definitions/342.html)

* [CWE-347 Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)

* [CWE-523 Unprotected Transport of Credentials](https://cwe.mitre.org/data/definitions/523.html)

* [CWE-757 Selection of Less-Secure Algorithm During Negotiation('Algorithm Downgrade')](https://cwe.mitre.org/data/definitions/757.html)

* [CWE-759 Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html)

* [CWE-760 Use of a One-Way Hash with a Predictable Salt](https://cwe.mitre.org/data/definitions/760.html)

* [CWE-780 Use of RSA Algorithm without OAEP](https://cwe.mitre.org/data/definitions/780.html)

* [CWE-916 Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)

* [CWE-1240 Use of a Cryptographic Primitive with a Risky Implementation](https://cwe.mitre.org/data/definitions/1240.html)

* [CWE-1241 Use of Predictable Algorithm in Random Number Generator](https://cwe.mitre.org/data/definitions/1241.html)
