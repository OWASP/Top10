# A04:2025 암호학적 실패 ![icon](../assets/TOP_10_Icons_Final_Crypto_Failures.png){: style="height:80px;width:80px" align="right"}



## 배경. 

2단계 하락해 4위에 유지하고 있다. 이번 카테고리는 암호화 부재, 불충분하게 강한 암호화, 약한 암호화키 그리고 에러와 관련된 실패에 중점을 둔다. 해당 카테고리에 포함된 3개의 CWE는 약한 의사 난수 생성기(PRNG)와 관련되어 있다. `CWE-327: 위험하고 실패한 암호화 알고리즘`, `CWE-331: 불충분한 엔트로피`, `CWE-1241: 난수 생성기 내 예측 가능한 알고리즘`, `CWE-338: 암호학적 약한 의사난수 생성기(PRNG) 사용`



## 점수표.


<table>
  <tr>
   <td>해당되는 CWE 개수
   </td>
   <td>최대 취약점 발생률
   </td>
   <td>평균 취약점 발생률
   </td>
   <td>최대 테스트 커버리지
   </td>
   <td>평균 테스트 커버리지
   </td>
   <td>가중 평균 악용도
   </td>
   <td>가중 평균 영향도
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



## 설명. 

흔히 말하기를, [전송 계층]((https://en.wikipedia.org/wiki/Transport_layer)([OSI 4계층](https://en.wikipedia.org/wiki/OSI_model)) 내 모든 데이터는 암호화되어 전송되어야 한다고 한다. 이전 장벽으로 CPU 성능, 프라이빗 키/인증서 관리가 있었으나, 지금은 CPU 명령어 셋이 정확한 암호화를(예시: [AES support](https://en.wikipedia.org/wiki/AES_instruction_set)) 위해 설계되었고, 프라이빗 키와 인정서 관리는 [LetsEncrypt.org](https://LetsEncrypt.org) 같은 서비스나 큰 클라우드 벤더들이 특정 플랫폼을 위한 통합된 인증서 관리 서비스를 제공하여 관리하기 쉬워졌다.

전송 계층 보안 외에도 어떤 저장된 데이터에 암호화가 필요한지 결정하는 것과 전송 중 ([애플리케이션 계층](https://en.wikipedia.org/wiki/Application_layer) 내, OSI 7계층)에도 추가적인 암호화가 필요한지 결정하는 것도 중요하다.  예시로, 패스워드, 신용 카드 번호, 건강 정보, 개인 정보 그리고 비즈니스 기밀 자료는 추가적 보호가 요구된다. 특히 해당 데이터가 개인정보 법률 (예시, GDPR, PCI DSS)에 명시된 경우 더욱 그렇다.
해당 데이터들을 위해선 다음과 같은 사항들이 해당되는지 검토하여야 한다.



* 약하거나 오래된 암호화 알고리즘이나 프로토콜이 기본 값으로 또는 예전 코드에 사용되는가?
* 기본 암호키가 사용되는가, 약한 암호키가 생성되었는가, 같은 키가 반복적으로 사용되는가, 적절한 키 관리 시스템이나 키 변경 주기가 있는가?
* 사용되는 암호키가 소스코드 저장소 내 존재하는가?
* 암호화가 강제되는가? (예시. HTTP 헤더 보안 지시자 또는 헤더 존재 여부)
* 수신한 서버 인증서와 신뢰 체인이 적절히 검증되었는가?
* 초기 벡터가 무시되거나, 재사용되거나 또는 운영 암호화 모드를 위한 충분한 초기 벡터가 생성되었는가? ECB 같은 안전하지 않은 운영 모드를 사용하는가? 인증된 적절한 암호화가 존재하는데 단순한 암호화를 사용하지는 않는가?
* 패스워드 기반 키 유도 함수가 없는 상태에서 패스워드가 암호키로써 사용되는가?
* 암호화 요구사항에 충족하지 않는 난수를 사용하는가? 만약 올바른 함수를 선택하더라도 개발자가 시드를 선택해야 하는가? 만일 아니라면, 개발자가 충분한 엔트로피/예측 불가능성이 부족한 시드로 강한 시드 기능을 덮어쓰지는 않았는가?
* MD5, SHA1 같은 더 이상 사용하지 않는 해시 함수를 사용하고 있거나 또는 암호학적 해시 함수가 필요할 때 비암호학적 해시 함수를 사용하는가?
* 암호화 알고리즘이 다운 그레이드 되거나 우회 가능한가?

레퍼런스 참고 ASVS: Cryptography (V11), Secure Communication (V12) and Data Protection (V14).


## 대응 방안. 

최소한 다음 사항들을 수행하고 레퍼런스를 참고하라.



* 애플리케이션에 의해 진행, 저장, 전송되는 데이터를 분류, 라벨링한다. 개인정보 보호법, 규제 요구사항, 비즈니스 필요에 따른 어떤 데이터가 민감한지 식별한다.
* 하드웨어 또는 클라우드 기반 HSM(하드웨어 보안 모듈)에 민감한 키를 보관한다.
* 언제나 사용 가능한 신뢰할 수 있는 암호화 알고리즘을 이용한다.
* 불필요한 민감 데이터는 저장하지 않는다. 저장할 시 가능한 빠르게 지우거나 PCI DSS 준수 토큰화(PCI DSS compliant tokenization) 이용 또는 마스킹 처리를 한다. 데이터가 보관되지 않으면 훔쳐질 수 없다.
* 모든 민감 데이터 암호화 되었는지 확인하라.
* 강한 표준 알고리즘, 프로토콜, 키가 최신 인지 확인하고 적절한 키 관리 시스템을 이용해라.
* 모든 데이터는 전달 시 전방향 보안(Forward secrecy), 암호 블록 체인(Cipher block chaining)에 대한 지원을 중단하고, 퀀텀 키 변경 알고리즘을 지원하는 TLS 1.2 버전 이상에서 암호화 되어야 한다. HTTP 스트릭 전송 보안(HTTP Strict Transport Security, HSTS) 을 이용해 HTTPS 강제 암호화를 하여야 한다. 모든 것을 도구를 이용해 검사하라.
* 민감 데이터가 들어있는 응답 값 캐싱을 비활성화한다. 이는 콘텐츠 전송 네트워크(CDN), 웹 서버 내 캐싱과 모든 애플리케이션 캐싱을 포함한다. (예시. 레디스(Redis))
* 매번의 데이터 분류 작업에서 요구된 보안 통제를 적용하라. 
* FTP 나 STARTTLS 같은 암호화되지 않은 프로토콜을 사용하지 마라. 기밀 정보 전달에 SMTP 사용을 피해라.
* 아라곤2(Argon2), 예스크립트(yescrypt, 스크립트(scrypt) 또는 PBKDF2-HMAC-SHA-512 같은 작업 인자(지연 인자라고도 함)과 강한 적응력(Adaptive)이 강구된  솔트 해싱 함수를 사용하라. 레거시 시스템을 위해 비크립트(bcrypt) 이용 시 [OWASP Cheat Sheet: Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) 을 참고하라.
  \* 적응력: 시간이 갈 수록 레인보우 테이블 생성에 많은 리소스가 사용되게 하는 능력
  \* 작업 인자: 계산 횟수를 증가시키는 것과 같이 해시 과정을 복잡하게 만드는 인자
* ////쑤쩡 초기화 벡터(IV)는 운영 모드에 따라 적절하게 선택되어야 하며, 이는 암호화적 보안 의사난수 생성기(cryptographically secure pseudo random number generator, CSPRNG) 사용을 의미할 수 있다. 해당 모드는 넌스값을 요구하며, 초기화 벡터는 CSPRNG가 필요하지 않다. 모든 케이스에서 초기화 벡터는 수정된 키에서 두번 이상 사용되지 않았다.///
* 일반 암호화보단 인증된 암호화를 사용해라.
* 키는 암호학적으로 랜덤하게 생성되며, 메모리 내 바이트 배열로써 저장되어야 한다. 만약 패스워드가 사용 중이라면, 이는 적절한 패스워드 기반 키 유도 함수를 통한 키로 변환된 상태여야 한다.
* 적절한 곳에서 암호학적 무작위성이 사용되는지와 낮은 엔트로피나 예측 가능한 시드가 사용되지 않는지 확인해라. 대다수의 현대 API는 개발자에게 CSPRNG에 보안을 설정할 것을 요구하지 않는다.
* MD5, SHA1, 암호 블록 체이닝 모드(CBC), PKCS number 1 v1.5. 같은 사용되지 않는 암호학 함수, 블록 빌딩 메소드, 패딩 스키마 사용을 피해라.
* 리뷰, 보안 전문가, 사용할 도구의 목적사항을 통해 설정 값이 보안 요구사항에 맞는지 확인해라.
* 양자 컴퓨터 이후의 암호학(PQC)을 준비해야 하며, 고위험 시스템은 2030년 전까지 반드시 안전하게 보호되도록 하여야 한다.(ENISA 참고)


## 공격 시나리오 예시. 

**시나리오 1**: A 사이트는 모든 페이지에 TLS 강제을사용하지 않거나 약한 암호화 알고리즘을 지원한다. 공격자는 네트워크 트래픽을 모니터링해 가로챈 요청에서 HTTPS에서 HTTP로 다운그레이드하여 사용자의 세션 쿠키를 가로챌 수 있다. 공격자는 세션 쿠키를 재전송해 사용자 세션을 하이재킹하여 사용자 개인 정보 접근 또는 변조가 가능하다. 위 내용 말고도 공격자는 전송되는 모든 데이터 변조가 가능하다. (예: 송금 수신자)

**시나리오 2**: 데이터베이스 내 패스워드는 솔트가 포함되지 않는 단순 해시로 모든 사용자의 패스워드를 저장한다. 파알 업로드 취약점으로 사용자 패스워드 해시값 탈취가 가능하고, 솔트가 포함되지 않는 해시는 사전 계산된 레인보우 테이블로 매핑하여 원본 패스워드 탈취가 가능하다. 간단하고 빠른 해시 함수로 생성한 해시는 GPU로 크랙 가능하며, 이는 솔트가 포함된 패스워드 또한 마찬가지다.
\* 솔트가 포함된 패스워드라 하더라도 공격자가 보유 중인 패스워드 사전 목록 또는 브루트 포싱을 이용해 레인보우 테이블을 생성해 패스워드 매핑 작업이 가능하다. 이를 방지하기 위해 대소문자, 특수문자, 숫자가 포함되고 사용자 인적사항과 관련없는 13자리 이상의 패스워드 사용을 권장하는 것이다.


## 참조.



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


## List of Mapped CWEs

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
