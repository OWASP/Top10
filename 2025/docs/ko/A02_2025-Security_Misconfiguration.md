# A02:2025 보안 설정 오류 ![icon](../assets/TOP_10_Icons_Final_Security_Misconfiguration.png){: style="height:80px;width:80px" align="right"}


## 배경.

지난 버전에서 3단계 상승해 2위로 올라왔으며, 테스트된 모든 애플리케이션에서 잘못된 설정 중 한가지 이상이 발견되었다. 이번 카테고리 내에서의 평균 취약점 발생률은 3% 이며, 총 CWE는 1,375개이고 71만 9천(719k)개가 넘는 취약점이 발견되었다. 최근 설정 가능한 소프트웨어 쪽으로 트렌드가 이동함에 따라 이번 카테고리 순위 변동은 크게 놀라울 만한 일이 아니다. 주목할만한 CWE로는 `CWE-16: 설정` 그리고 `CWE-611: XML 외부 엔티티 참조의 부적절한 제한(XXE)`가 있다.


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
   <td>평균 가중 악용도
   </td>
   <td>평균 가중 영향도
   </td>
   <td>총 발생 건수
   </td>
   <td>총 CVE 건수
   </td>
  </tr>
  <tr>
   <td>16
   </td>
   <td>27.70%
   </td>
   <td>3.00%
   </td>
   <td>100.00%
   </td>
   <td>52.35%
   </td>
   <td>7.96
   </td>
   <td>3.97
   </td>
   <td>719,084
   </td>
   <td>1,375
   </td>
  </tr>
</table>



## 설명.

보안 설정 오류은 보안 관점에서 시스템, 애플리케이션, 클라우드 서비스 설정이 잘못되어 취약점이 발생하는 것을 말한다.

다음과 같은 경우 애플리케이션은 취약할 수 있다.


* 애플리케이션 스택 전반에 적절한 보안 하드닝이 적용되지 않았거니, 클라우드 서비스 내 보안 설정이 잘못 구성되어 있는 경우.
* 불필요한 기능이 활성화 또는 설치된 경우. (예: 불필요 포트, 서비스, 페이지, 계정, 테스트 프레임워크 또는 권한)
* 기본 계정, 패스워드가 활성화되어 있거나 변경되지 않은 경우
* 과도한 에러메시지를 처리할 공통 설정이 부족하여 에러 처리 과정에서 스택 트레이스(Stack trace)나 과도한 에러 정보 메시지가 사용자에게 전달되는 경우.
* 업그레이드된 시스템에서 최신 보안 기능이 비활성화 되어 있거나 안전하게 설정되지 않은 경우.
* 이전 버전과의 호환성을 우선시하여 안전하지 않은 설정을 하는 경우.
* 애플리케이션 서버 내 보안 설정, 애플리케이션 프레임워크(예: 스트럿츠(Struts), 스프링(Spring), ASP.NET), 라이브러리, 데이터베이스 등에서 보안 설정이 되지 않은 경우.
* 서버가 보안 헤더 또는 지시문을 전달하지 않거나 안전하지 않은 설정 값으로 전달되는 경우.

일관되고 재사용 가능한 애플리케이션 보안 설정 하드닝 절차가 없다면 시스템은 더 높은 위험에 놓인다.


## 대응 방안.

다음과 같은 항목들을 포함하여 보안성이 반영된 구성 절차를 수립한다.

* 재사용 가능한 하드닝 프로세스를 구축하여 필요한 보안 통제가 적용된 동일한 형태의 신규 환경을 빠르고 쉽게 배포 가능해야 한다. 개발, QA, 운영 환경은 모두 동일한 구성으로 설정하며, 각각의 환경에서 서로 다른 자격증명을 사용한다. 이 프로세스는 자동화하여 요구되는 새로운 보안환경을 구성하는 데 필요한 노력을 최소화한다.
* 사용하지 않은 기능, 컴포넌트, 문서, 샘플을 포함하지 않는 최소한의 플랫폼을 구현한다. 사용하지 않는 기능과 프레임워크는 삭제하거나 설치되지 않아야 한다.
* 패치 관리 프로세스(참고: [A03 소프트웨어 공급망 체인 실패](A03_2025-Software_Supply_Chain_Failures.md)) 수행 시 모든 보안 공지, 업데이트, 패치에 따른 적절한 검토 및 업데이트를 한다. 또한, 클라우드 스토리지 권한(예: S3 버킷 권한)을 점검한다.
* 구성 요소 간 또는 테넌트 간 효과적으로 격리할 수 있도록 세분화, 컨테이너화, 클라우드 보안 그룹(ACL)을 활용해 애플리케이션 아키텍쳐를 설계함으로써 효과적이고 안전한 분리 구조를 보장한다.
* 보안 지시문을 클라이언트로 보내야 한다. (예: 보안 헤더)
* 자동화된 프로세스를 구축하여 모든 환경에서 해당 설정들의 안전성을 검증한다.
* 만일의 경우를 대비해, 과도한 에러 메시지가 사용자에게 노출되지 않도록 공통 설정을 사전에 구성한다.
* 만약 이런 검증사항들이 자동화되지 않았다면, 최소한 매년 1회는 수동으로 검증한다.
* 코드, 설정 파일, 파이프 라인 내 정적인 키나 시크릿을 저장하는 대신 플랫폼에서 제공하는 아이덴티티 페더레이션, 단기 유효 자격 증명, 또는 역할 기반 접근 매커니즘을 사용한다.


## 공격 시나리오 예시. 

**시나리오 1:** 운영 서버에서 테스트용 애플리케이션이 지워지지 않았다. 테스트용 애플리케이션은 공격자가 해당 서버를 공격할 수 있는 보안 취약점이 존재한다고 알려져 있으며, 그중 하나의 애플리케이션은 관리자용 콘솔이라 가정해 보겠다. 그리고 기본 계정은 변경되지 않았다. 이런 경우 공격자는 기본 계정으로 로그인 한 뒤 시스템 장악이 가능하다.

**시나리오 2:** 서버에서 디렉토리 리스팅이 활성화 되었을 때 공격자는 단순하게 디렉토리 목록을 탐색할 수 있다. 공격자는 컴파일된 자바 클래스들을 찾거나 다운로드 할 수 있고, 이런 클래스들을 디컴파일 하거나 리버싱 엔지니어링을 통해 코드를 볼 수 있다. 그 뒤 공격자는 애플리케이션 내에서 서버 접근 제어 취약점을 찾은 뒤 악용 가능하다.

**시나리오 3:** 사용자에게 반환되는 스택 트레이스(Stack trace) 같은 자세한 에러 메시지가 표시되도록 설정되어 있는 경우 민감한 정보나 해당 컴포넌트 버전에 알려진 취약점 같은 근본적 취약점이 노출될 가능성이 있다.

**시나리오 4:** 클라우드 서비스 제공자(Cloud service provider, CSP)는 인터넷에 자원을 공유하는 권한이 기본 설정이다. 이는 민감한 정보가 공개된 클라우드 스토리지 내 저장될 시 관계자 외 접근을 허용할 수 있다.


## 참조.

* [OWASP Testing Guide: Configuration Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)
* [OWASP Testing Guide: Testing for Error Codes](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)
* [Application Security Verification Standard V13 Configuration](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x22-V13-Configuration.md)
* [NIST Guide to General Server Hardening](https://csrc.nist.gov/publications/detail/sp/800-123/final)
* [CIS Security Configuration Guides/Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
* [Amazon S3 Bucket Discovery and Enumeration](https://blog.websecurify.com/2017/10/aws-s3-bucket-discovery.html)
* ScienceDirect: Security Misconfiguration

## 해당되는 보안 약점(CWE).

* [CWE-5 J2EE Misconfiguration: Data Transmission Without Encryption](https://cwe.mitre.org/data/definitions/5.html)

* [CWE-11 ASP.NET Misconfiguration: Creating Debug Binary](https://cwe.mitre.org/data/definitions/11.html)

* [CWE-13 ASP.NET Misconfiguration: Password in Configuration File](https://cwe.mitre.org/data/definitions/13.html)

* [CWE-15 External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html)

* [CWE-16 Configuration](https://cwe.mitre.org/data/definitions/16.html)

* [CWE-260 Password in Configuration File](https://cwe.mitre.org/data/definitions/260.html)

* [CWE-315 Cleartext Storage of Sensitive Information in a Cookie](https://cwe.mitre.org/data/definitions/315.html)

* [CWE-489 Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)

* [CWE-526 Exposure of Sensitive Information Through Environmental Variables](https://cwe.mitre.org/data/definitions/526.html)

* [CWE-547 Use of Hard-coded, Security-relevant Constants](https://cwe.mitre.org/data/definitions/547.html)

* [CWE-611 Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)

* [CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html)

* [CWE-776 Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')](https://cwe.mitre.org/data/definitions/776.html)

* [CWE-942 Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html)

* [CWE-1004 Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)

* [CWE-1174 ASP.NET Misconfiguration: Improper Model Validation](https://cwe.mitre.org/data/definitions/1174.html)
