# A08:2025 소프트웨어 또는 데이터 무결성 실패 ![icon](../assets/TOP_10_Icons_Final_Software_and_Data_Integrity_Failures.png){: style="height:80px;width:80px" align="right"}

## 배경.

소프트웨어 또는 데이터 무결성 실패는 8위를 유지했으며, "소프트웨어 *및* 데이터 무결성 실패"에서 약간의 명확화를 위해 명칭이 소폭 변경되었다. 해당 카테고리는 소프트웨어 공급망 실패(Software Supply Chain Failures)보다 더 하위 수준에서, 신뢰 경계를 유지하지 못하고 소프트웨어, 코드, 데이터 아티팩트의 무결성을 검증하지 못하는 문제에 초점을 둔다. 즉, 무결성을 확인하지 않은 채 소프트웨어 업데이트와 중요 데이터에 대해 가정하는 행위를 다룬다. 대표적인 CWE로는 *CWE-829: 신뢰할 수 없는 통제 영역에서 기능 포함(Inclusion of Functionality from Untrusted Control Sphere)*, *CWE-915: 동적-결정 객체 속성의 부적절하게 통제된 수정(Improperly Controlled Modification of Dynamically-Determined Object Attributes)*, *CWE-502: 신뢰할 수 없는 데이터의 역직렬화(Deserialization of Untrusted Data)*가 있다.


## 점수 표.


<table>
  <tr>
   <td>매핑된 CWE 수
   </td>
   <td>최대 발생률
   </td>
   <td>평균 발생률
   </td>
   <td>최대 커버리지
   </td>
   <td>평균 커버리지
   </td>
   <td>평균 가중 악용
   </td>
   <td>평균 가중 영향
   </td>
   <td>총 발생 건수
   </td>
   <td>총 CVE 수
   </td>
  </tr>
  <tr>
   <td>14
   </td>
   <td>8.98%
   </td>
   <td>2.75%
   </td>
   <td>78.52%
   </td>
   <td>45.49%
   </td>
   <td>7.11
   </td>
   <td>4.79
   </td>
   <td>501,327
   </td>
   <td>3,331
   </td>
  </tr>
</table>



## 설명.

소프트웨어 및 데이터 무결성 실패는 유효하지 않거나 신뢰할 수 없는 코드 또는 데이터가 신뢰할 수 있고 유효한 것으로 취급되는 것을 방지하지 못하는 코드 및 인프라와 관련된다. 예를 들어, 애플리케이션이 신뢰할 수 없는 출처, 저장소, 콘텐츠 전송 네트워크(CDN)에서 제공되는 플러그인, 라이브러리, 모듈에 의존하는 경우가 이에 해당한다. 소프트웨어 무결성 검증을 수행하지 않거나 제공하지 않는 불안전한 CI/CD 파이프라인은 비인가 접근, 불안전하거나 악의적인 코드, 또는 시스템 손상으로 이어질 잠재적 위험을 초래할 수 있다. 또 다른 예로, CI/CD가 신뢰할 수 없는 장소에서 코드나 아티팩트를 가져오고, 사용 전에 서명 확인 등 유사한 메커니즘으로 이를 검증하지 않는 경우가 있다. 마지막으로, 많은 애플리케이션에는 자동 업데이트 기능이 포함되어 있는데, 업데이트가 충분한 무결성 검증 없이 다운로드되어 기존에 신뢰하던 애플리케이션에 그대로 적용되는 경우가 있다. 이런 구조에서는 공격자가 자신의 업데이트를 업로드해 이를 모든 설치본에 배포, 실행되도록 만들 수 있다. 또 다른 예로, 객체나 데이터가 공격자가 확인하고 수정할 수 있는 형태로 인코딩되거나 직렬화된 경우, 불안전한 역직렬화(insecure deserialization)에 취약해질 수 있다.

## 예방 방법.



* 디지털 서명 또는 유사한 메커니즘을 사용하여 소프트웨어나 데이터가 예상된 출처에서 왔고 변조되지 않았음을 검증한다.
* npm이나 Maven과 같은 라이브러리 및 의존성이 신뢰할 수 있는 저장소만 사용하도록 보장한다. 위험 수준이 더 높다면, 잘 검증된 내부 저장소를 호스팅하는 방안을 고려한다.
* 악의적인 목적의 코드 또는 설정이 소프트웨어 파이프라인에 유입될 가능성을 최소화하기 위해, 코드 및 설정 변경에 대한 검토 절차를 마련한다.
* 빌드 및 배포 과정에서 흐르는 코드의 무결성을 보장할 수 있도록, CI/CD 파이프라인에 적절한 분리(격리), 구성, 접근 제어를 적용한다.
* 서명되지 않았거나 암호화되지 않은 직렬화 데이터가 신뢰할 수 없는 클라이언트로부터 수신된 뒤, 변조 또는 재전송(replay)을 탐지하기 위한 무결성 검사나 디지털 서명 없이 사용되지 않도록 보장한다.


## 공격 시나리오 예시.

**시나리오 #1 신뢰할 수 없는 외부 웹 기능 연동:** 한 회사가 고객 지원 기능을 제공받기 위해 외부 서비스 제공업체를 사용한다. 편의상 `myCompany.SupportProvider.com`을 `support.myCompany.com`으로 DNS 매핑해 두었다. 그 결과 `myCompany.com` 도메인에 설정된 모든 쿠키(인증 쿠키 포함)가 이제 고객 지원 제공업체로 전송된다. 고객 지원 제공업체의 인프라에 접근할 수 있는 누구든 `support.myCompany.com`을 방문한 모든 사용자의 쿠키를 탈취하여 세션 하이재킹 공격을 수행할 수 있다.

**시나리오 #2 서명 없이 업데이트:** 많은 가정용 라우터, 셋톱박스, 장치 펌웨어 등은 업데이트를 위해 서명된 펌웨어를 사용하지 않는다. 서명되지 않은 펌웨어는 공격자에게 점점 더 매력적인 표적이 되고 있으며, 앞으로도 악화될 것으로 예상된다. 이는 대개 향후 버전에서 수정한 뒤 이전 버전이 자연스럽게 사라질 때까지 기다려야 수밖에 없는 경우가 많다는 점에서 큰 우려 사항이다.

**시나리오 #3 신뢰할 수 없는 출처의 패키지 사용:** 한 개발자가 찾고 있는 패키지의 최신 버전을 구하기 어렵자, 일반적으로 사용하는 신뢰할 수 있는 패키지 관리자가 아니라 온라인 웹사이트에서 패키지를 다운로드한다. 해당 패키지는 서명되어 있지 않으므로 무결성을 보장할 방법이 없다. 해당 패키지에는 악의적인 코드가 포함되어 있다.

**시나리오 #4 불안전한 역직렬화:** 한 React 애플리케이션이 여러 Spring Boot 마이크로서비스를 호출한다. 함수형 프로그래밍을 지향하던 이들은 코드의 불변성을 보장하려고 했다. 그들이 선택한 해결책은 사용자 상태를 직렬화하여 각 요청마다 이를 주고받는 것이었다. 공격자는 (base64로 인코딩된) "rO0" 자바 객체 시그니처를 발견하고, [Java Deserialization Scanner](https://github.com/federicodotta/Java-Deserialization-Scanner)를 사용해 애플리케이션 서버에서 원격 코드 실행(RCE)을 획득한다.

## 참조.

* [OWASP 치트 시트: 소프트웨어 공급망 보안](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html)
* [OWASP 치트 시트: 코드형 인프라(Infrastructure as Code)](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html)
* [OWASP 치트 시트: 역직렬화(Deserialization)](https://wiki.owasp.org/index.php/Deserialization_Cheat_Sheet)
* [SAFECode 소프트웨어 무결성 통제(Software Integrity Controls)](https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)
* [‘최악의 악몽’ 사이버 공격: SolarWinds 해킹의 알려지지 않은 이야기](https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack)
* [CodeCov Bash Uploader 침해 사고](https://about.codecov.io/security-update)
* [Julien Vehent의 『Securing DevOps』](https://www.manning.com/books/securing-devops)
* [Tenendo: 불안전한 역직렬화(Insecure Deserialization)](https://tenendo.com/insecure-deserialization/)


## 매핑된 CWE 목록

* [CWE-345 데이터 진정성에 대한 불충분한 검증(Insufficient Verification of Data Authenticity)](https://cwe.mitre.org/data/definitions/345.html)

* [CWE-353 무결성 검사 지원 누락(Missing Support for Integrity Check)](https://cwe.mitre.org/data/definitions/353.html)

* [CWE-426 신뢰할 수 없는 검색 경로(Untrusted Search Path)](https://cwe.mitre.org/data/definitions/426.html)

* [CWE-427 통제되지 않은 검색 경로 요소(Uncontrolled Search Path Element)](https://cwe.mitre.org/data/definitions/427.html)

* [CWE-494 무결성 검사 없이 코드 다운로드(Download of Code Without Integrity Check)](https://cwe.mitre.org/data/definitions/494.html)

* [CWE-502 신뢰할 수 없는 데이터의 역직렬화(Deserialization of Untrusted Data)](https://cwe.mitre.org/data/definitions/502.html)

* [CWE-506 악성 코드 내장(Embedded Malicious Code)](https://cwe.mitre.org/data/definitions/506.html)

* [CWE-509 악성 코드 복제(바이러스 또는 웜)(Replicating Malicious Code (Virus or Worm))](https://cwe.mitre.org/data/definitions/509.html)

* [CWE-565 검증 및 무결성 검사 없이 쿠키에 의존(Reliance on Cookies without Validation and Integrity Checking)](https://cwe.mitre.org/data/definitions/565.html)

* [CWE-784 보안 의사결정에서 검증 및 무결성 검사 없이 쿠키에 의존(Reliance on Cookies without Validation and Integrity Checking in a Security Decision)](https://cwe.mitre.org/data/definitions/784.html)

* [CWE-829 신뢰할 수 없는 통제 영역(Control Sphere)에서 기능 포함(Inclusion of Functionality from Untrusted Control Sphere)](https://cwe.mitre.org/data/definitions/829.html)

* [CWE-830 신뢰할 수 없는 출처로부터의 웹 기능 포함(Inclusion of Web Functionality from an Untrusted Source)](https://cwe.mitre.org/data/definitions/830.html)

* [CWE-915 동적으로 결정되는 객체 속성의 부적절하게 통제된 수정(Improperly Controlled Modification of Dynamically-Determined Object Attributes)](https://cwe.mitre.org/data/definitions/915.html)

* [CWE-926 Android 애플리케이션 컴포넌트의 부적절한 내보내기(Improper Export of Android Application Components)](https://cwe.mitre.org/data/definitions/926.html)
