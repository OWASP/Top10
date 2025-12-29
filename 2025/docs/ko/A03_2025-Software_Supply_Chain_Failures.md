# A03:2025 소프트웨어 공급망 체인 실패![icon](../assets/TOP_10_Icons_Final_Vulnerable_Outdated_Components.png){: style="height:80px;width:80px" align="right"}


## 배경.

이번 TOP 10 커뮤니티 조사에서 정확히 50%의 응답자가 1위로 선정되었다. 2013년 TOP 10에 "A9 - 서용 중인 컴포넌트 내 알려진 취약점" 에 처음 등장한 이후, 해당 위험은 "알려진 취약점" 외에도 모든 공급망 체인 실패를 포함하도록 범위가 확장되었다. 범위가 증가함에도 불구하고, 공급망 체인 실패는 11개의 보안 약점(CWE)와 관련된 보안 취약점(CVE)으로 식별하는데 어려움을 겪고 있다. 그러나, 수집한 데이터로부터 테스트 또는 제보받은 결과 이번 카테고리는 5.19% 라는 높은 평균 사고 발생률을 보였고, 관련된 CWE로는 CWE-447: 불필요한 기능 사용, CWE-1104: 유지되지 않은 외부 컴포넌트 사용, CWE-1329: 업데이트 할 수 없는 신뢰된 컴포넌트 사용, 그리고 CWE-1398: 취약한 외부 컴포넌트 의존이 있다.

## 점수표.


<table>
  <tr>
   <td>매칭된 보안약점(CWE)
   </td>
   <td>최대 취약점 발생률
   </td>
   <td>평균 취약점 발생률
   </td>
   <td>최대 테스트 커버리지
   </td>
   <td>평균 테스트 커버리지
   </td>
   <td>평균 가중 공격 가능성
   </td>
   <td>평균 가중 영향도
   </td>
   <td>총 발생 건수
   </td>
   <td>총 CVE 건수
   </td>
  </tr>
  <tr>
   <td>40
   </td>
   <td>20.15%
   </td>
   <td>3.74%
   </td>
   <td>100.00%
   </td>
   <td>42.93%
   </td>
   <td>7.04
   </td>
   <td>3.84
   </td>
   <td>1,839,701
   </td>
   <td>32,654
   </td>
  </tr>
</table>



## 설명.

소프트웨어 공급망 체인 실패는 소프트웨어 개발, 배포, 업데이트하는 과정에서 발생하는 침해사고, 중단을 의미합니다. 이는 주로 외부 코드, 도구, 시스템이 신뢰하는 의존성들에서 악의적인 변경이나 취약점이 원인이 된다.

다음과 같을 시 취약하다 판단할 수 있다.

* 사용하는 모든 컴포넌트 버전을 추적하는 않는 경우.(클라이언트, 서버 사이드 모두 포함하고 이에는 직접 사용하는 컴포넌트 뿐만 아니라 중첩되거나 전파된 의존성들도 포함한다.) 
* 소프트웨어가 취약하거나, 더이상 지원하지 않거나, 오래된 버전인 경우.(이는 OS, 웹/애플리케이션 서버, 데이터 베이스 관리 시스템(DBMS), 애플리케이션, API, 모든 컴포넌트, 런타임 환경 그리고 모든 라이브러리를 포함한다.)
* 주기적으로 취약점을 스캔하지 않거나 사용 중인 컴포넌트에 대한 보안 공지를 확인하지 않는 경우.
* 공급망 체인 내 관리 프로세스 또는 공급망 체인 변경에 대한 추적 (IDE 추적 포함) 기능이 없는 경우(IDE 확장 도구와 업데이트, 조직 내 코드 저장소 변경, 샌드박스, 이미지 또는 라이브러리 저장소, 생성 또는 저장되는 아티팩트 등). 모든 공급망 체인에 대한 영역은 문서화되어야 한다. (특히 변경에 관한 사항)
* 모든 공급망 체인 영역 대한 보안 강화 사항이 없는 경우 (특히 접근 제어, 애플리케이션 최소 권한).
* 공급망 체인 시스템에 직무 분리 사항이 없으니, 누구라도 다른 사람의 감독 없이 공급망 체인 내 코드를 작성하거나 프로덕션 환경에 배포되는 모든 과정을 진행해서는 안 된다.
* 신뢰할 수 없는 출처의 컴포넌트나 기술 스택이 프로덕션 환경에 영향을 미치는 경우
* 기반 플랫폼, 프레임워크, 의존성을 위험 기반으로 적시에 고치거나 업그레이드 하지 않는 경우. 이는 변경 관리를 월, 분기 단위 작업 환경에서 흔히 발생하며, 취약점을 고치기 전 조직에 불필요한 위험을 수일 또는 수개월 간 노출시킬 수 있다.
* 소프트웨어 개발자가 업데이트, 업그레이드, 라이브러리 패치의 확장성을 테스트하지 않는 경우.
* 시스템의 모든 영역의 설정에 보안성이 강구되지 않은 경우 (참고. [A02:2025-잘못된 보안 설정](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/))
* 시스템 개발, 배포보다 CI/CD 파이프 라인이 보안성이 약한 경우 (특히 파이프 라인이 복잡할 때)

## 방어.

패치 관리 프로세스 내 다음과 같은 사항이 포함되어야 한다.



* 전체 소프트웨어의 중앙 생성 및 관리가 가능한 소프트 웨어 구성 목록(SBOM).
* 직접적 의존성, 전파된 의존성 등 추적. (전파된 의존성 예시. 사용 중인 라이브러리에서 사용되는 의존성)
* 사용하지 않는 의존성, 불필요한 기능, 컴포넌트, 파일 그리고 문서를 지움으로써 공격 가능 범위 축소.
* OWASP Dependency Track, OWASP Dependency Check, retire.js 등과 같은 도구를 사용함으로써 클라이언트, 서버 사이드 컴포넌트 버전 지속 목록화.
* 사용 중인 컴포넌트에 대한 취약점들을 보안 취약점(CVE), 국제적 취약점 데이터 베이스(NVD), 오픈 소스 취약점(OSV) 을 통해 지속 모니터링. 이를 위해 소프트웨어 구성 분석, 소프트웨어 공급망 체인 또는 보안 집중된 소프트웨어 구성 목록(SBOM) 도구를 이용해 해당 프로세스 자동화가 가능하다. 또는 사용 중인 컴포넌트에 대한 보안 취약점 알림 구독을 통해서도 관리할 수 있다.
* 보안 링크를 통한 공식 소스와 컴포넌트 다운로드. 조작되거나 악성 컴포넌트로 변경되는 경우를 방지하기 위해 서명된 패키지 사용과 체크를 권고한다. (참고. [A08:2025-소프트웨어 그리고 데이터 무결성 실패](https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/))
* 사용할 의존성 버전 선택이 가능하고 필요할 때 업그레이드 할 수 있어야 한다.
* 유지되지 않거나 보안 패치가 이루어지지 않는 오래된 버전의 라이브러리, 컴포넌트 모니터링. 만약 패치가 가능하지 않다면 대안을 선택해야 하는 것을 고려해야 하며, 만약 이 또한 가능하지 않다면 가상 패치된 것을 배포하여 발견된 문제에 대해 모니터링, 탐지, 방어하는 방안을 고려하여야 한다.
* CI/CD, IDE, 기타 다른 개발 도구를 주기적으로 업데이트해야 한다.
* 모든 시스템에 대한 동시 업데이트를 하지 않아야 한다. 신뢰된 제조사가 침해된 경우를 대비하여 노출을 제한하기 위해 점진적 배포나 카나리 배포를 하여야 한다.

다음과 같은 변경 사항을 추적하기 위해 변경 관리 프로세스 또는 추적 시스템이 마련되어야 한다.

* CI/CD 설정 (모든 빌드 도구와 파이프 라인)
* 코드 저장소
* 샌드박스 영역
* 개발자 IDE
* 소프트웨어 구성 목록 도구(SBOM tooling)와 생성된 아티팩트
* 로깅 시스템과 로그
* 소프트웨어 서비스(Saas) 같은 통합된 외부 서비스
* 아티팩트 저장소
* 컨테이너 레지스트리(저장소)


다음과 같은 시스템의 경우 보안 강화를 해야하며, 이는 다중 인증(MFA)과 식별 접근 관리(IAM) 잠금을 포함한다.

* 코드 저장소 (백업, 보호된 브런치, 커밋된 민감 데이터를 포함한다.)
* 개발자 워크스테이션 (주기적 패치, 다중 인증(MFA), 모니터링)
* 빌드 서버와 CI/CD 서버 (직무 분리, 접근 제어, 서명된 빌드, 환경변수 내 민감 데이터, 조작된 증거 로그 등)
* 아티팩트 (무결성 보장을 위해 발신지, 서명, 타임 스탬프를 확인하고, 각각의 환경을 재구축하기 보단 아티팩트를 재배포한다. 또한 빌드가 변경 불가능한지 검증해야 한다.)
* 코드로서의 인프라 (모든 코드 관리, PR 사용과 버전 관리 포함)

모든 조직은 애플리케이션 생애주기 또는 포트폴리오와 관련된 진행 중인 계획에 대해 모니터링, 분류, 그리고 업데이트 적용 또는 설정 변경에 대해 검증하여야 한다.


## 공격 시나리오 예시.

**시나리오 1:** 신뢰된 제조사는 악성 프로그램(멀웨어)로 침해사고가 발생하였으며, 이는 우리 컴퓨터 시스템이 업그레이드 될 때 침해사고가 발생하는 결과로 이어진다. 유명한 예시는 다음과 같다.



* 2019년 솔러 윈즈 침해사고는 18,000개의 조직 침해사고로 이어졌다.[https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack](https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack)

**시나리오 2:** 신뢰된 제조사는 침해사고가 발생하였으며, 이는 특정 조건이 발생하면 동작하도록 되어 있다.



* 2025년에 바이빗은 15억 달러 상당을 탈취당했으며, 사고 이유는 [월렛 소프트웨어에서의 공급망 체인 공격](https://www.sygnia.co/blog/sygnia-investigation-bybit-hack/)으로 알려졌다. 이는 지갑이 사용될 때 악성행위가 동작하도록 설계되었다.

**시나리오 3:** 2025년에 발생한 [`Shai-Hulud` 공급망 체인 공격](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)은 첫번째로 성공한 자기 전파형 npm 웜이다. 공격자는 유명한 패키지에 악성 프로그램 버전을 배포하였으며, 이는 post-install 스크립트를 이용해 민감 정보를 퍼블릭 깃허브 저장소로 유출하거나 탈취하는 역할을 한다. 해당 멀웨어는 피해자 환경 내에서 npm 토큰을 탐지하여 이를 이용해 자동적으로 접근 가능한 패키지의 악성 버전을 푸시한다. 해당 웜은 npm에 의해 차단되기 전 500개가 넘는 패키지 버전에 영향을 미쳤다. 이번 공격망 체인 공격은 사전적이였으며, 빠르게 전파되고 심한 데미지가 있었다. 그리고 개발자가 목표가 됨으로써 개발자 스스로가 공급망 체인 공격을 위한 중요 타깃이 될 수 있다는 것을 증명하였다.

**시나리오 4:** 컴포넌트는 일반적으로 애플리케이션과 같은 권한으로 동작하여야 한다. 그래서 컴포넌트에 존재하는 취약점은 심각한 영향을 미치는 결과를 낳는다. 해당 취약점은 사고적이거나(예시. 코딩 에러), 고의적일 수 있다(예시. 컴포넌트 내 백도어). 몇개의 발견된 악용 가능한(exploitable) 컴포넌트 취약점은 다음과 같다. 

* CVE-2017-5638, 스트럿츠(Struts)에 2개의 원격 코드 실행 취약점이 발견되었으며, 이는 서버에 임의코드 실행이 가능한 심각한 보안 사고 원인으로 판별되었다.
* CVE-2021-44228 ("Log4Shell"), 아파치 Log4j 라이브러리에서 제로데이 원격코드 실행 취약점이 발견되었으며,  랜섬웨어, 크립토 채굴 그리고 다른 공격에 사용되는 원인으로 판별되었다.


## 참조

* [OWASP Application Security Verification Standard: V15 Secure Coding and Architecture](https://owasp.org/www-project-application-security-verification-standard/)
* [OWASP Cheat Sheet Series: Dependency Graph SBOM](https://cheatsheetseries.owasp.org/cheatsheets/Dependency_Graph_SBOM_Cheat_Sheet.html)
* [OWASP Cheat Sheet Series: Vulnerable Dependency Management](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html)
* [OWASP Dependency-Track](https://owasp.org/www-project-dependency-track/)
* [OWASP CycloneDX](https://owasp.org/www-project-cyclonedx/)
* [OWASP Application Security Verification Standard: V1 Architecture, design and threat modelling](https://owasp-aasvs.readthedocs.io/en/latest/v1.html)
* [OWASP Dependency Check (for Java and .NET libraries)](https://owasp.org/www-project-dependency-check/)
* OWASP Testing Guide - Map Application Architecture (OTG-INFO-010)
* [OWASP Virtual Patching Best Practices](https://owasp.org/www-community/Virtual_Patching_Best_Practices)
* [The Unfortunate Reality of Insecure Libraries](https://www.scribd.com/document/105692739/JeffWilliamsPreso-Sm)
* [MITRE Common Vulnerabilities and Exposures (CVE) search](https://www.cve.org)
* [National Vulnerability Database (NVD)](https://nvd.nist.gov)
* [Retire.js for detecting known vulnerable JavaScript libraries](https://retirejs.github.io/retire.js/)
* [GitHub Advisory Database](https://github.com/advisories)
* Ruby Libraries Security Advisory Database and Tools
* [SAFECode Software Integrity Controls (PDF)](https://safecode.org/publication/SAFECode_Software_Integrity_Controls0610.pdf)
* [Glassworm supply chain attack](https://thehackernews.com/2025/10/self-spreading-glassworm-infects-vs.html)
* [PhantomRaven supply chain attack campaign](https://thehackernews.com/2025/10/phantomraven-malware-found-in-126-npm.html)


## 매핑된 보안 약점(CWE) 목록

* [CWE-447 Use of Obsolete Function](https://cwe.mitre.org/data/definitions/447.html)

* [CWE-1035 2017 Top 10 A9: Using Components with Known Vulnerabilities](https://cwe.mitre.org/data/definitions/1035.html)

* [CWE-1104 Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html)

* [CWE-1329 Reliance on Component That is Not Updateable](https://cwe.mitre.org/data/definitions/1329.html)

* [CWE-1357 Reliance on Insufficiently Trustworthy Component](https://cwe.mitre.org/data/definitions/1357.html)

* [CWE-1395 Dependency on Vulnerable Third-Party Component](https://cwe.mitre.org/data/definitions/1395.html)
