# A03:2025 소프트웨어 공급망 실패 ![icon](../assets/TOP_10_Icons_Final_Vulnerable_Outdated_Components.png){: style="height:80px;width:80px" align="right"}


## 배경

소프트웨어 공급망 실패는 TOP 10 커뮤니티 조사에서 정확히 50%의 응답자가 1위로 선정하였다. 2013년 TOP 10에 "A9 - 사용 중인 컴포넌트 내 알려진 취약점"으로 처음 등장한 이후, 해당 카테고리는 "알려진 취약점" 외에도 "모든 공급망 실패"를 포함하도록 범위가 확장되었다. 범위가 확대됨에도 불구하고, 공급망 실패는 여전히 식별이 어려우며, 관련 CWE와 매핑된 CVE가 11개에 불과하다. 그러나, 수집한 데이터를 테스트하고 보고한 결과에 따르면 이번 카테고리는 5.19%라는 가장 높은 평균 발생률을 보였고, 관련된 CWE로는 *CWE-477: 더 이상 사용되지 않는 기능 사용*, *CWE-1104: 관리되지 않은 외부 컴포넌트 사용*, *CWE-1329: 업데이트할 수 없는 컴포넌트에 대한 의존*, 그리고 *CWE-1395: 취약한 외부 컴포넌트 의존*이 있다.

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
   <td>6
   </td>
   <td>9.56%
   </td>
   <td>5.72%
   </td>
   <td>65.42%
   </td>
   <td>27.47%
   </td>
   <td>8.17
   </td>
   <td>5.23
   </td>
   <td>215,248
   </td>
   <td>11
   </td>
  </tr>
</table>



## 설명

소프트웨어 공급망 실패는 소프트웨어를 개발, 배포, 업데이트하는 과정에서 발생하는 장애 또는 침해를 의미한다. 이는 주로 외부 코드, 도구, 시스템이 신뢰하는 의존성이 악의적으로 변조되거나 의존성에 존재하는 취약점이 원인이 된다.

다음과 같은 경우 취약하다.

* 사용하는 모든 컴포넌트(클라이언트 측, 서버 측 모두) 버전을 추적하지 않는 경우. 여기에서 컴포넌트는 직접 사용하는 컴포넌트뿐만 아니라 중첩 의존성(중첩 전이 의존성)도 포함한다.
* 소프트웨어가 취약하거나, 더 이상 지원하지 않거나, 오래된 버전인 경우. 이는 OS, 웹/애플리케이션 서버, 데이터베이스 관리 시스템(DBMS), 애플리케이션, API, 모든 컴포넌트, 런타임 환경 그리고 모든 라이브러리를 포함한다.
* 사용 중인 컴포넌트에 대해 주기적으로 취약점을 스캔하지 않거나 보안 공지를 구독하지 않는 경우.
* 공급망의 변경을 관리하는 절차가 없거나, 변경 이력을 추적하지 못하는 경우. 여기에는 사용 중인 IDE와 IDE 확장 프로그램(extension) 및 업데이트를 추적하는 것, 조직의 코드 저장소에서 발생하는 변경 사항, 샌드박스, 이미지 및 라이브러리 저장소, 아티팩트가 생성되고 보관되는 방식 등도 모두 포함된다. 공급망을 이루는 모든 요소는 문서화되어야 하며, 특히 변경 사항은 반드시 기록으로 남겨야 한다.
* 공급망에 대한 모든 영역에 보안 하드닝이 없는 경우. 특히 접근 제어 부분과 애플리케이션 최소 권한 원칙 적용을 신경 쓰지 않은 경우.
* 공급망 시스템에 직무 분리가 없는 경우. 다른 사람의 검토와 승인 없이 작성된 코드를 운영 환경에 배포해서는 안 된다.
* 기술 스택의 어느 계층에서든 신뢰할 수 없는 출처의 컴포넌트가 사용되고 있거나, 이에 따라 운영 환경이 영향받는 경우.
* 기반이 되는 플랫폼, 프레임워크, 의존성을 위험도에 따라 또는 적시에 수정하거나 업그레이드하지 않는 경우. 이는 보통 변경 관리 절차 때문에 패치를 매월, 매 분기 단위로 작업할 때 흔히 발생하며, 취약점 조치 전까지 조직에 불필요한 위험을 수일 또는 수개월간 노출할 수 있다.
* 소프트웨어 개발자가 업데이트, 업그레이드, 패치된 라이브러리의 호환성을 테스트하지 않는 경우.
* 시스템의 모든 구성 요소에 대한 설정이 안전하지 않은 경우. (참고. [A02:2025-보안 설정 오류](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/))
* CI/CD 파이프라인의 보안이 빌드하고 배포하는 시스템보다 취약한 경우, 특히 파이프라인이 복잡할수록 취약하다.

## 대응 방안

패치 관리 프로세스 내 다음과 같은 사항이 포함되어야 한다.



* 전체 소프트웨어에 대한 소프트웨어 자재 명세서(Software Bill of Materials, SBOM)를 중앙에서 생성 및 관리한다.
* 직접 추가한 의존성만 추적할 것이 아니라, 그 의존성의 (전이) 의존성, 그리고 그다음 단계 의존성까지 추적한다.
* 사용하지 않는 의존성, 불필요한 기능, 컴포넌트, 파일 그리고 문서를 지움으로써 공격 표면을 축소한다.
* OWASP Dependency Track, OWASP Dependency Check, retire.js 등과 같은 도구를 활용해서 클라이언트 측과 서버 측 컴포넌트(예: 프레임워크, 라이브러리) 및 그 의존성의 버전 정보를 지속적으로 목록화한다.
* 사용 중인 컴포넌트에 대한 취약점들을 CVE(Common Vulnerabilities and Exposures), 미국 정부가 운영하는 취약점 데이터베이스(National Vulnerability Database), [OSV(Open Source Vulnerabilities)](https://osv.dev/)와 같은 출처를 지속적으로 모니터링한다. 이를 위해 소프트웨어 구성 분석(software composition analysis, SCA) 도구, 소프트웨어 공급망 도구, 보안에 초점이 맞춰진 SBOM 도구를 사용해 이 과정을 자동화한다. 사용 중인 컴포넌트와 관련된 보안 취약점 알림을 구독한다.
* 공식(신뢰할 수 있는) 출처에서 암호화가 적용된 링크를 통해서만 컴포넌트를 획득한다. 변조되었거나 악성 컴포넌트가 포함될 가능성을 줄이기 위해 서명된 패키지를 우선시한다. (참고. [A08:2025-소프트웨어, 데이터 무결성 실패](https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/))
* 의존성의 어떤 버전을 사용할지 의도적으로 선택하고, 필요가 있을 때만 업그레이드한다.
* 관리되지 않거나 보안 패치가 이루어지지 않는 오래된 버전의 라이브러리, 컴포넌트 사용 여부를 모니터링한다. 만약 패치가 불가능하다면 대체품으로 마이그레이션하는 것을 고려한다. 그것 또한 불가능하다면 가상 패치(virtual patch)를 적용해 발견된 문제에 대해 모니터링, 탐지, 방어하는 방안을 고려한다.
* CI/CD, IDE, 기타 개발 도구를 주기적으로 업데이트한다.
* 모든 시스템에 업데이트를 동시에 배포하는 것을 피한다. 신뢰하는 벤더가 침해된 경우를 대비하여 공격의 영향을 제한하기 위해 점진적 배포나 카나리 배포를 수행한다.

다음과 같은 항목의 변경 사항을 추적하기 위해 변경 관리 프로세스 또는 추적 시스템을 마련한다.

* CI/CD 설정(모든 빌드 도구와 파이프라인)
* 코드 저장소
* 샌드박스 영역
* 개발자 IDE
* 소프트웨어 자재 명세서(SBOM) 도구와 생성된 아티팩트
* 로깅 시스템과 로그
* SaaS 등 외부 서비스와의 연동
* 아티팩트 저장소
* 컨테이너 레지스트리


다음과 같은 시스템을 하드닝한다. 하드닝에는 MFA를 활성화하고 IAM의 권한을 제한하는 조치가 포함된다.

* 코드 저장소: 시크릿 커밋 금지, 브랜치 보호, 백업 설정
* 개발자 워크스테이션: 주기적 패치, 다중 인증(MFA), 모니터링 등
* 빌드 서버와 CI/CD 서버: 직무 분리, 접근 제어, 서명된 빌드, 환경변수 내 시크릿, 변조 감지 로그(tamper-evident log) 등
* 아티팩트: 프로비넌스(provenance), 서명, 타임스탬프를 통해 무결성을 보장. 환경마다 재빌드하지 않고 동일한 아티팩트를 사용, 빌드의 불변성 보장
* 코드형 인프라(Infrastructure as Code): 다른 모든 코드와 마찬가지로 PR과 버전 관리를 포함해 코드로 관리

모든 조직은 해당 애플리케이션 또는 포트폴리오의 생명 주기 동안, 업데이트나 설정 변경 사항을 계속 감시하고 중요도를 판단해 우선순위를 정한 뒤 적시에 반영할 수 있는 상시적인 운영 계획을 갖춰야 한다.

## 공격 시나리오 예시

**시나리오 1:** 신뢰하는 벤더가 악성코드에 감염되어, 업데이트하는 과정에서 내부 시스템까지 침해되는 경우. 가장 유명한 사례는 다음과 같다.

* 2019년에 발생한 솔라윈즈(Solarwinds) 침해 사고로 약 18,000개 조직이 침해된 사례. [https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack](https://www.npr.org/2021/04/16/985439655/a-worst-nightmare-cyberattack-the-untold-story-of-the-solarwinds-hack)

**시나리오 2:** 신뢰하는 벤더가 침해되어, 특정 조건에서만 악성 행위가 동작하는 경우.

* 2025년에 바이빗(Bybit)은 [월렛 소프트웨어에서의 공급망 공격](https://www.sygnia.co/blog/sygnia-investigation-bybit-hack/)으로 15억 달러가량을 탈취당했다. 해당 공격은 표적 월렛이 사용될 때만 실행되도록 작동했다.

**시나리오 3:** 2025년에 발생한 [`Shai-Hulud` 공급망 공격](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)은 최초로 성공한 자기복제형 npm 웜이다. 공격자는 인기 패키지에 악성코드를 심어 배포했으며, 이 패키지들은 post-install 스크립트를 통해 민감 정보를 수집하여 공개된 GitHub 저장소로 유출했다. 해당 악성코드는 피해자 환경에서 npm 토큰을 탐지하고, 이를 이용해 접근할 수 있는 모든 패키지에 자동으로 악성 버전을 배포했다. 이 웜은 npm에 의해 차단되기 전까지 500개 이상의 패키지에 확산했다. 이 공급망 공격은 고도화된 공격이며 빠르게 전파되어 심각한 피해를 줬으며, 개발자 환경을 직접 표적으로 삼아 개발자 자신이 공급망 공격의 주요 대상이 될 수 있음을 보여주었다.

**시나리오 4:** 컴포넌트는 일반적으로 애플리케이션과 동일한 권한으로 실행되므로, 컴포넌트의 취약점이 있으면 심각한 영향을 미칠 수 있다. 이러한 취약점은 우발적(예: 코딩 에러)이거나, 의도적(예: 컴포넌트 내 백도어)일 수 있다. 지금까지 발견된 악용 가능한 컴포넌트 취약점 사례는 다음과 같다. 

* CVE-2017-5638: Struts 2의 원격 코드 실행 취약점으로, 서버에서 임의 코드 실행 가능하여 다수의 심각한 침해 사고의 원인이 되었다.
* CVE-2021-44228("Log4Shell"): Apache Log4j의 제로데이 원격 코드 실행 취약점으로, 랜섬웨어, 암호화폐 채굴 등 다양한 공격 캠페인에 악용되었다.


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


## 해당되는 CWE

* [CWE-477 Use of Obsolete Function](https://cwe.mitre.org/data/definitions/477.html)

* [CWE-1035 2017 Top 10 A9: Using Components with Known Vulnerabilities](https://cwe.mitre.org/data/definitions/1035.html)

* [CWE-1104 Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html)

* [CWE-1329 Reliance on Component That is Not Updateable](https://cwe.mitre.org/data/definitions/1329.html)

* [CWE-1357 Reliance on Insufficiently Trustworthy Component](https://cwe.mitre.org/data/definitions/1357.html)

* [CWE-1395 Dependency on Vulnerable Third-Party Component](https://cwe.mitre.org/data/definitions/1395.html)
