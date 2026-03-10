# A06:2025 안전하지 않은 설계 ![icon](../assets/TOP_10_Icons_Final_Insecure_Design.png){: style="height:80px;width:80px" align="right"}


## 배경 

안전하지 않은 설계는 **[A02:2025-보안 설정 오류](A02_2025-Security_Misconfiguration.md)**와 **[A03:2025-소프트웨어 공급망 실패](A03_2025-Software_Supply_Chain_Failures.md)**가 이를 추월함에 따라, 순위에서 4위에서 6위로 두 칸 하락했다. 이 카테고리는 2021년에 도입되었으며, 이후 업계 전반에서 위협 모델링의 적용이 확대되고 보안 설계에 대한 강조가 강화되는 등 눈에 띄는 개선이 관찰되었다. 이 카테고리는 설계 및 아키텍처 결함과 관련된 위험에 초점을 맞추며, 더 많은 위협 모델링, 안전한 설계 패턴, 그리고 레퍼런스 아키텍처 사용을 요구한다. 이 카테고리에는 비즈니스 로직 취약점도 포함된다. 예를 들어, 애플리케이션이 가질 수 있는 단계(상태)와 각 단계가 서로 바뀔 수 있는 조건을 명확히 정의하지 않으면, 예상치 못한 변경을 유도하여 시스템을 공격할 수 있다. 커뮤니티 차원에서 코딩 단계의 "시프트-레프트(shift-left)"에 머무르지 않고, 설계상 안전(Secure by Design, SbD)의 원칙에 중요하게 기여하는 코딩 이전의 활동(예: 요구사항 작성 및 애플리케이션 설계)까지 확장해야 한다. 이를 위해 **[현대적 애플리케이션 보안 체계 수립: 기획 및 설계 단계](0x03_2025-Establishing_a_Modern_Application_Security_Program.md)**를 참고한다. 대표적인 CWE로는 *CWE-256: 자격 증명 저장 보호 미흡, CWE-269: 권한 관리 오류, CWE-434: 위험한 파일 형식 업로드 제한 미흡, CWE-501: 신뢰 경계 위반, 그리고 CWE-522: 자격 증명 보호 불충분*이 있다.



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
   <td>39
   </td>
   <td>22.18%
   </td>
   <td>1.86%
   </td>
   <td>88.76%
   </td>
   <td>35.18%
   </td>
   <td>6.96
   </td>
   <td>4.05
   </td>
   <td>729,882
   </td>
   <td>7,647
   </td>
  </tr>
</table>



## 설명 

안전하지 않은 설계는 다양한 유형의 약점을 포괄하는 범주로, 주로 "누락되었거나 비효과적인 통제 설계"로 나타난다. 또한 이 카테고리가 다른 모든 Top 10 위험의 근본 원인이라고 보기는 어렵다. 안전하지 않은 설계와 안전하지 않은 구현은 차이가 있어 구분되어야 하며, 설계 결함과 구현 결함은 근본 원인이 다르며, 개발 과정에서의 발생 시점이 다르고, 그리고 개선 방법도 다르다. 안전한 설계를 하더라도 구현상 결함을 가질 수 있으며, 이에 따라 취약점이 발생할 수 있다. 안전하지 않은 설계는 필요한 보안 통제가 특정 공격에 대해 방어하기 위해 대비되지 않았기 때문에, 완벽한 구현만으로는 수정될 수 없다. 안전하지 않은 설계의 원인 중 하나는 개발 대상 소프트웨어 및 시스템에 대한 비즈니스 리스크 프로파일링이 부족한 것이며, 그 결과 요구되는 보안 설계 수준을 적절히 산정하지 못하는 것이다.

보안 설계를 갖추기 위한 세 가지 핵심 구성요소는 다음과 같다.

* 요구사항 수집 및 리소스 관리
* 안전한 설계 수립
* 보안 개발 생명 주기(Secure Development Lifecycle, SDLC) 보유


### 요구사항 수집 및 리소스 관리

비즈니스 부서와 협업하여 애플리케이션의 비즈니스 요구사항을 수집 및 조율하며, 모든 데이터 자산과 예상되는 비즈니스 로직에 대해 기밀성, 무결성, 가용성, 인증성 관점의 보호 요구사항을 함께 정의한다. 애플리케이션의 대외 노출 수준을 고려하고, 그리고 단순 접근 제어 수준을 넘어서는 테넌트 격리가 필요한지 고려한다. 기능 요구사항뿐 아니라 비기능 보안 요구사항까지 포함해 기술 요구사항을 정리한다. 또한, 보안 활동을 포함한 설계, 구축, 테스트, 운영 전반을 포괄하는 예산을 계획하고 협의한다.


### 안전한 설계

안전한 설계는 지속적으로 위협을 평가하고, 알려진 공격 기법을 방지하기 위해 코드가 견고하게 설계되고 테스트 되도록 보장하는 문화이자 방법론이다. 위협 모델링은 요구사항 개선 단계(혹은 유사한 활동)에 내재화되어야 하며, 이 과정에서 데이터 흐름과 접근 제어 또는 기타 보안 통제의 변화를 중심으로 검토해야 한다. 유저 스토리를 작성할 때 정상 흐름과 실패 흐름을 결정하고, 책임 당사자 및 영향받는 당사자가 이를 충분히 이해하고 합의했는지 확인한다. 또한 정상과 실패 흐름에 대한 가정과 조건을 분석하여 정확하고 바람직한 상태로 유지되는지 확인한다. 올바른 동작을 위해 필요한 가정과 조건을 어떻게 검증하고 강제할지 결정한다. 이 결과는 유저 스토리에 문서화되어야 한다. 과정 중에 발생하는 실수로부터 학습하고, 개선을 촉진하기 위해 긍정적 인센티브를 제공한다. 마지막으로, 안전한 설계는 개발이 완료된 이후에 추가할 수 있는 부가 기능도 아니고 도구도 아니다.


### 보안 개발 생명 주기

안전한 소프트웨어에는 보안 개발 생명 주기, 안전한 설계 패턴, 포장된 도로(가장 쉽고 선호되는 방법이 동시에 가장 안전한 방법이 되도록 하는 것) 방법론, 안전한 컴포넌트 라이브러리, 적절한 도구, 위협 모델링, 그리고 프로세스를 개선하기 위해 사용되는 사고 포스트모템(post-mortem)이 필요하다. 소프트웨어 프로젝트 초기부터 보안 전문가와 협업하고, 개발 전체 과정 및 소프트웨어 유지보수 단계에서도 지속적으로 협업해야 한다. 보안 개발 활동을 체계화하기 위해 [OWASP 소프트웨어 보증 성숙도 모델(Software Assurance Maturity Model, SAMM)](https://owaspsamm.org/)와 같은 성숙도 모델을 참고하는 방안을 고려한다.

개발자가 보안에 대해 주도적으로 책임져야 한다는 인식이 종종 부족하다. 보안 인식과 책임감을 강화하고, 위험을 사전에 완화하려는 문화를 조성한다. 보안에 관한 정기적인 교류(예: 위협 모델링 세션 도중)는 모든 중요한 설계 의사결정에 보안을 포함시키기 위한 마인드셋을 형성할 수 있다.   


## 대응 방안


* 보안 및 프라이버시 관련 통제를 평가하고 설계하는 데 도움받기 위해 애플리케이션 보안 전문가와 함께 안전한 개발 생명 주기(SDLC)를 수립하고 운영한다.
* 안전한 설계 패턴과 포장된 도로 컴포넌트를 라이브러리화하여 사용한다.
* 인증, 접근 제어, 비즈니스 로직, 핵심 처리 흐름과 같은 애플리케이션의 중요한 부분을 위협 모델링한다.
* 보안 마인드셋을 생성하기 위한 교육 도구로서 위협 모델링을 사용한다.
* 유저 스토리에 보안 요구사항과 보안 통제를 반영한다.
* 애플리케이션의 각 계층(프론트엔드부터 백엔드까지)에 요청과 데이터가 타당한지 검증하는 절차를 추가한다.
* 위협 모델에 기반해 핵심 흐름이 안전한지 검증하는 단위 및 통합 테스트를 구현하고, 애플리케이션 계층별 정상 시나리오*와* 악용 시나리오를 취합한다.
* 외부 노출 수준과 보호 필요도에 따라 시스템 및 네트워크 레벨에서 분리한다.
* 전 계층에 걸쳐 설계 단계부터 테넌트 격리를 강하게 보장한다.
* 전 계층에서 테넌트를 구조적으로 격리되도록 한다.


## 공격 시나리오 예시 

**시나리오 1:** 계정 복구 절차에 "질문-답변 방식"을 넣는 경우가 있는데, 이는 NIST 800-63b, OWASP ASVS 및 OWASP Top 10에서 금지하는 설계다. 질문-답변은 여러 사람이 답을 알고 있을 수 있어 본인 확인의 근거로 신뢰하기 어렵다. 따라서 해당 기능은 제거하고, 보다 안전한 복구 설계로 대체하는 것이 바람직하다.

**시나리오 2:** 한 영화관 체인이 단체 예매 할인 정책을 운용하며, 예매 인원이 15명을 초과하면 보증금을 요구한다고 가정한다. 공격자는 이 예약 흐름을 위협 모델링한 뒤 비즈니스 로직의 허점을 찾아, 몇 번의 요청(14명으로 여러번)만으로 전 지점에 걸쳐 좌석 600석을 동시에 예약해 매출 손실을 유발할 수 있다.

**시나리오 3:** 한 유통 체인의 전자상거래 사이트가 리셀러 구매 봇을 차단하지 못하면, 고가 그래픽카드가 대량 매집되어 리셀 채널로 흘러갈 수 있다. 이는 제조사와 유통사 모두에 대한 부정적 여론을 초래하고, 해당 제품을 어떤 가격에서도 구할 수 없었던 마니아층의 반감을 장기화한다. 제품 판매 개시 직후 극단적으로 짧은 시간 내 구매, 비정상 다량 구매 등 도메인 규칙 기반의 봇 방어 설계를 적용하면, 비정상 구매를 탐지해 거래를 거절할 수 있다.


## 참조



* [OWASP Cheat Sheet: Secure Design Principles](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html)
* [OWASP SAMM: Design | Secure Architecture](https://owaspsamm.org/model/design/secure-architecture/)
* [OWASP SAMM: Design | Threat Assessment](https://owaspsamm.org/model/design/threat-assessment/)
* [NIST – Guidelines on Minimum Standards for Developer Verification of Software](https://www.nist.gov/publications/guidelines-minimum-standards-developer-verification-software)
* [The Threat Modeling Manifesto](https://threatmodelingmanifesto.org/)
* [Awesome Threat Modeling](https://github.com/hysnsec/awesome-threat-modelling)


## 해당 CWE 목록

* [CWE-73 External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)

* [CWE-183 Permissive List of Allowed Inputs](https://cwe.mitre.org/data/definitions/183.html)

* [CWE-256 Unprotected Storage of Credentials](https://cwe.mitre.org/data/definitions/256.html)

* [CWE-266 Incorrect Privilege Assignment](https://cwe.mitre.org/data/definitions/266.html)

* [CWE-269 Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html)

* [CWE-286 Incorrect User Management](https://cwe.mitre.org/data/definitions/286.html)

* [CWE-311 Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)

* [CWE-312 Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)

* [CWE-313 Cleartext Storage in a File or on Disk](https://cwe.mitre.org/data/definitions/313.html)

* [CWE-316 Cleartext Storage of Sensitive Information in Memory](https://cwe.mitre.org/data/definitions/316.html)

* [CWE-362 Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')](https://cwe.mitre.org/data/definitions/362.html)

* [CWE-382 J2EE Bad Practices: Use of System.exit()](https://cwe.mitre.org/data/definitions/382.html)

* [CWE-419 Unprotected Primary Channel](https://cwe.mitre.org/data/definitions/419.html)

* [CWE-434 Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)

* [CWE-436 Interpretation Conflict](https://cwe.mitre.org/data/definitions/436.html)

* [CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')](https://cwe.mitre.org/data/definitions/444.html)

* [CWE-451 User Interface (UI) Misrepresentation of Critical Information](https://cwe.mitre.org/data/definitions/451.html)

* [CWE-454 External Initialization of Trusted Variables or Data Stores](https://cwe.mitre.org/data/definitions/454.html)

* [CWE-472 External Control of Assumed-Immutable Web Parameter](https://cwe.mitre.org/data/definitions/472.html)

* [CWE-501 Trust Boundary Violation](https://cwe.mitre.org/data/definitions/501.html)

* [CWE-522 Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)

* [CWE-525 Use of Web Browser Cache Containing Sensitive Information](https://cwe.mitre.org/data/definitions/525.html)

* [CWE-539 Use of Persistent Cookies Containing Sensitive Information](https://cwe.mitre.org/data/definitions/539.html)

* [CWE-598 Use of GET Request Method With Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html)

* [CWE-602 Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)

* [CWE-628 Function Call with Incorrectly Specified Arguments](https://cwe.mitre.org/data/definitions/628.html)

* [CWE-642 External Control of Critical State Data](https://cwe.mitre.org/data/definitions/642.html)

* [CWE-646 Reliance on File Name or Extension of Externally-Supplied File](https://cwe.mitre.org/data/definitions/646.html)

* [CWE-653 Insufficient Compartmentalization](https://cwe.mitre.org/data/definitions/653.html)

* [CWE-656 Reliance on Security Through Obscurity](https://cwe.mitre.org/data/definitions/656.html)

* [CWE-657 Violation of Secure Design Principles](https://cwe.mitre.org/data/definitions/657.html)

* [CWE-676 Use of Potentially Dangerous Function](https://cwe.mitre.org/data/definitions/676.html)

* [CWE-693 Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)

* [CWE-799 Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html)

* [CWE-807 Reliance on Untrusted Inputs in a Security Decision](https://cwe.mitre.org/data/definitions/807.html)

* [CWE-841 Improper Enforcement of Behavioral Workflow](https://cwe.mitre.org/data/definitions/841.html)

* [CWE-1021 Improper Restriction of Rendered UI Layers or Frames](https://cwe.mitre.org/data/definitions/1021.html)

* [CWE-1022 Use of Web Link to Untrusted Target with window.opener Access](https://cwe.mitre.org/data/definitions/1022.html)

* [CWE-1125 Excessive Attack Surface](https://cwe.mitre.org/data/definitions/1125.html)
