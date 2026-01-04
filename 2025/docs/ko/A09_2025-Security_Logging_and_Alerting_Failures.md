# A09:2025 보안 로깅 및 알림 실패 ![icon](../assets/TOP_10_Icons_Final_Security_Logging_and_Monitoring_Failures.png){: style="height:80px;width:80px" align="right"}


## 배경. 

보안 로깅 및 알림 실패는 9위를 유지한다. 명칭이 약간 변경되었는데, 로그에서 발생한 이벤트의 조치를 유도하는 데 필요한 알림 기능을 강조하기 위함이다. 이 카테고리는 특성상 데이터상 순위가 낮게 나타나기 쉬우며, 커뮤니티 설문 투표를 통해 이번이 세 번째로 Top 10에 포함되었다. 또한 테스트가 극도로 어렵고, CVE/CVSS 데이터에서의 비중이 매우 낮지만(총 723개의 CVE), 가시성 확보, 인시던트 알림, 그리고 포렌식에 측면에서 큰 영향을 미칠 수 있다. 해당 카테고리에 포함되는 CWE는 *로그 기록 시 출력 인코딩 처리 미흡(CWE-117), 로그에 민감정보가 기록(CWE-532), 그리고 불충분한 로깅(CWE-778)이다.*


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
   <td>5
   </td>
   <td>11.33%
   </td>
   <td>3.91%
   </td>
   <td>85.96%
   </td>
   <td>46.48%
   </td>
   <td>7.19
   </td>
   <td>2.65
   </td>
   <td>260,288
   </td>
   <td>723
   </td>
  </tr>
</table>



## 설명.

로깅과 모니터링이 없으면 공격 및 침해를 탐지할 수 없으며, 알림이 없으면 보안 인시던트 발생시 신속하고 효과적으로 대응하기가 매우 어렵다. 다음과 같은 경우에는 불충분한 로깅, 지속적인 모니터링, 탐지 및 능동적 대응을 시작하기 위한 알림의 미흡이 발생한다. 아래와 같은 경우, 능동적 대응을 개시하기 위한 로깅, 지속적 모니터링, 탐지, 알림이 부족한 것으로 볼 수 있다.

* 로그인, 로그인 실패, 중요 거래 데이터 등 감사가 필요한 대상의 이벤트가 누락되거나 기준 없이 들쭉날쭉하게(예: 성공 로그인만 기록) 로깅되는 경우.
* 경고 및 오류가 로그 메시지를 생성하지 않거나, 부적절하거나, 불명확한 로그를 생성하는 경우.
* 로그가 위변조되지 않도록 무결성 보호가 적용되지 않는 경우.
* 애플리케이션 및 API 로그를 기반으로 한 이상징후 모니터링이 수행되지 않는 경우.
* 로그가 로컬에만 보관되고 백업이 적절히 수행되지 않는 경우.
* 적절한 알림 임계값 및 대응 에스컬레이션 절차가 마련되어 있지 않거나 효과적이지 않다. 알림이 적시에 확인되지 않거나 검토되지 않는 경우.
* 동적 애플리케이션 보안 테스트(DAST) 도구(예: Burp 또는 ZAP)에 의한 침투 테스트 및 스캔이 알림을 트리거하지 않는 경우.
* 진행 중인 공격을 실시간 혹은 준실시간으로 탐지하지 못하거나 상위 단계로 에스컬레이션하거나 알림을 발생시키지 못하는 경우.
* 로깅 및 알림 이벤트를 사용자 또는 공격자에게 노출 하거나([A01:2025-접근 제어 실패](A01_2025-Broken_Access_Control.md) 참조), 로깅되면 안 되는 민감정보(예: PII 또는 PHI)를 로깅함으로써 민감정보 유출에 취약한 경우.
* 로그 데이터 인코딩이 부적절해 로깅 또는 모니터링 시스템 자체가 인젝션 등 공격 대상이 되는 경우.
* 애플리케이션이 오류 및 예외 처리를 누락 또는 오처리하여 시스템이 오류 발생 자체를 인지하지 못하고, 결과적으로 문제를 로그로 남길 수 없는 경우.
* 특수 상황을 식별하기 위한 알림 '유스케이스'가 없거나 오래되어 현재 환경을 반영하지 못한다.
* 특정 상황을 탐지해 알림을 발생시키기 위한 인시던트 유스케이스(use case)가 없거나, 갱신이 되지 않아 현행 환경을 충분히 반영하지 못하는 경우.
* 너무 많은 오탐 알림으로 인해 중요한 알림과 중요하지 않은 알림을 구분할 수 없게 되어, 알림이 너무 늦게 인지되거나 전혀 인지되지 않는 경우(SOC 팀의 물리적 과부하).
* 유스케이스에 대한 플레이북이 불완전하거나, 최신이 아니거나, 누락되어 감지된 알림을 올바르게 처리할 수 없는 경우.


## 대응 방안. 

개발자는 애플리케이션의 위험도에 따라 아래 통제 항목 중 일부 또는 전체를 구현해야 한다.

* 모든 로그인, 접근 통제 및 서버 측 입력 검증 실패에 대해 로그를 남기며, 의심스럽거나 악성인 계정을 식별할 수 있을 만큼 충분한 유저 컨텍스트를 포함하고, 사후 포렌식 분석을 위해 충분한 기간 동안 저장한다.
* 보안 통제가 포함된 애플리케이션의 모든 부분에서, 성공 여부와 관계없이 로깅되도록 보장한다.
* 보안 통제가 적용된 구간은 성공 및 실패 여부와 무관하게 모두 로깅 대상에 포함한다.
* 로그는 중앙 로그 플랫폼이 쉽게 수집할 수 있는 표준화된 포맷으로 생성한다.
* 로그 데이터는 인코딩을 확실히 적용해 로깅 및 모니터링 시스템의 로그 기반 인젝션 및 공격을 예방한다.
* 모든 트랜잭션에 대해 감사 로그를 남기고, 추가만 가능한(append-only) 데이터베이스 테이블 등으로 삭제 및 변조를 어렵게 하는 무결성 통제를 적용한다.
* 오류가 발생한 모든 트랜잭션은 롤백되고 다시 시작되도록 한다. 또한, 기본적으로 차단(fail closed)되도록 한다.
* 애플리케이션 또는 사용자 행위가 의심스러운 경우 알림을 발행한다. 개발자가 해당 내용을 대응하여 코드를 개발할 수 있도록 가이드를 제공하거나, 이를 위한 시스템을 구매한다.
* DevSecOps 및 보안 팀은 SOC(Security Operations Center) 팀이 의심 활동을 신속히 탐지하고 대응할 수 있도록, 플레이북을 포함한 효과적인 모니터링 및 알림 유스케이스를 수립해야 한다.
* 공격자를 위한 함정으로 '허니토큰(honeytoken)'을 애플리케이션에 추가한다. 예를 들어 데이터베이스 내에 실제 사용자 및/또는 시스템 계정 형태의 데이터 또는 식별자를 삽입한다. 허니토큰은 정상 업무에서는 사용되지 않으므로, 접근이 발생하면 관련 이벤트가 로그로 남고 오탐이 거의 없는 알림 조건으로 활용할 수 있다.
* 필요 시 행위 기반 분석 및 AI를 보조 수단으로 활용해 오탐을 낮추고 알림 품질을 개선한다.
* NIST 800-61r2 이상 수준의 인시던트 대응 및 복구 계획을 마련하고, 개발자에게 공격/인시던트 징후를 교육해 보고 및 초기 대응이 가능하도록 한다.


추가로, OWASP ModSecurity 핵심 규칙 세트(Core Rule Set)와 같은 상용 및 오픈소스 애플리케이션 보호 제품, 그리고 사용자 정의 대시보드 및 알림 기능을 제공하여 대응에 도움이 될 수 있는 Elasticsearch, Logstash, Kibana(ELK) 스택과 같은 오픈소스 로그 상관분석 소프트웨어가 있다. 공격에 준실시간으로 대응하거나 이를 차단하는 데 도움이 되는 상용 옵저버빌리티(observability) 도구도 존재한다.


## 공격 시나리오 예시. 

**시나리오 1:** 한 아동 건강보험 제공업체의 웹사이트 운영자는 모니터링 및 로깅 부재로 인해 침해 사고를 탐지하지 못했다. 외부 제3자가 해당 제공업체에 공격자가 350만 명이 넘는 아동의 민감한 건강 기록 수천 건에 접근하여 이를 수정했다고 통보했다. 사후 분석에서는 핵심 취약점이 장기간 방치된 정황이 확인되었으며, 로그와 모니터링이 없어 침해가 2013년부터 7년 이상 지속되었을 가능성도 배제할 수 없었다.

**시나리오 2:** 인도의 주요 항공사에서 여권 및 신용카드 데이터를 포함해 수백만 명 승객의 10년 이상 분량 개인정보가 관련된 데이터 유출이 발생했다. 해당 유출은 제3자 클라우드 호스팅 제공업체에서 발생했으며, 해당 제공업체는 일정 시간이 지난 뒤 항공사에 침해 사실을 통보했다.

**사나리오 3:** 유럽의 주요 항공사는 GDPR 신고 의무가 있는 침해 사고를 겪었다. 보고에 따르면, 결제 애플리케이션 보안 취약점이 공격자에 의해 악용되었고, 공격자는 40만 건이 넘는 고객 결제 기록을 탈취했다. 그 결과 항공사는 개인정보 감독기관으로부터 2,000만 파운드의 벌금을 부과받았다.


## 참조.

-   [OWASP Proactive Controls: C9: Implement Logging and Monitoring](https://top10proactive.owasp.org/archive/2024/the-top-10/c9-security-logging-and-monitoring/)

-   [OWASP Application Security Verification Standard: V16 Security Logging and Error Handling](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md)

-   [OWASP Cheat Sheet: Application Logging Vocabulary](https://cheatsheetseries.owasp.org/cheatsheets/Application_Logging_Vocabulary_Cheat_Sheet.html)

-   [OWASP Cheat Sheet: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

-   [Data Integrity: Recovering from Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-11/final)

-   [Data Integrity: Identifying and Protecting Assets Against Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-25/final)

-   [Data Integrity: Detecting and Responding to Ransomware and Other Destructive Events](https://csrc.nist.gov/publications/detail/sp/1800-26/final)

-   [Real world example of such failures in Snowflake Breach](https://www.huntress.com/threat-library/data-breach/snowflake-data-breach)


## 해당되는 CWE 목록.

* [CWE-117 Improper Output Neutralization for Logs](https://cwe.mitre.org/data/definitions/117.html)

* [CWE-221 Information Loss of Omission](https://cwe.mitre.org/data/definitions/221.html)

* [CWE-223 Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)

* [CWE-532 Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)

* [CWE-778 Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
