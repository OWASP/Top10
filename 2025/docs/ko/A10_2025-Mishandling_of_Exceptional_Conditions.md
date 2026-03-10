# A10:2025 부적절한 예외 처리 ![icon](../assets/TOP_10_Icons_Final_Mishandling_of_Exceptional_Conditions.png){: style="height:80px;width:80px" align="right"}

## 배경

부적절한 예외 처리는 2025년에 신설된 카테고리다. 이 카테고리는 24개의 CWE를 포함하며, 부적절한 오류 처리, 논리적 오류, 페일 오픈(fail open), 그 외 시스템이 비정상적인 상황에서 마주할 수 있는 시나리오를 다룬다. 이 카테고리에는 이전에 낮은 코드 품질과 연관되었던 일부 CWE가 포함되어 있다. 기존의 낮은 코드 품질 카테고리는 너무 광범위했기에, 부적절한 예외 처리라는 구체적인 카테고리로 분리하여 더 명확한 가이드를 제공하고자 했다.

대표적인 CWE로는 *CWE-209: 민감한 정보가 포함된 오류 메시지 생성*, *CWE-234: 누락된 파라미터 처리 실패*, *CWE-274: 권한 부족 처리 미흡*, *CWE-476: NULL 포인터 역참조*, 그리고 *CWE-636: 안전하지 않은 실패 처리('Failing Open')*가 있다.


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
   <td>24
   </td>
   <td>20.67%
   </td>
   <td>2.95%
   </td>
   <td>100.00%
   </td>
   <td>37.95%
   </td>
   <td>7.11
   </td>
   <td>3.81
   </td>
   <td>769,581
   </td>
   <td>3,416
   </td>
  </tr>
</table>



## 설명

부적절한 예외 처리는 프로그램이 비정상적이고 예측 불가능한 상황을 예방, 탐지, 대응하지 못할 때 발생하며, 이로 인해 시스템 충돌, 예상치 못한 동작, 때로는 보안 취약점까지 초래할 수 있다. 이는 다음 세 가지 실패 중 하나 이상을 포함한다. 비정상적인 상황을 사전에 예방하지 못하거나, 발생 시 이를 식별하지 못하거나, 발생 후 적절히 대응하지 못하는 경우다.

예외 상황은 다음과 같은 원인으로 발생할 수 있다. 누락되거나 불완전한 입력 검증, 발생 지점이 아닌 상위 레벨에서의 지연된 오류 처리, 메모리, 권한, 네트워크 문제 등 예기치 않은 환경 상태, 일관성 없는 예외 처리, 또는 전혀 처리되지 않는 예외로 인해 시스템이 알 수 없고 예측 불가능한 상태에 빠지는 경우다. 애플리케이션이 다음에 무엇을 해야 할지 알 수 없는 상태에 빠진다면, 예외 처리가 실패한 것이다. 이러한 오류와 예외는 발견이 어려워 장기간 보안을 위협할 수 있다.

부적절한 예외 처리로 인해 다양한 보안 취약점이 발생할 수 있다. 예를 들어 논리 버그, 오버플로우, 레이스 컨디션, 부정 거래, 메모리, 상태, 리소스, 타이밍, 인증, 인가 관련 문제 등이 있다. 이러한 유형의 취약점은 시스템 또는 데이터의 기밀성, 가용성, 무결성에 부정적인 영향을 미칠 수 있다. 공격자는 애플리케이션의 결함 있는 오류 처리를 악용하여 이 취약점을 공격한다.

## 대응 방안 

예외 상황을 적절히 처리하려면 이러한 상황에 대비한 계획을 세워야 한다(최악의 상황을 예상하라). 모든 시스템 오류를 발생 지점에서 캐치(catch)하고 이를 처리해야한다. 여기서 처리란 문제 해결을 위한 의미 있는 조치를 취하고 정상 상태로 복구하는 것을 의미한다. 처리 과정에는 오류 발생 시 사용자에게 이해하기 쉬운 방식으로 알리고, 이벤트를 로깅하며, 필요하다고 판단되면 알림을 발송하는 것이 포함되어야 한다. 또한 놓친 예외가 있을 경우를 대비해 전역 예외 핸들러(Global Exception Handler)를 구현해야 한다. 이상적으로는 반복되는 오류나 진행 중인 공격을 나타내는 패턴을 감시하고, 이에 대응, 방어, 차단할 수 있는 모니터링 또는 옵저버빌리티 도구를 갖추는 것이 좋다. 이를 통해 오류 처리 취약점을 악용하는 스크립트와 봇에 대응하고 차단할 수 있다.

예외 상황을 캐치하고 처리하면 프로그램의 기반 인프라가 예측 불가능한 상황에 노출되는 것을 방지할 수 있다. 트랜잭션 처리 도중이라면, 트랜잭션의 모든 부분을 롤백하고 처음부터 다시 시작하는 것이 매우 중요하다(이를 fail closed라고 한다). 트랜잭션을 중간 상태에서 복구하려는 시도는 종종 복구 불가능한 오류를 만들어낸다.

가능하다면 속도 제한(rate limit), 리소스 쿼터, 스로틀링 등 다양한 제한을 적용하여 애초에 예외 상황이 발생하지 않도록 예방한다. 정보기술 분야에서 무제한이어야 하는 것은 없다. 제한이 없으면 애플리케이션 복원력 저하, 서비스 거부(DoS), 무차별 대입 공격 성공, 과도한 클라우드 비용 등의 문제가 발생할 수 있다.

특정 빈도 이상으로 동일한 오류가 반복될 경우, 개별 오류 메시지 대신 발생 횟수와 시간대를 보여주는 통계 형태로 출력하는 것을 고려한다. 이 정보는 자동화된 로깅 및 모니터링을 방해하지 않도록 원본 메시지에 추가하는 방식으로 처리해야 한다. [A09:2025 보안 로깅 및 알림 실패](A09_2025-Security_Logging_and_Alerting_Failures.md)를 참고한다.

이 외에도 다음 사항을 포함해야 한다. 엄격한 입력 검증(허용해야 하는 위험 문자에 대한 새니타이징 또는 이스케이프 처리 포함), *중앙 집중화된* 오류 처리, 로깅, 모니터링, 알림 체계, 그리고 전역 예외 핸들러다. 하나의 애플리케이션에서 예외 처리를 위한 여러 함수를 두어서는 안 되며, 한 곳에서 동일한 방식으로 처리해야 한다. 또한 이 섹션의 모든 권고 사항에 대해 프로젝트 보안 요구사항을 수립하고, 설계 단계에서 위협 모델링 또는 보안 설계 검토를 수행하며, 코드 리뷰나 정적 분석을 실시하고, 최종 시스템에 대해 스트레스, 성능, 침투 테스트를 수행해야 한다.

가능하다면 조직 전체가 동일한 방식으로 예외 상황을 처리하는 것이 좋다. 이렇게 하면 이 중요한 보안 통제에 대한 코드 리뷰와 감사가 더 쉬워진다.

## 공격 시나리오 예시 

**시나리오 1:** 애플리케이션이 파일 업로드 시 예외를 캐치하되 리소스를 해제하지 않으면, 예외가 발생할 때마다 리소스가 잠긴 채로 남는다. 이로 인해 리소스가 고갈되어 서비스 거부(DoS)로 이어질 수 있다.

**시나리오 2:** 데이터베이스 오류가 사용자에게 그대로 노출되면 민감한 시스템 정보가 유출된다. 공격자는 이를 악용해 의도적으로 오류를 유발하고, 수집한 정보를 기반으로 더 정교한 SQL 인젝션 공격을 구성할 수 있다.

**시나리오 3:** 공격자가 네트워크 장애를 일으켜 여러 단계로 이루어진 트랜잭션을 중간에 방해할 수 있다. 예를 들어 트랜잭션이 사용자 계좌 출금, 대상 계좌 입금, 트랜잭션 로깅 순서로 처리된다고 가정한다면, 중간에 오류가 발생해도 시스템이 전체 트랜잭션을 롤백(안전한 실패)하지 않으면 문제가 생긴다. 공격자는 이를 악용해 사용자 계좌에서 돈만 빠져나가게 하거나, 레이스 컨디션을 이용해 대상 계좌로 여러 번 송금할 수 있다.

## 참조

- [OWASP MASVS‑RESILIENCE](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/)

- [OWASP Cheat Sheet: Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

- [OWASP Cheat Sheet: Error Handling](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)

- [OWASP Application Security Verification Standard (ASVS): V16.5 Error Handling](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md#v165-error-handling)

- [OWASP Testing Guide: 4.8.1 Testing for Error Handling](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling)

* [Best practices for exceptions (Microsoft, .Net)](https://learn.microsoft.com/en-us/dotnet/standard/exceptions/best-practices-for-exceptions)

* [Clean Code and the Art of Exception Handling (Toptal)](https://www.toptal.com/developers/abap/clean-code-and-the-art-of-exception-handling)

* [General error handling rules (Google for Developers)](https://developers.google.com/tech-writing/error-messages/error-handling)

* [Example of real-world mishandling of an exceptional condition](https://www.firstreference.com/blog/human-error-and-internal-control-failures-cause-us62m-fine/) 

## 해당 CWE 목록
* [CWE-209	Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
* [CWE-215	Insertion of Sensitive Information Into Debugging Code](https://cwe.mitre.org/data/definitions/215.html)
* [CWE-234	Failure to Handle Missing Parameter](https://cwe.mitre.org/data/definitions/234.html)
* [CWE-235	Improper Handling of Extra Parameters](https://cwe.mitre.org/data/definitions/235.html)
* [CWE-248	Uncaught Exception](https://cwe.mitre.org/data/definitions/248.html)
* [CWE-252	Unchecked Return Value](https://cwe.mitre.org/data/definitions/252.html)
* [CWE-274	Improper Handling of Insufficient Privileges](https://cwe.mitre.org/data/definitions/274.html)
* [CWE-280	Improper Handling of Insufficient Permissions or Privileges](https://cwe.mitre.org/data/definitions/280.html)
* [CWE-369	Divide By Zero](https://cwe.mitre.org/data/definitions/369.html)
* [CWE-390	Detection of Error Condition Without Action](https://cwe.mitre.org/data/definitions/390.html)
* [CWE-391	Unchecked Error Condition](https://cwe.mitre.org/data/definitions/391.html)
* [CWE-394	Unexpected Status Code or Return Value](https://cwe.mitre.org/data/definitions/394.html)
* [CWE-396	Declaration of Catch for Generic Exception](https://cwe.mitre.org/data/definitions/396.html)
* [CWE-397	Declaration of Throws for Generic Exception](https://cwe.mitre.org/data/definitions/397.html)
* [CWE-460	Improper Cleanup on Thrown Exception](https://cwe.mitre.org/data/definitions/460.html)
* [CWE-476	NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html)
* [CWE-478	Missing Default Case in Multiple Condition Expression](https://cwe.mitre.org/data/definitions/478.html)
* [CWE-484	Omitted Break Statement in Switch](https://cwe.mitre.org/data/definitions/484.html)
* [CWE-550	Server-generated Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/550.html)
* [CWE-636	Not Failing Securely ('Failing Open')](https://cwe.mitre.org/data/definitions/636.html)
* [CWE-703	Improper Check or Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/703.html)
* [CWE-754	Improper Check for Unusual or Exceptional Conditions](https://cwe.mitre.org/data/definitions/754.html)
* [CWE-755	Improper Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/755.html)
* [CWE-756	Missing Custom Error Page](https://cwe.mitre.org/data/definitions/756.html)
