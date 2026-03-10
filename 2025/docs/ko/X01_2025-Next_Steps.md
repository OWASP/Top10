# 다음 단계

OWASP Top 10은 이름 그대로 가장 중요한 10가지 위험으로만 선정한다. 각 버전의 OWASP Top 10에는 포함 여부를 두고 충분히 검토되었으나, 다른 위험들이 더 빈번하게 발생하고 영향도도 더 컸기 때문에 최종 목록에 포함되지 않은 "경계선상"의 위험들이 존재한다.

아래의 세 가지 이슈는 발견 및 조치에 투자할 만한 가치가 크며, 성숙한 애플리케이션 보안 프로그램을 목표로 하는 조직, 보안 컨설팅 회사, 또는 제품의 커버리지를 확장하려는 보안 도구 벤더에 특히 유용할 수 있다.


## X01:2025 애플리케이션 복원력 부족

### 배경 

이 카테고리의 명칭은 2021년 버전의 서비스 거부(Denial of Service)에서 현재 명칭으로 변경됐다. 기존 명칭은 근본 원인보다는 발생 현상을 설명하는 성격이 강해, 이를 보완하기 위해 재명명되었다. 이 카테고리는 복원력과 관련된 약점을 설명하는 CWE에 초점을 둔다. 점수 산정은 A10:2025-부적절한 예외 처리와 매우 근접했다. 관련된 CWE로는 *CWE-400: 통제되지 않은 자원 소비, CWE-409: 고압축 데이터의 부적절한 처리(데이터 증폭), CWE-674: 통제되지 않은 재귀*, 그리고 *CWE-835: 종료 조건에 도달할 수 없는 루프(무한 루프)*가 있다.


### 점수표


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
   <td>16
   </td>
   <td>20.05%
   </td>
   <td>4.55%
   </td>
   <td>86.01%
   </td>
   <td>41.47%
   </td>
   <td>7.92
   </td>
   <td>3.49
   </td>
   <td>865,066
   </td>
   <td>4,423
   </td>
  </tr>
</table>



### 설명 

이 카테고리는 애플리케이션이 스트레스, 장애 및 엣지 케이스에 대응하는 방식 전반에 존재하는 시스템적 약점을 의미하며, 그 결과 장애 발생 시 애플리케이션이 정상 상태로 복구하지 못할 수 있다. 애플리케이션이 예기치 않은 조건, 리소스 제약 및 기타 불리한 이벤트를 우아하게(gracefully) 처리하지 못하거나, 견디지 못하거나, 또는 복구하지 못할 경우, 가용성 문제(일반적으로)로 이어지며, 그 외에도 데이터 손상, 민감 데이터 노출, 연쇄 장애 또는 보안 통제 우회를 유발할 수 있다.

또한 [X02:2025 메모리 관리 실패](#x022025) 역시 애플리케이션, 또는 심지어 전체 시스템의 장애로 이어질 수 있다.

### 대응 방안 

이 유형의 취약점을 예방하기 위해서는 시스템의 장애와 복구를 기본 전제로 설계해야 한다.

* 제한, 할당량 및 페일오버(failover) 기능을 추가하되, 특히 자원을 가장 많이 소모하는 작업에 주의를 기울인다.
* 자원 소모가 큰 페이지를 식별하고 사전에 대비해야 한다. 공격 표면을 줄이되, 특히 불명의 또는 신뢰할 수 없는 사용자에게 불필요한 '가젯'과 많은 자원(예: CPU, 메모리)을 요구하는 기능을 노출하지 않도록 한다.
* 입력값은 크기 제한을 적용하고 허용 리스트 기반으로 엄격히 검증한 뒤, 철저히 테스트한다.
* 응답 크기를 제한하고, 가공되지 않은(raw) 응답을 클라이언트에 그대로 반환하지 않는다(서버 측에서 우선 처리한다).
* 기본적으로 페일 클로즈드(fail closed)를 사용하고 절대로 페일 오픈(fail open)을 사용하지 않는다. 우선 거부 정책(deny by default)을 사용하며, 오류가 발생하면 롤백한다.
* 리퀘스트 스레드에서 동기식 차단 호출(blocking synchronous call)을 피한다(비동기/논블로킹 사용, 타임아웃 설정, 동시성 제한 등).
* 에러 처리 기능을 신중하게 테스트한다.
* 서킷 브레이커, 격벽(bulkhead), 재시도 로직, 우아한 성능 저하(graceful degradation)와 같은 복원력 패턴을 구현한다.
* 성능 및 부하 테스트를 수행한다. 조직의 위험 수용 범위 내에서 카오스 엔지니어링을 도입한다.
* 합리적이고 비용적으로 감당 가능한 범위에서 이중화를 구현하고, 이를 전제로 아키텍처를 설계한다.
* 모니터링, 옵저버빌리티, 알림을 구현한다.
* RFC 2267을 준수해 잘못된 발신자 주소를 필터링한다.
* 핑거프린트, IP 또는 행위 기반 동적 탐지로 알려진 봇넷을 차단한다.
* 작업 증명(Proof-of-Work)을 적용하여 자원 소모 작업을 서버가 아니라 *공격자* 측에 부과한다. 정상 사용자 경험에 미치는 영향은 최소화하고, 시스템 부하가 상승할수록 작업 증명 난이도를 높이고, 특히 신뢰도가 낮거나 봇으로 판단되는 트래픽에는 더 높은 난이도를 적용한다.
* 비활성 시간과 최종 타임아웃을 기준으로 서버 측 세션 시간을 제한한다.
* 세션에 저장되는 상태 정보는 최소화한다.


### 공격 시나리오 예시  

**시나리오 1:** 공격자가 리소스 소모를 유도해 시스템 장애를 유발하고, 결과적으로 서비스 거부(DoS) 상태를 만든다. 예로 메모리 고갈, 디스크 용량 소진, CPU 사용량 포화, 커넥션 무제한 연결 등이 있다.

**시나리오 2:** 입력값 퍼징을 통해 비정상 입력을 대량 주입하고, 비즈니스 로직을 오동작시키는 조작된 응답을 유도한다.

**시나리오 3:** 공격자가 애플리케이션의 의존성을 공격하여 API 또는 기타 외부 서비스를 다운시키며, 애플리케이션이 정상 동작할 수 없게 만든다.


### 참조

* [OWASP Cheat Sheet: Denial of Service](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
* [OWASP MASVS‑RESILIENCE](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/)
* [ASP.NET Core Best Practices (Microsoft)](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/best-practices?view=aspnetcore-9.0)
* [Resilience in Microservices: Bulkhead vs Circuit Breaker (Parser)](https://medium.com/@parserdigital/resilience-in-microservices-bulkhead-vs-circuit-breaker-54364c1f9d53)
* [Bulkhead Pattern (Geeks for Geeks)](https://www.geeksforgeeks.org/system-design/bulkhead-pattern/)
* [NIST Cybersecurity Framework (CSF)](https://www.nist.gov/cyberframework)
* [Avoid Blocking Calls: Go Async in Java (Devlane)](https://www.devlane.com/blog/avoid-blocking-calls-go-async-in-java)

### 해당되는 CWE 목록
* [CWE-73  External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)
* [CWE-183 Permissive List of Allowed Inputs](https://cwe.mitre.org/data/definitions/183.html)
* [CWE-256 Plaintext Storage of a Password](https://cwe.mitre.org/data/definitions/256.html)
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
* [CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')](https://cwe.mitre.org/data/definitions/444.html)
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
* [CWE-653 Improper Isolation or Compartmentalization](https://cwe.mitre.org/data/definitions/653.html)
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


## X02:2025 메모리 관리 실패

### 배경 

Java, C#, JavaScript/TypeScript(Node.js), Go, 그리고 "안전한" Rust와 같은 언어는 메모리 안전한 언어이다. 메모리 관리 문제는 C 및 C++와 같은 메모리가 안전하지 않은 언어에서 발생하는 경향이 있다. 이 카테고리는 관련 CVE가 세 번째로 많음에도 불구하고, 커뮤니티 설문에서는 가장 낮은 점수를 받았고 데이터상에서도 낮게 나타났다. 이는 전통적인 데스크톱 애플리케이션보다 웹 애플리케이션이 우세하기 때문이라고 본다. 메모리 관리 취약점은 대체로 가장 높은 CVSS 점수를 가진다.


### 점수표


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
   <td>2.96%
   </td>
   <td>1.13%
   </td>
   <td>55.62%
   </td>
   <td>28.45%
   </td>
   <td>6.75
   </td>
   <td>4.82
   </td>
   <td>220,414
   </td>
   <td>30,978
   </td>
  </tr>
</table>



### 설명 

애플리케이션이 메모리를 직접 관리해야 할 때 실수가 발생하기 쉽다. 메모리 안전 언어가 더 많이 사용되고 있지만, 전 세계 운영 환경에는 여전히 많은 레거시 시스템이 존재하며, 메모리가 안전하지 않은 언어가 필요한 새로운 저수준 시스템과 메인프레임, IoT 장치, 펌웨어 및 자체 메모리를 관리해야 할 수 있는 기타 시스템과 상호작용하는 웹 애플리케이션도 여전히 많다. 대표적인 CWE로는 *CWE-120 입력 크기 확인 없이 버퍼 복사('클래식 버퍼 오버플로')* 및 *CWE-121 스택 기반 버퍼 오버플로*가 있다.

메모리 관리 실패는 다음과 같은 경우에 발생할 수 있다.

* 변수에 대해 충분한 메모리를 할당하지 않는 경우.
* 입력을 검증하지 않아 힙, 스택 또는 버퍼에서 오버플로가 발생하는 경우.
* 변수 타입이 수용할 수 있는 크기보다 큰 데이터 값을 저장하는 경우.
* 할당되지 않은 메모리 또는 주소 공간을 사용하려고 시도하는 경우.
* 오프 바이 원(off-by-one, 0이 아니라 1부터 카운팅) 오류가 있는 경우.
* 해제(free)된 이후에 객체에 접근하려고 하는 경우.
* 초기화되지 않은 변수를 사용하는 경우.
* 메모리 누수 또는 비정상 메모리 소모로 가용 메모리가 고갈되어 장애로 이어지는 경우.

메모리 관리 실패는 애플리케이션뿐만 아니라 심지어 전체 시스템의 장애로 이어질 수 있으며, 이는 [X01:2025 애플리케이션 복원력 부족](#x012025)를 함께 참고한다.


### 대응 방안 

메모리 관리 실패를 예방하는 최선의 방법은 메모리 안전 언어를 사용하는 것이다. 예로는 Rust, Java, Go, C#, Python, Swift, Kotlin, JavaScript 등이 있다. 새로운 애플리케이션을 개발할 때는 학습 곡선이 있더라도 메모리 안전 언어로 전환할 가치가 있음을 조직 내에서 적극적으로 설득해야 한다. 전면적인 리팩터링을 수행하는 경우에는 가능하고 실현 가능한 범위에서, 메모리 안전 언어로의 재작성을 추진한다.

메모리 안전 언어를 사용할 수 없다면 다음을 수행한다.

* 메모리 관리 오류의 악용을 어렵게 만드는 서버 기능을 활성화한다. 주소 공간 배치 무작위화(Address Space Layout Randomization, ASLR), 데이터 실행 방지(Data Execution Protection, DEP), 구조화된 예외 처리(Structured Exception Handling Overwrite Protection).
* 애플리케이션의 메모리 누수를 모니터링한다.
* 시스템으로 들어오는 모든 입력을 매우 신중하게 검증하고, 기대 조건을 충족하지 않는 입력은 모두 거부한다.
* 사용 중인 언어를 학습하여 위험한 함수와 비교적 안전한 함수의 목록을 작성하고, 이를 팀과 공유한다. 가능하다면 이를 시큐어 코딩 가이드라인이나 표준에 추가한다. 예를 들어, C 언어에서는 strcpy() 대신 strncpy()를, strcat() 대신 strncat()을 우선적으로 사용한다.
* 언어나 프레임워크에서 메모리 안전 라이브러리를 제공한다면 이를 사용한다. 예: Safestringlib 또는 SafeStr.
* 가능하면 원시 배열과 포인터보다 관리형 버퍼 및 문자열을 사용한다.
* 메모리 이슈나 사용 중인 언어에 초점을 맞춘 시큐어 코딩 교육을 받는다. 교육 담당자에게 메모리 관리 실패에 대해 우려하고 있음을 알린다.
* 코드 리뷰 및 정적 분석을 수행한다.
* StackShield, StackGuard, Libsafe 등 메모리 관리를 돕는 컴파일러/도구를 사용한다.
* 시스템의 모든 입력에 대해 퍼징을 수행한다.
* 모의침투 테스트를 수행하는 경우, 테스터에게 메모리 관리 실패에 대한 우려가 있으며 테스트 중 해당 부분에 특별히 주의를 기울여 줄 것을 요청한다.
* 컴파일러 오류와 경고를 *모두* 수정한다. 프로그램이 컴파일된다고 해서 경고를 무시하지 않는다.
* 기반 인프라가 정기적으로 패치, 스캔, 하드닝되도록 보장한다.
* 특히 기반 인프라를 대상으로 한 잠재적 메모리 취약점 및 기타 장애 요인을 모니터링한다.
* 오버플로 공격으로부터 주소 스택을 보호하기 위해 [카나리](https://en.wikipedia.org/wiki/Buffer_overflow_protection#Canaries) 사용을 고려한다.

### 공격 시나리오 예시 

**시나리오 1:** 버퍼 오버플로는 가장 유명한 메모리 취약점으로, 공격자가 필드가 수용할 수 있는 것보다 더 많은 데이터를 입력하여 해당 변수에 대해 생성된 버퍼를 넘치게 만드는 상황을 말한다. 공격이 성공하면 넘친 데이터가 스택 포인터를 덮어쓰게 되며, 이를 통해 공격자가 프로그램에 악의적인 명령을 삽입할 수 있게 된다.

**시나리오 2:** 유즈 에프터 프리(Use-After-Free)은 비교적 자주 발생하여 브라우저 버그 바운티에서 흔히 제보되는 유형의 버그다. 예를 들어 웹 브라우저가 DOM 요소를 조작하는 JavaScript를 처리하는 상황을 가정하자. 공격자는 객체(예: DOM 요소)를 생성하고 그에 대한 참조를 획득하는 JavaScript 페이로드를 작성한다. 이후 정교한 조작을 통해, 브라우저가 해당 객체의 메모리를 해제하도록 유도하면서도 그 객체를 가리키는 댕글링 포인터(dangling pointer)는 유지하게 만든다. 브라우저가 메모리 해제를 인지하기 전에, 공격자는 *동일한* 메모리 공간을 차지하도록 새 객체를 할당한다. 브라우저가 원래 포인터를 사용하면, 이제 그 포인터는 공격자가 삽입한 데이터를 참조하게 된다. 만약 이 포인터가 가상 함수 테이블을 가리키는 것이었다면, 공격자는 코드 실행 흐름을 자신의 페이로드로 리다이렉션할 수 있다.

**시나리오 3:** 사용자 입력을 받아 적절히 검증하거나 정제하지 않고 로깅 함수로 직접 전달하는 네트워크 서비스를 가정해 보자. 사용자 입력은 형식을 지정하는 syslog("%s", user_input) 대신 형식을 지정하지 않은 syslog(user_input) 형태로 로깅 함수에 전달된다. 공격자는 스택 메모리를 읽기 위한(민감한 데이터 노출) %x 또는 메모리 주소에 값을 쓰기 위한 %n과 같은 형식 지정자(format specifier)를 포함한 악성 페이로드를 전송한다. 공격자는 여러 형식 지정자를 결합하여 스택 구조를 파악하고, 중요한 주소를 찾아낸 뒤 이를 덮어쓸 수 있다. 이는 포맷 스트링 취약점에 해당한다.

참고: 현대의 브라우저는 [브라우저 샌드박스](https://www.geeksforgeeks.org/ethical-hacking/what-is-browser-sandboxing/#types-of-browser-sandboxing), ASLR, DEP/NX, RELRO 및 PIE를 포함한 심층적 방어 체계를 사용하기에, 브라우저에 대한 메모리 관리 실패 공격이 쉽지 않다.

### 참조

* [OWASP community pages: Memory leak,](https://owasp.org/www-community/vulnerabilities/Memory_leak) [Doubly freeing memory,](https://owasp.org/www-community/vulnerabilities/Doubly_freeing_memory) [& Buffer Overflow](https://owasp.org/www-community/vulnerabilities/Buffer_Overflow)
* [Awesome Fuzzing: a list of fuzzing resources](https://github.com/secfigo/Awesome-Fuzzing) 
* [Project Zero Blog](https://googleprojectzero.blogspot.com)
* [Microsoft MSRC Blog](https://www.microsoft.com/en-us/msrc/blog)

### 해당되는 CWE 목록
* [CWE-14 Compiler Removal of Code to Clear Buffers](https://cwe.mitre.org/data/definitions/14.html)
* [CWE-119 Improper Restriction of Operations within the Bounds of a Memory Buffer](https://cwe.mitre.org/data/definitions/119.html)
* [CWE-120 Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')](https://cwe.mitre.org/data/definitions/120.html)
* [CWE-121 Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121.html)
* [CWE-122 Heap-based Buffer Overflow](https://cwe.mitre.org/data/definitions/122.html)
* [CWE-124 Buffer Underwrite ('Buffer Underflow')](https://cwe.mitre.org/data/definitions/124.html)
* [CWE-125 Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)
* [CWE-126 Buffer Over-read](https://cwe.mitre.org/data/definitions/126.html)
* [CWE-190 Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)
* [CWE-191 Integer Underflow (Wrap or Wraparound)](https://cwe.mitre.org/data/definitions/191.html)
* [CWE-196 Unsigned to Signed Conversion Error](https://cwe.mitre.org/data/definitions/196.html)
* [CWE-367 Time-of-check Time-of-use (TOCTOU) Race Condition](https://cwe.mitre.org/data/definitions/367.html)
* [CWE-415 Double Free](https://cwe.mitre.org/data/definitions/415.html)
* [CWE-416 Use After Free](https://cwe.mitre.org/data/definitions/416.html)
* [CWE-457 Use of Uninitialized Variable](https://cwe.mitre.org/data/definitions/457.html)
* [CWE-459 Incomplete Cleanup](https://cwe.mitre.org/data/definitions/459.html)
* [CWE-467 Use of sizeof() on a Pointer Type](https://cwe.mitre.org/data/definitions/467.html)
* [CWE-787 Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html)
* [CWE-788 Access of Memory Location After End of Buffer](https://cwe.mitre.org/data/definitions/788.html)
* [CWE-824 Access of Uninitialized Pointer](https://cwe.mitre.org/data/definitions/824.html)



## X03:2025 AI 생성 코드에 대한 부적절한 신뢰('바이브 코딩')

### 배경

현재 전 세계가 AI에 대해 이야기하고 활용하고 있으며, 소프트웨어 개발자도 예외는 아니다. 아직 AI 생성 코드와 직접 관련된 CVE나 CWE는 없지만, AI 생성 코드가 인간이 작성한 코드보다 더 많은 취약점을 포함하는 경우가 많다는 사실은 널리 알려져 있고 문서로도 입증되어 있다.


### 설명

우리는 소프트웨어 개발 관행이 변화하여, AI의 도움을 받아 작성한 코드뿐 아니라 사람의 검토 없이 거의 전적으로 작성되어 그대로 커밋되는 코드(흔히 '바이브 코딩'이라 불림)까지 포함하는 흐름을 보고 있다. 예전에도 블로그나 웹사이트의 코드 스니펫을 깊이 생각하지 않고 복사하는 것이 결코 바람직하지 않았던 것과 마찬가지로, 이 경우에는 문제가 더 악화된다. 양질의 보안 코드 스니펫은 예나 지금이나 드물며, 시스템적 제약으로 인해 AI가 이런 좋은 예시를 통계적으로 잘 나타내지 못할 수 있다.


### 대응 방안
AI를 활용해 코드를 작성하는 모든 사람에게 다음 사항을 고려할 것을 권고한다.

* AI가 작성했거나 온라인 포럼에서 복사한 코드일지라도, 제출하는 모든 코드를 읽고 완전히 이해할 수 있어야 한다. 커밋하는 모든 코드에 대한 책임은 본인에게 있다.
* 모든 AI 지원 코드를 취약점 관점에서 철저히 검토해야 하며, 이상적으로는 직접 육안으로 확인하고 목적에 맞게 제작된 (정적 분석 같은) 보안 도구를 병행해야 한다. [OWASP Cheat Sheet Series: Secure Code Review](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html)에 기술된 전통적인 코드 리뷰 기법의 사용을 고려한다.
* 이상적으로는 직접 코드를 작성하고, AI가 개선안을 제시하게 한 뒤, 제안된 코드를 검증하고, 결과에 만족할 때까지 AI가 수정을 하도록 한다.
* 조직의 보안 코딩 가이드라인/표준/정책 등과 같이, 자체적으로 수집, 검토한 안전한 코드 샘플과 문서를 기반으로 하는 RAG(Retrieval Augmented Generation) 서버 사용을 고려한다. 또한 RAG 서버가 정책이나 표준을 강제하도록 한다.
* 선택한 AI와 함께 사용할 수 있도록, 개인정보 보호와 보안을 위한 가드레일 구현 도구를 구매하는 방안을 고려해야 한다.
* 사설(private) AI의 구매를 고려하며, 이상적으로는 조직의 데이터, 쿼리, 코드 또는 기타 민감한 정보로 AI를 학습시키지 않는다는 계약(개인정보 보호 협약 포함)을 체결한다.
* IDE와 AI 사이에 모델 컨텍스트 프로토콜(Model Context Protocol, MCP) 서버를 구축하고, 선택한 보안 도구의 사용을 강제하도록 설정하는 것을 고려한다.
* 개발자(및 전 직원)에게 조직 내에서 AI를 어떻게 사용해야 하고 사용하지 말아야 하는지 안내하기 위해, 소프트웨어 개발 생명 주기(Software Development Life Cycle, SDLC)의 일부로 정책과 프로세스를 수립한다.
* IT 보안 모범 사례를 반영한, 유용하고 효과적인 프롬프트 목록을 작성한다. 이상적으로는 내부 시큐어 코딩 가이드라인도 반영해야 한다. 개발자는 해당 프롬프트를 프로그램 개발의 출발점으로 사용할 수 있다.
* AI는 시스템 개발 생명 주기의 각 단계에 포함될 가능성이 높으므로, 효과적이고 안전하게 사용해야 한다. AI는 지혜롭게 사용해야 한다.
* 실제로 복잡한 함수, 비즈니스 크리티컬 프로그램, 또는 장기간 사용되는 프로그램에는 바이브 코딩을 사용하는 것을 권장하지 **<u>않는다</u>**.
* 섀도우 AI(Shadow AI) 사용에 대한 기술적 점검과 보호 조치를 구현한다.
* 개발자에게 조직의 정책뿐만 아니라, 안전한 AI 사용 및 소프트웨어 개발에서의 AI 활용 모범 사례에 대한 교육을 실시한다.


### 참조

* [OWASP Cheat Sheet: Secure Code Review](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html)


###  해당되는 CWE 목록.
-none-
