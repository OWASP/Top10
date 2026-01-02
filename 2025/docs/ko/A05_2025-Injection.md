# A05:2025 인젝션 ![icon](../assets/TOP_10_Icons_Final_Injection.png){: style="height:80px;width:80px" align="right"}

## 배경. 

인젝션은 3위에서 5위로 두 단계 하락했으며, A04:2025-암호 실패 및 A06:2025-안전하지 않은 설계 대비 상대적 위치는 변동이 없다. 인젝션은 가장 많이 테스트 된 카테고리 중 하나로, 조사된 모든 애플리케이션에서 테스트 되었다. 인젝션은 다른 카테고리보다 가장 많은 수의 CVE를 보유했으며, 총 37개의 CWE가 포함되었다. 이 카테고리에는 총 3만 개가 넘는 CVE가 보고된 크로스 사이트 스크립팅(높은 빈도/낮은 영향)과 1만 4천 개가 넘는 CVE가 보고된 SQL 인젝션(낮은 빈도/높은 영향)이 포함되었다. CWE-79 웹 페이지 생성 중 입력값의 부적절한 중립화(크로스 사이트 스크립팅)에 대한 보고된 CVE 수가 매우 많아 이 범주의 평균 가중 영향도가 낮아졌다.

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
   <td>37
   </td>
   <td>13.77%
   </td>
   <td>3.08%
   </td>
   <td>100.00%
   </td>
   <td>42.93%
   </td>
   <td>7.15
   </td>
   <td>4.32
   </td>
   <td>1,404,249
   </td>
   <td>62,445
   </td>
  </tr>
</table>



## 설명. 

인젝션 취약점은 신뢰할 수 없는 사용자 입력이 인터프리터(예: 브라우저, 데이터베이스, 커맨드 라인)로 전송되어 인터프리터가 해당 입력의 일부를 명령으로 실행하도록 허용하는 애플리케이션 결함이다.

다음과 같은 경우 인젝션 공격에 취약할 수 있다.

* 사용자가 제공한 데이터가 애플리케이션에 의해 검증, 필터링 또는 새니타이징되지 않는 경우.
* 동적 쿼리 또는 파라미터 바인딩이 없는 호출을 해당 컨텍스트에 맞는 이스케이핑 없이 인터프리터에 직접 전달하는 경우.
* 객체 관계형 매핑(object-relational mapping, ORM) 검색 파라미터에 새니타이징 되지 않은 입력값을 사용하여, 의도하지 않은 추가 민감 데이터 레코드를 조회하는 경우.
* 잠재적으로 악의적일 수 있는 데이터가 그대로 사용되거나, 기존 SQL 또는 커맨드 뒤에 문자열로 이어 붙여지는 경우. 그 결과 동적 쿼리, 커맨드, 또는 저장 프로시저에서 원래의 구문과 공격자가 주입한 악성 데이터가 함께 포함되게 된다.

대표적인 인젝션 유형으로는 SQL, NoSQL, OS 커맨드, 객체 관계형 매핑(ORM), LDAP, 그리고 EL 표현식(Expression Language) 및 OGNL 표현식(Object Graph Navigation Library) 인젝션 있다. 인터프리터 종류가 달라도 핵심 원리는 동일하다. 효과적인 탐지를 위해서는 소스 코드 리뷰와 함께, 모든 파라미터, 헤더, URL, 쿠키, JSON, SOAP, 및 XML 데이터 입력에 대한 자동화(퍼징 포함) 테스트하는 게 좋다. CI/CD 파이프라인에 정적(SAST), 동적(DAST), 및 인터랙티브(IAST) 애플리케이션 보안 테스트 도구를 통합하여, 것도 운영 환경 배포 전에 인젝션 결함을 식별하는 데 도움이 될 수 있다.

한편 LLM 환경에서도 유사한 계열의 인젝션 취약점이 흔해지고 있다. 이는 [OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/)에서 별도로 다룬다. 특히 [LLM01:2025 프롬프트 인젝션](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) 항목에서 관련 내용을 확인할 수 있다.


## 대응 방안. 

인젝션 공격을 예방하는 최선의 방법은 데이터를 명령 및 쿼리로부터 분리하여 유지하는 것이다.

* 가장 권장되는 방식은 안전한 API를 사용하는 것이다. 이는 인터프리터를 전혀 사용하지 않거나, 입력값을 파라미터 화하도록 하는 인터페이스를 제공하거나, 객체 관계형 매핑(ORM) 도구를 사용하는 방식을 통해 이를 달성할 수 있다.
**참고:** 저장 프로시저는 파라미터화되어 있더라도, PL/SQL 또는 T‑SQL 내부에서 문자열 결합으로 쿼리와 데이터를 연결하거나, EXECUTE IMMEDIATE / exec()처럼 동적 실행 기능으로 적대적 입력을 실행하면 SQL 인젝션이 발생할 수 있다.

데이터를 커맨드로 분리하는 것이 불가능한 경우, 다음 방법을 사용하여 위협을 줄일 수 있다.

* 서버 측 입력값 검증은 허용 목록 기반을 사용한다. 다만 텍스트 입력란이나 모바일 API처럼 특수문자 입력이 필요한 경우가 많아, 이것만으로는 완전한 방어가 되기 어렵다.
* 불가피하게 동적 쿼리를 사용하는 지점이 남아 있다면, 사용 중인 인터프리터에서 사용하는 규칙에 맞춰 특수문자를 이스케이프 처리한다.
**참고:** 테이블 명과 칼럼 명 같은 SQL 구문들은 이스케이핑 할 수 없으므로, 사용자가 제공한 입력값을 쓰는 것은 위험하다. 이런 문제는 보고서 생성 기능에서 자주 나타난다.

**경고** 위 방법들은 문자열을 파싱하고 이스케이프하는 복잡한 처리를 전제로 하며, 구현 실수가 발생하기 쉽고 시스템 내부 동작이 조금만 바뀌어도 방어가 쉽게 무력화될 수 있다.

## 공격 시나리오 예시.

**시나리오 1:** 애플리케이션이 신뢰할 수 없는 데이터를 사용하여 다음과 같은 취약 방식으로 SQL을 호출한다.

```
String query = "SELECT * FROM accounts WHERE custID='" + request.getParameter("id") + "'";
```

공격자는 'id' 값에 `' OR '1'='1`와 같은 페이로드를 주입하여 다음과 같이 요청을 보낼 수 있다.

```
http://example.com/app/accountView?id=' OR '1'='1
```

그 결과 쿼리의 내용이 변경되어 accounts 테이블의 전체 레코드가 조회될 수 있다. 상황에 따라 공격자는 데이터 변경 및 삭제 또는 저장된 프로시저 실행 등 더 심각한 행위를 유도할 수도 있다.

**시나리오 2:** 프레임워크를 사용하더라도 이를 과신하면, 여전히 인젝션에 취약할 수 있다. 취약한 하이퍼네이트 쿼리 언어(Hibernate Query Language, HQL)의 경우를 보자.

```
Query HQLQuery = session.createQuery("FROM accounts WHERE custID='" + request.getParameter("id") + "'");
```

공격자는 입력값으로 `' OR custID IS NOT NULL OR custID='`를 입력한다. 이는 필터를 우회하고 모든 계정의 레코드를 반환한다. HQL은 로우 raw SQL보다 위험한 함수가 더 적지만, 사용자 입력 값이 쿼리의 문자열로 연결될 때 여전히 허용되지 않은 데이터에 접근할 수 있다.

**시나리오 3:** 애플리케이션이 사용자 입력을 OS 커맨드으로 사용한다.

```
String cmd = "nslookup " + request.getParameter("domain");
Runtime.getRuntime().exec(cmd);
```

공격자는 `example.com; cat /etc/passwd`를 입력하여 서버에서 임의의 명령을 실행한다.

## 참조.

* [OWASP Proactive Controls: Secure Database Access](https://owasp.org/www-project-proactive-controls/v3/en/c3-secure-database)
* [OWASP ASVS: V5 Input Validation and Encoding](https://owasp.org/www-project-application-security-verification-standard)
* [OWASP Testing Guide: SQL Injection,](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection) [Command Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection), and [ORM Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection)
* [OWASP Cheat Sheet: Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
* [OWASP Cheat Sheet: SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
* [OWASP Cheat Sheet: Injection Prevention in Java](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet_in_Java.html)
* [OWASP Cheat Sheet: Query Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)
* [OWASP Automated Threats to Web Applications – OAT-014](https://owasp.org/www-project-automated-threats-to-web-applications/)
* [PortSwigger: Server-side template injection](https://portswigger.net/kb/issues/00101080_serversidetemplateinjection)
* [Awesome Fuzzing: a list of fuzzing resources](https://github.com/secfigo/Awesome-Fuzzing) 



## 해당되는 CWE.

* [CWE-20 Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

* [CWE-74 Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)

* [CWE-76 Improper Neutralization of Equivalent Special Elements](https://cwe.mitre.org/data/definitions/76.html)

* [CWE-77 Improper Neutralization of Special Elements used in a Command ('Command Injection')](https://cwe.mitre.org/data/definitions/77.html)

* [CWE-78 Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)

* [CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)

* [CWE-80 Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)](https://cwe.mitre.org/data/definitions/80.html)

* [CWE-83 Improper Neutralization of Script in Attributes in a Web Page](https://cwe.mitre.org/data/definitions/83.html)

* [CWE-86 Improper Neutralization of Invalid Characters in Identifiers in Web Pages](https://cwe.mitre.org/data/definitions/86.html)

* [CWE-88 Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')](https://cwe.mitre.org/data/definitions/88.html)

* [CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')](https://cwe.mitre.org/data/definitions/89.html)

* [CWE-90 Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')](https://cwe.mitre.org/data/definitions/90.html)

* [CWE-91 XML Injection (aka Blind XPath Injection)](https://cwe.mitre.org/data/definitions/91.html)

* [CWE-93 Improper Neutralization of CRLF Sequences ('CRLF Injection')](https://cwe.mitre.org/data/definitions/93.html)

* [CWE-94 Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)

* [CWE-95 Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html)

* [CWE-96 Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')](https://cwe.mitre.org/data/definitions/96.html)

* [CWE-97 Improper Neutralization of Server-Side Includes (SSI) Within a Web Page](https://cwe.mitre.org/data/definitions/97.html)

* [CWE-98 Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion')](https://cwe.mitre.org/data/definitions/98.html)

* [CWE-99 Improper Control of Resource Identifiers ('Resource Injection')](https://cwe.mitre.org/data/definitions/99.html)

* [CWE-103 Struts: Incomplete validate() Method Definition](https://cwe.mitre.org/data/definitions/103.html)

* [CWE-104 Struts: Form Bean Does Not Extend Validation Class](https://cwe.mitre.org/data/definitions/104.html)

* [CWE-112 Missing XML Validation](https://cwe.mitre.org/data/definitions/112.html)

* [CWE-113 Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')](https://cwe.mitre.org/data/definitions/113.html)

* [CWE-114 Process Control](https://cwe.mitre.org/data/definitions/114.html)

* [CWE-115 Misinterpretation of Output](https://cwe.mitre.org/data/definitions/115.html)

* [CWE-116 Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html)

* [CWE-129 Improper Validation of Array Index](https://cwe.mitre.org/data/definitions/129.html)

* [CWE-159 Improper Handling of Invalid Use of Special Elements](https://cwe.mitre.org/data/definitions/159.html)

* [CWE-470 Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')](https://cwe.mitre.org/data/definitions/470.html)

* [CWE-493 Critical Public Variable Without Final Modifier](https://cwe.mitre.org/data/definitions/493.html)

* [CWE-500 Public Static Field Not Marked Final](https://cwe.mitre.org/data/definitions/500.html)

* [CWE-564 SQL Injection: Hibernate](https://cwe.mitre.org/data/definitions/564.html)

* [CWE-610 Externally Controlled Reference to a Resource in Another Sphere](https://cwe.mitre.org/data/definitions/610.html)

* [CWE-643 Improper Neutralization of Data within XPath Expressions ('XPath Injection')](https://cwe.mitre.org/data/definitions/643.html)

* [CWE-644 Improper Neutralization of HTTP Headers for Scripting Syntax](https://cwe.mitre.org/data/definitions/644.html)

* [CWE-917 Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')](https://cwe.mitre.org/data/definitions/917.html)
