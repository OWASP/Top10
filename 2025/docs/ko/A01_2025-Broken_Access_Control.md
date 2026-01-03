#  A01:2025 불충분한 접근 제어![icon](../assets/TOP_10_Icons_Final_Broken_Access_Control.png){: style="height:80px;width:80px" align="right"}



## 배경. 

불충분한 접근 제어는 OWASP TOP 10에서 1위를 유지하고 있다. 테스트된 모든 애플리케이션에서 불충분한 접근 제어 취약점이 발견되었으며, 주목할만한 CWE는 CWE-200: 비인기자에게 민감정보 노출, CWE-201: 전송된 데이터로부터의 민감정보 노출, `CWE-918: 서버측 요청 위조(SSRF)`, 그리고 `CWE-352: 크로스 사이트 요청 위조(CSRF)` 가 있다. 해당 카테고리는 제공받은 데이터 기준 발생 건수가 가장 많았으며, 관련된 CVE 건수는 두 번째로 많았다.

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

접근 제어는 사용자가 의도된 권한을 벗어나는 행위를 하지 못하도록 정책을 강제한다. 접근 제어 실패는 일반적으로 비인가자 정보 유출,  데이터 수정 및 삭제(파괴), 또는 사용자 제한사항에 벗어나는 비즈니스 기능을 수행으로 이어질 수 있다. 흔히 발견되는 불충분한 접근 제어 취약점은 목록은 다음과 같다.

* 최소 권한 원칙 위반, 우선 거부 정책(Deny by Default)이 적용되지 않아 제한된 기능, 역할, 사용자들에게만 허용된 접근 권한이 불특정 다수에게 허용되는 경우.
* 조작된 URL(파라미터 변조 또는 강제 브라우징), 애플리케이션 내부 상태값 변조, HTML 페이지 조작 또는 공격 도구를 통해 API 요청을 조작함으로써 접근 제어 검사 우회가 가능한 경우
* 고유 식별자를 이용해 권한이 필요한 다른 사용자 계정을 조회 또는 수정할 수 있는 경우(안전하지 않은 직접 객체 참조, Insecure Direct Object References)
* 접근 가능한 API의 POST, PUT, DELETE 메서드에 대한 접근 제어가 없는 경우
* 권한 상승. 로그인 과정 없이 다른 사용자로 가장하거나 또는 사용자가 보유한 이상의 권한을 획득하는 경우. (예시. 관리자 접근 권한)
* 메타데이터 조작, 예를 들어 JWT 토큰, 접근 통제 토큰, 쿠키 또는 히든 필드 값을 수정하여 재전송 하거나 위조하여 권한 상승하는 경우 또는 JWT 무효화가 없거나 우회하여 악용하는 경우
* 교차 출처 리소스 공유 (Cross-Origin Resource Sharing, CORS)의 잘못된 설정으로 비인가자 또는 신뢰할 수 없는 출처(Origin)로부터 API 접근을 허용하는 경우
* 강제 브라우징 (URL 예측)을 통해 인증이 필요한 페이지에 인증없이 접근하거나, 일반 사용자가 권한이 필요한 페이지에 접근할 경우


## 대응 방안. 

접근 제어는 공격자가 접근 제어 검사나 메타데이터를 변조할 수 없는 곳에서 신뢰할 수 있는 서버측 코드나 서버리스 API들로 수행될 때 실효성이 있다. 



* 공개 리소스 제외 모든 리소스는 우선 거부 정책(Deny By Default)을 따라야 한다.
* 접근제어 매커니즘을 구현한 후엔 전체 애플리케이션에 재사용하고 교차 출처 리소스 검증(CORS) 사용을 최소화 한다.
* 모델 수준의 접근 제어는 레코드 소유자 기준으로 접근 권한을 제한하도록 한다. 다른 사용자가 임의의 레코드에 대해 생성, 조회, 수정, 삭제를 수행하도록 하지 못하게 한다.
* 애플리케이션의 고유한 비즈니스 제약사항은 도메인 모델에 의해 검사한다.
* 웹 서버 디렉토리 리스팅 비활성화 여부와 웹 루트에 파일 메타데이터 및 (예시. .git 디렉토리) 백업 파일이 존재하지 않는지 확인한다.
* 접근 제어 실패를 로깅하고 필요한 경우엔 관리자에게 알린다. (예시. 반복적 실패 또는 비정상적 접근 시도)
* 자동화된 공격 도구로 인한 피해를 최소화하기 위해 API 및 컨트롤러 접근에 대한 속도 제한(Rate limit)을 구현한다. 
* 상태기반 세션 식별자는 로그아웃 후 무효화 한다. 상태를 저장하지 않는 JWT 토큰의 경우 짧은 유효시간을 부여하여 공격을 위한 기회를 최소화하고, 유효기간이 긴 JWT 토큰은 리프레쉬 토큰 사용을 고려하며, OAuth 표준에 따른 토큰 취소도 고려한다.
* 간단하고 선언적 접근 제어를 제공하는 확립된 툴킷과 패턴을 사용한다.

개발자와 QA 담당자는 단위 및 통합 테스트에서 접근 제어를 포함해야 한다.

## 공격 시나리오 예시. 

**시나리오 1:** 이 기능은 계정 정보에 접근하는 SQL 요청에서 검증되지 않은 데이터를 사용한다.


```
pstmt.setString(1, request.getParameter("acct"));
ResultSet results = pstmt.executeQuery( );
```


공격자는 원하는 계정 정보를 전달하기 위해 단순하게 'acct' 파라미터를 변조할 수 있으며, 만약 해당 파라미터가 완벽하게 검증되지 않았을 시 공격자는 모든 사용자 계정 정보에 접근 가능하다.


```
https://example.com/app/accountInfo?acct=notmyacct
```


**시나리오 2:** 공격자는 단순하게 목적 URL로 브라우저를 이용해 접속할 수 있다. 하지만 관리자 페이지 접근하기 위해선 관리자 권한이 요구된다.


```
https://example.com/app/getappInfo
https://example.com/app/admin_getappInfo
```


먄약 인증되지 않은 사용자가 두 페이지 중 하나에 접근할 수 있다면, 보안 취약점으로 간주한다. 만약 관리자가 아닌 자가 관리자 페이지 접근이 가능하다면 이 또한 마찬가지다.


**시나리오 3:** 애플리케이션이 모든 접근 제어를 프론트 엔드에서만 구현할 경우. 공격자가 브라우저에서 동작하는 자바 스크립트 코드 때문에 `https://example.com/app/admin_getappInfo` 에 접근할 수 없지만, 커멘드 라인에서 단순하게 curl 명령어를 실행하면 접속할 수 있다.

```
$ curl https://example.com/app/admin_getappInfo
```




## 참조.

* [OWASP Proactive Controls: C1: Implement Access Control](https://top10proactive.owasp.org/archive/2024/the-top-10/c1-accesscontrol/)
* [OWASP Application Security Verification Standard: V8 Authorization](https://github.com/OWASP/ASVS/blob/master/5.0/en/0x17-V8-Authorization.md)
* [OWASP Testing Guide: Authorization Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README)
* [OWASP Cheat Sheet: Authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
* [PortSwigger: Exploiting CORS misconfiguration](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
* [OAuth: Revoking Access](https://www.oauth.com/oauth2-servers/listing-authorizations/revoking-access/)


## 해당되는 CWE.

* [CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)

* [CWE-23 Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html)

* [CWE-36 Absolute Path Traversal](https://cwe.mitre.org/data/definitions/36.html)

* [CWE-59 Improper Link Resolution Before File Access ('Link Following')](https://cwe.mitre.org/data/definitions/59.html)

* [CWE-61 UNIX Symbolic Link (Symlink) Following](https://cwe.mitre.org/data/definitions/61.html)

* [CWE-65 Windows Hard Link](https://cwe.mitre.org/data/definitions/65.html)

* [CWE-200 Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

* [CWE-201 Exposure of Sensitive Information Through Sent Data](https://cwe.mitre.org/data/definitions/201.html)

* [CWE-219 Storage of File with Sensitive Data Under Web Root](https://cwe.mitre.org/data/definitions/219.html)

* [CWE-276 Incorrect Default Permissions](https://cwe.mitre.org/data/definitions/276.html)

* [CWE-281 Improper Preservation of Permissions](https://cwe.mitre.org/data/definitions/281.html)

* [CWE-282 Improper Ownership Management](https://cwe.mitre.org/data/definitions/282.html)

* [CWE-283 Unverified Ownership](https://cwe.mitre.org/data/definitions/283.html)

* [CWE-284 Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)

* [CWE-285 Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)

* [CWE-352 Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)

* [CWE-359 Exposure of Private Personal Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/359.html)

* [CWE-377 Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)

* [CWE-379 Creation of Temporary File in Directory with Insecure Permissions](https://cwe.mitre.org/data/definitions/379.html)

* [CWE-402 Transmission of Private Resources into a New Sphere ('Resource Leak')](https://cwe.mitre.org/data/definitions/402.html)

* [CWE-424 Improper Protection of Alternate Path](https://cwe.mitre.org/data/definitions/424.html)

* [CWE-425 Direct Request ('Forced Browsing')](https://cwe.mitre.org/data/definitions/425.html)

* [CWE-441 Unintended Proxy or Intermediary ('Confused Deputy')](https://cwe.mitre.org/data/definitions/441.html)

* [CWE-497 Exposure of Sensitive System Information to an Unauthorized Control Sphere](https://cwe.mitre.org/data/definitions/497.html)

* [CWE-538 Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)

* [CWE-540 Inclusion of Sensitive Information in Source Code](https://cwe.mitre.org/data/definitions/540.html)

* [CWE-548 Exposure of Information Through Directory Listing](https://cwe.mitre.org/data/definitions/548.html)

* [CWE-552 Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html)

* [CWE-566 Authorization Bypass Through User-Controlled SQL Primary Key](https://cwe.mitre.org/data/definitions/566.html)

* [CWE-601 URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)

* [CWE-615 Inclusion of Sensitive Information in Source Code Comments](https://cwe.mitre.org/data/definitions/615.html)

* [CWE-639 Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)

* [CWE-668 Exposure of Resource to Wrong Sphere](https://cwe.mitre.org/data/definitions/668.html)

* [CWE-732 Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)

* [CWE-749 Exposed Dangerous Method or Function](https://cwe.mitre.org/data/definitions/749.html)

* [CWE-862 Missing Authorization](https://cwe.mitre.org/data/definitions/862.html)

* [CWE-863 Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html)

* [CWE-918 Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)

* [CWE-922 Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html)

* [CWE-1275 Sensitive Cookie with Improper SameSite Attribute](https://cwe.mitre.org/data/definitions/1275.html)
