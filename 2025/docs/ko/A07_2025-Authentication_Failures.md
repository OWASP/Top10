# A07:2025 인증 실패 ![icon](../assets/TOP_10_Icons_Final_Identification_and_Authentication_Failures.png){: style="height:80px;width:80px" align="right"}


## 배경 

인증 실패는 동일하게 7위를 유지하고 있으며, 이 카테고리에 해당되는 36개의 CWE를 보다 정확하게 반영하기 위해 명칭을 약간 변경했다. 표준화된 프레임워크로부터의 이점에도 불구하고, 이 카테고리는 2021년부터 7위를 유지해 왔다. 대표적인 CWE로는 *CWE-259: 하드코딩된 비밀번호 사용*, *CWE-297: 호스트 불일치 상황에서의 인증서 검증 미흡*, *CWE-287: 부적절한 인증*, *CWE-384: 세션 고정(Session Fixation)*, 그리고 *CWE-798: 하드코딩된 자격 증명 사용*이 포함된다.


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
   <td>36
   </td>
   <td>15.80%
   </td>
   <td>2.92%
   </td>
   <td>100.00%
   </td>
   <td>37.14%
   </td>
   <td>7.69
   </td>
   <td>4.44
   </td>
   <td>1,120,673
   </td>
   <td>7,147
   </td>
  </tr>
</table>



## 설명 

공격자가 시스템을 속여 유효하지 않거나 잘못된 사용자 정보를 정상 사용자로 인증되도록 만들 수 있는 경우, 해당 취약점이 존재한다고 판단한다. 특히 애플리케이션이 아래와 같은 행위를 실질적으로 방어하지 못하면 인증 관련 약점이 있을 수 있다.

* 공격자가 유출된 사용자명과 비밀번호 목록을 이용해 수행하는 크리덴셜 스터핑(credential stuffing)과 같은 자동화 공격을 방어하지 못하는 경우. 최근에는 이러한 공격 유형이 하이브리드 비밀번호 공격(비밀번호 스프레이 공격)으로 확장되었으며, 공격자가 유출된 자격 증명을 변형하거나 숫자를 추가하여 접근 권한을 획득하는 방식이다. 예를 들어 획득된 비밀번호가 Password1!인 경우 Password2!, Password3! 등을 순차적으로 시도하는 것이다.

* 무차별 대입(brute force) 또는 기타 자동화된 스크립트 기반 공격을 방어하지 못하는 경우 혹은 이러한 공격이 신속하게 차단되지 않는 경우.

* 기본 비밀번호, 취약한 비밀번호 또는 널리 알려진 비밀번호를 허용하는 경우. 예를 들어 "Password1"와 같은 비밀번호나 "admin" 사용자명과 "admin" 비밀번호와 같은 조합이 있다.

* 이미 유출된 아이디 및 비밀번호로 사용자가 새 계정을 생성할 수 있는 경우.

* 안전하지 않은 "질문-답변 방식 비밀번호 찾기"과 같은 취약하거나 비효율적인 자격 증명 복구 및 비밀번호 찾기 프로세스를 사용하는 경우.

* 평문, 암호화된, 또는 약한 해시(hash)로 해시된 비밀번호를 사용하는 경우. [A04:2025-암호 실패](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/) 참고.

* 다중 인증(MFA)이 누락되어 있거나 효과적이지 않은 경우.

* 다중 인증을 사용할 수 없을 때 적용되는 대체 수단(fallback)이 취약하거나 효과적이지 않은 경우.

* 세션 식별자가 URL, 히든 필드, 또는 클라이언트가 접근 가능한 기타 안전하지 않은 위치에 노출되는 경우.

* 로그인 성공 후에도 동일한 세션 식별자를 재사용하는 경우.

* 로그아웃 또는 비활성 기간 동안 사용자 세션 또는 인증 토큰(싱글 사인온[SSO] 토큰)을 올바르게 무효화하지 않는 경우.

* 제공된 자격 증명의 범위(scope) 및 의도된 대상(audience)을 올바르게 검증하지 않는 경우.

## 대응 방안 

* 가능하다면 MFA를 도입하고 강제 적용하여 자동화된 크리덴셜 스터핑, 무차별 대입 공격 및 탈취된 자격 증명의 재사용 공격을 차단한다.

* 가능하다면 사용자가 더 나은 선택을 할 수 있도록 비밀번호 관리자의 사용을 장려하고 활성화한다.

* 배포 시점에 기본 계정 및 기본 비밀번호가 남아있지 않도록 하며, 특히 관리자 더 주의를 기울인다.

* 신규 및 변경 비밀번호에 대해 최악의 비밀번호 Top 10,000에 기반하여 해당 비밀번호를 설정하지 못하도록 적용한다.

* 신규 계정 생성 및 비밀번호 변경 시, 알려진 유출 자격 증명 목록에 있는지 검증한다. (예: [haveibeenpwned.com](https://haveibeenpwned.com) 사용.)

* 비밀번호 정책(길이, 복잡도, 주기적 변경)은 [NIST 800-63B 섹션 5.1.1](https://pages.nist.gov/800-63-3/sp800-63b.html#:~:text=5.1.1%20Memorized%20Secrets) 등 현대적 근거 기반 가이드에 맞춰 수립한다.

* 유출이 의심되지 않는 한, 사람에게 비밀번호를 주기적으로 변경하도록 강제하지 않는다. 유출이 의심되는 경우, 즉시 비밀번호 재설정을 강제한다.

* 계정 열거 공격에 계정 존재 여부가 드러나지 않도록 회원가입, 비밀번호 복구, API 응답 메시지를 결과와 무관하게 동일(예: "올바르지 않은 유저명 혹은 패스워드")하게 유지한다.

* 로그인 실패에 대해 횟수 제한 또는 점진적인 지연을 적용하되, 과도한 통제로 서비스 거부 공격이 유발되지 않도록 설계한다. 또한 실패 이벤트를 로깅하고 크리덴셜 스터핑이나 무차별 대입 공격 징후 탐지 시 관리자에게 알림을 발송한다.

* 세션은 높은 엔트로피를 가진 새로운 무작위 세션 ID를 생성하는 서버 측의 안전한 내장 세션 관리자를 사용한다. 세션 식별자는 URL에 포함되지 않아야 하며, 쿠키에 안전하게 저장되고, 로그아웃하거나 유휴 시간 및 최대 세션 시간 초과 시 무효가 되어야 한다.

* 가능하면 인증, 아이덴티티, 세션 관리를 자체 구현하기보다 사전 제작된, 신뢰할 수 있는 시스템을 사용한다. 가능하다면 검증되고 충분히 테스트 된 도구를 구매/활용해 구현 위험을 줄인다.

* 제공된 자격 증명의 의도된 용도를 검증한다. 예를 들어 JWT의 경우 `aud`와 `iss` 클레임 및 범위를 검증한다.

## 공격 시나리오 예시 

**시나리오 1:** 크리덴셜 스터핑은 유출된 계정-비밀번호 조합을 자동으로 대입하는 대표적인 공격이다. 최근에는 사람들의 습관을 악용해 비밀번호의 숫자를 증가 및 감소시켜 가며 공격하는 사례가 확인되고 있다. 예를 들어 'Winter2025'를 'Winter2026'으로 바꾸거나, 'ILoveMyDog6'를 'ILoveMyDog7' 또는 'ILoveMyDog5'로 바꾸는 식이다. 이러한 공격을 하이브리드 크리덴셜 스터핑 공격 또는 패스워드 스프레이 공격이라고 하며, 기존의 크리덴셜 스터핑보다 더 효과적일 수 있다. 애플리케이션이 자동화된 위협(무차별 대입, 스크립트, 봇) 또는 크리덴셜 스터핑에 대한 방어를 구현하지 않으면, 해당 애플리케이션은 자격 증명이 유효한지 여부를 판별하는 패스워드 오라클로 악용되어 비인가 접근을 획득하는 데 사용될 수 있다.

**시나리오 2:** 인증 공격의 상당수는 비밀번호만으로 인증을 구성하는 구조에서 발생한다. 과거에 권장되던 주기적 비밀번호 변경 및 과도한 복잡도 정책은 오히려 비밀번호 재사용을 늘리고 기억하기 쉬운 취약 패턴을 만들 수 있다. 따라서 NIST 800-63의 권고에 맞춰 불필요한 정책을 지양하고, 중요 시스템에는 다중 인증(MFA)을 기본으로 강제 적용하는 것이 바람직하다.

**시나리오 3:** 애플리케이션의 세션 타임아웃이 올바르게 구현되지 않았다. 사용자가 공용 컴퓨터에서 애플리케이션에 접근한 뒤 "로그아웃" 버튼 대신 브라우저 탭을 닫고 자리를 떠난다. 또 다른 예로, SSO(Single Sign-On) 환경에서 단일 로그아웃(Single Logout)이 지원되지 않는 경우가 있다. 즉, SSO로 메일, 문서 시스템, 채팅 시스템에 한 번에 로그인되지만, 로그아웃은 현재 사용 중인 시스템에서만 로그아웃 처리된다. 이 상태에서 공격자가 동일한 브라우저를 사용하면, 다른 애플리케이션에는 세션이 남아 있어 피해자 계정에 접근할 수 있다. 동일한 문제는 민감한 애플리케이션이 적절히 종료되지 않은 상태에서 동료가 잠금 해제된 컴퓨터에 일시적으로 접근할 수 있는 사무실 환경에서도 발생할 수 있다.

## 참조

* [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

* [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/01-introduction/05-introduction)


## 해당 CWE 목록

* [CWE-258 Empty Password in Configuration File](https://cwe.mitre.org/data/definitions/258.html)

* [CWE-259 Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)

* [CWE-287 Improper Authentication](https://cwe.mitre.org/data/definitions/287.html)

* [CWE-288 Authentication Bypass Using an Alternate Path or Channel](https://cwe.mitre.org/data/definitions/288.html)

* [CWE-289 Authentication Bypass by Alternate Name](https://cwe.mitre.org/data/definitions/289.html)

* [CWE-290 Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)

* [CWE-291 Reliance on IP Address for Authentication](https://cwe.mitre.org/data/definitions/291.html)

* [CWE-293 Using Referer Field for Authentication](https://cwe.mitre.org/data/definitions/293.html)

* [CWE-294 Authentication Bypass by Capture-replay](https://cwe.mitre.org/data/definitions/294.html)

* [CWE-295 Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

* [CWE-297 Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/297.html)

* [CWE-298 Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/298.html)

* [CWE-299 Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/299.html)

* [CWE-300 Channel Accessible by Non-Endpoint](https://cwe.mitre.org/data/definitions/300.html)

* [CWE-302 Authentication Bypass by Assumed-Immutable Data](https://cwe.mitre.org/data/definitions/302.html)

* [CWE-303 Incorrect Implementation of Authentication Algorithm](https://cwe.mitre.org/data/definitions/303.html)

* [CWE-304 Missing Critical Step in Authentication](https://cwe.mitre.org/data/definitions/304.html)

* [CWE-305 Authentication Bypass by Primary Weakness](https://cwe.mitre.org/data/definitions/305.html)

* [CWE-306 Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)

* [CWE-307 Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)

* [CWE-308 Use of Single-factor Authentication](https://cwe.mitre.org/data/definitions/308.html)

* [CWE-309 Use of Password System for Primary Authentication](https://cwe.mitre.org/data/definitions/309.html)

* [CWE-346 Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)

* [CWE-350 Reliance on Reverse DNS Resolution for a Security-Critical Action](https://cwe.mitre.org/data/definitions/350.html)

* [CWE-384 Session Fixation](https://cwe.mitre.org/data/definitions/384.html)

* [CWE-521 Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)

* [CWE-613 Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html)

* [CWE-620 Unverified Password Change](https://cwe.mitre.org/data/definitions/620.html)

* [CWE-640 Weak Password Recovery Mechanism for Forgotten Password](https://cwe.mitre.org/data/definitions/640.html)

* [CWE-798 Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

* [CWE-940 Improper Verification of Source of a Communication Channel](https://cwe.mitre.org/data/definitions/940.html)

* [CWE-941 Incorrectly Specified Destination in a Communication Channel](https://cwe.mitre.org/data/definitions/941.html)

* [CWE-1390 Weak Authentication](https://cwe.mitre.org/data/definitions/1390.html)

* [CWE-1391 Use of Weak Credentials](https://cwe.mitre.org/data/definitions/1391.html)

* [CWE-1392 Use of Default Credentials](https://cwe.mitre.org/data/definitions/1392.html)

* [CWE-1393 Use of Default Password](https://cwe.mitre.org/data/definitions/1393.html)
