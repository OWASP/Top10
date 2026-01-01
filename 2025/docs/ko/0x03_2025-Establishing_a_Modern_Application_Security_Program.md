# 현대적 애플리케이션 보안 체계 수립

OWASP Top 10 항목들은 보안 인식을 제고하기 위한 문서로, 각 항목에서 다루는 중요한 위험의 인식을 높이기 위함이다. 이는 모든 위험을 망라한 목록이 아니라, 대응을 시작하기 위한 출발점으로 활용하도록 구성되어 있다. 따라서, 이전 버전에서부터 각 항목에 해당하는 위험을 예방하고 더 나아가 전반적인 보안 수준을 높이기 위한 최선의 방법으로 애플리케이션 보안 체계를 시작하는 것을 권고해왔다. 이 페이지에서는 현대적 애플리케이션 보안 체계를 수립을을 어떻게 시작하고 구축하는지 다룰 것이다.

 

이미 애플리케이션 보안 체계를 운영 중이라면, [OWASP SAMM (Software Assurance Maturity Model)](https://owasp.org/www-project-samm/) 또는 DSOMM(DevSecOps Maturity Model) 같은 성숙도 모델을 활용하여 현재 수준에 대한 성숙도 평가를 수행하는 것을 고려하라. 해당 모델들은 포괄적이며 세부 항목까지 망라하고 있어, 체계를 고도화하는 과정에서 어디에 집중해야 하는지 파악하는 데 활용할 수 있다. OWASP SAMM 또는 DSOMM의 모든 항목을 수행해야만 제대로 하고 있다고 볼 수 있는 것은 아니며, 이는 방향을 제시하고 다양한 선택지를 제공하기 위한 것이다. 따라서 이는 현실적으로 달성하기 어려운 기준을 제시하거나 과도한 비용이 드는 체계를 수립하는 게 목적이 아니라, 개선을 위한 다양한 아이디어를 제공하기 위해 폭넓게 구성되어 있다.

 

애플리케이션 보안 체계를 처음 구축하는 단계이거나, 현재 팀의 상황에서 OWASP SAMM/DSOMM가 과도하다고 느껴진다면, 아래 조언을 참고하라.


### 1. 위험 기반 포트폴리오 관리 체계 수립

* 비즈니스 관점에서 애플리케이션 포트폴리오의 보안 요구사항을 식별한다. 이때 해당 데이터에 적용되는 개인정보보호 법령 및 관련 규제 요구사항을 기준으로 요구사항을 도출한다.

* 조직의 위험 수용 수준에 맞춰, 가능성과 영향도 기준을 표준화한 [통합 위험 평가 모델](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology)을 수립한다.

* 위의 정의된 모델에 따라 전체 애플리케이션 및 API의 위험을 평가하고 우선순위를 결정한 뒤, 결과를 구성 관리 데이터베이스(Configuration Management Database, CMDB)에 등록한다.

* 적용 범위와 요구되는 엄격도 수준을 정의하기 위한 가이드라인을 수립한다.


### 2. 탄탄한 기반을 통한 실행 체계 확보

* 모든 개발 조직이 준수할 애플리케이션 보안 최소 기준을 맞추기 위한 정책 및 표준을 수립한다.

* 수립한 정책 및 표준을 따를 수 있도록 재사용 가능한 공통 보안 통제를 정의하고 설계 및 개발 지침을 함께 제공한다.

* 개발자의 역할과 주제에 맞춘 애플리케이션 보안 교육 체계를 마련한다.


### 3. 기존 프로세스에 보안 내재화

* 기존 개발 및 운영 프로세스에 안전한 구현 및 검증 활동을 정의하고 내재화한다.

* 검증 활동에는 위협 모델링, 안전한 설계 및 설계 검토, 시큐어 코딩 및 코드 리뷰, 침투 테스트, 그리고 취약점 조치가 포함된다.

* 개발 및 프로젝트 팀이 각 활동을 성공적으로 수행할 수 있도록 주제별 분야 전문가(subject matter expert)와 지원 서비스를 제공한다.
 
* 현행 시스템 개발 수명 주기(system development life cycle, SDLC)와 모든 소프트웨어 보안 활동, 도구, 정책, 프로세스를 검토한 후 이를 문서화한다.

* 신규 소프트웨어의 경우, 시스템 개발 생명주기의 각 단계에 하나 이상의 보안 활동을 추가한다. 아래에서는 수행 가능한 다양한 제안을 제공한다. 이러한 신규 활동을 모든 신규 프로젝트 또는 소프트웨어 이니셔티브에 대해 수행하도록 보장한다. 이를 통해 각 신규 소프트웨어가 조직에 허용 가능한 보안 상태(security posture)로 제공(납품)됨을 알 수 있다.
* 새로운 소프트웨어 개발 시에는 시스템 개발 생명주기의 각 단계에 하나 이상의 보안 활동을 추가한다. 아래에서 수행 가능한 다양한 활동을 제시한다. 제시된 활동을 수행하여 모든 새로운 프로젝트 또는 소프트웨어에 조직의 요구 사항에 부합하는 보안 수준이 제공되도록 한다.

* 최종 산출물이 조직의 수용 가능한 위험 수준을 만족하도록 활동을 선정한다.

* 기존(때로는 레거시라고 함)의 소프트웨어의 경우 유지관리 계획을 수립한다. 안전한 애플리케이션을 유지하는 방법은 아래의 운영 및 변경 관리 섹션을 참고한다.


### 4. 애플리케이션 보안 교육

* 개발 조직의 보안 역량 강화를 위해 보안 챔피언(Security Champion) 제도 또는 개발자 대상 보안 교육 프로그램(보안 인식 프로그램이라고 부르기도 함)을 도입하는 방안을 검토한다. 이를 통해 개발자에게 필요한 지식을 교육할 수 있다. 이를 통해 개발자가 최신 보안 지식을 지속적으로 습득하고, 안전한 방식으로 업무를 수행할 수 있도록 지원하며, 조직 내 보안 문화를 보다 긍정적으로 만든다. 또한 보안팀과의 신뢰를 향상시키고 더 만족스러운 협업 관계를 형성할 수 있다. 관련 가이드는 [OWASP 보안 챔피언 가이드](https://securitychampions.owasp.org/)를 참고하며, 해당 가이드는 단계적으로 보강되고 있다.

* OWASP 교육 프로젝트는 개발자에게 웹 애플리케이션 보안을 교육하는 데 필요한 교육 자료를 제공한다. 취약점에 대한 실습 중심 학습을 위해 [OWASP Juice Shop Project](https://owasp.org/www-project-juice-shop/) 또는 [OWASP WebGoat](https://owasp.org/www-project-webgoat/)를 활용한다. 최신 동향을 유지하기 위해 [OWASP AppSec 컨퍼런스](https://owasp.org/events/), [OWASP 컨퍼런스 트레이닝](https://owasp.org/events/), 또는 지역 [OWASP Chapter](https://owasp.org/chapters/) 모임에 참여한다.


### 5. 지표 가시성 확보

* 지표를 기반으로 관리하라. 수집된 지표 및 분석 데이터를 기반으로 개선 활동과 예산 의사결정을 추진한다. 지표로는 보안 활동 준수, 신규 취약점 유입, 취약점 조치, 테스트된 애플리케이션 범위, 결함 유형별 밀도 및 발생 건수 등이 있다.

* 구현 및 검증 활동에서 축적된 데이터를 분석하여, 근본 원인(root cause)과 취약점 패턴을 식별하고, 전사 차원의 전략 및 시스템적 개선을 추진한다. 실수로부터 학습하고, 개선을 촉진하기 위해 긍정적 인센티브를 제공한다.


## Establish & Use Repeatable Security Processes and Standard Security Controls

### Requirements and Resource Management Phase:

* Collect and negotiate the business requirements for an application with the business, including the protection requirements with regard to confidentiality, authenticity, integrity and availability of all data assets, and the expected business logic.

* Compile the technical requirements including functional and nonfunctional security requirements. OWASP recommends you use the [OWASP Application Security Verification Standard (ASVS)(https://owasp.org/www-project-application-security-verification-standard/) as a guide for setting the security requirements for your application(s).

* Plan and negotiate the budget that covers all aspects of design, build, testing and operation, including security activities.

* Add security activities to your project schedule.

* Introduce yourself as the security representative at the project kick off, so they know who to talk to.


### Request for Proposals (RFP) and Contracting:

* Negotiate the requirements with internal or external developers, including guidelines and security requirements with respect to your security program, e.g. SDLC, best practices.

*  Rate the fulfillment of all technical requirements, including a planning and design phase.

*  Negotiate all technical requirements, including design, security, and service level agreements (SLA).

*  Adopt templates and checklists, such as [OWASP Secure Software Contract Annex](https://owasp.org/www-community/OWASP_Secure_Software_Contract_Annex).<br>**Note:** *The annex is for US contract law, so please consult qualified legal advice before using the sample annex.*


### Planning and Design Phase:

*  Negotiate planning and design with the developers and internal shareholders, e.g. security specialists.

* Define the security architecture, controls, countermeasures and design reviews appropriate to the protection needs and the expected threat level. This should be supported by security specialists.

* Rather than retrofitting security into your applications and APIs, it is far more cost effective to design the security in from the start. OWASP recommends the [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/index.html) and the [OWASP Proactive Controls](https://top10proactive.owasp.org/) as a good starting point for guidance on how to design security included from the beginning.

*  Perform threat modelling, see [OWASP Cheat Sheet: Threat Modeling](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html).

*  Teach your software architects secure design concepts and patterns and ask them to add them to their designs where possible.

*  Examine data flows with your developers.

*  Add security user stories alongside all of your other user stories.


### Secure Development Lifecycle:


* To improve the process your organization follows when building applications and APIs, OWASP recommends the [OWASP Software Assurance Maturity Model (SAMM)](https://owasp.org/www-project-samm/). This model helps organizations formulate and implement a strategy for software security that is tailored to the specific risks facing their organization.

*  Provide secure coding training to your software developers, and any other training you think will help them create more robust and secure applications.

*  Code review, see [OWASP Cheat Sheet: Secure Code Review](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html).

*  Give your developers security tools, then teach them how to use them, especially static analysis, software composition analysis, secret, and [Infrastructure-as-Code (IaC)](https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html) scanners.

*  Create guardrails for your developers, if possible (technical safeguards to steer them towards more secure choices).

*   Building strong and usable security controls is difficult. Offer secure defaults whenever possible, and create ‘paved roads’ (making the easiest way also the most secure way to do something, the obvious preferred way) whenever possible. The [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/index.html) are a good starting point for developers, and many modern frameworks now come with standard and effective security controls for authorization, validation, CSRF prevention, etc.

*  Give your developers security-related IDE plugins and encourage them to use them.

*  Provide them a secret management tool, licenses, and documentation on how to use it.

*  Provide them a private AI to use, ideally set up with a RAG server full of useful security documentation, prompts your team has written for better outcomes, and an MCP server that calls the security tooling of choice for your org. Teach them how to use AI safely, because they are going to do it whether you like it or not.


### Establish Continuous Application Security Testing:

*  Test the technical functions and integration with the IT architecture and coordinate business tests.

* Create “use” and “abuse” test cases from technical and business perspectives.

* Manage security tests according to internal processes, the protection needs, and the assumed threat level by the application.

* Provide security testing tools (fuzzers, DAST, etc.), a safe place to test, and training on how to use them, OR do the testing for them OR hire a tester

*  If you require a high level of assurance, consider a formal penetration test, as well as stress testing and performance testing.

*  Work with your developers to help them decide what they need to fix from the bug reports, and ensure their managers give them time to do it.


### Rollout:

* Put the application in operation and migrate from previously used applications if needed.

* Finalize all documentation, including the change management database (CMDB) and security architecture.


### 운영 및 변경 관리

*  Operations must include guidelines for the security management of the application (e.g. patch management).

*  Raise the security awareness of users and manage conflicts about usability vs. security.

*  Plan and manage changes, e.g. migrate to new versions of the application or other components like OS, middleware, and libraries.

*  Ensure all apps are in your inventory, with all important details documented. Update all documentation, including in the CMDB and the security architecture, controls, and countermeasures, including any runbooks or project documentation.

*  Perform logging, monitoring, and alerting for all apps. Add it if it’s missing.

*  Create processes for effective and efficient updating and patching.

*  Create regular scanning schedules (hopefully dynamic, static, secrets, IaC, and software composition analysis).

*  SLAs for fixing security bugs.

*  Provide a way for employees (and ideally also your customers) to report bugs.

*  Establish a trained incident response team that understands what software attacks look like, observability tooling.

*  Run blocking or shielding tools to stop automated attacks.

*  Annual (or more often) hardening of configurations.

*  At least annual penetration testing (depending upon the level assurance required for your app).

*  Establish processes and tooling for hardening and protecting your software supply chain.

*  Establish and update business continuity and disaster recovery planning that includes your most important applications and the tools you use to maintain them.


### Retiring Systems:

* Any required data should be archived. All other data should be securely wiped.

* Securely retire the application, including deleting unused accounts and roles and permissions.

* Set your application’s state to retired in the CMDB.


## Using the OWASP Top 10 as a standard

The OWASP Top 10 is primarily an awareness document. However, this has not stopped organizations from using it as a de facto industry AppSec standard since its inception in 2003. If you want to use the OWASP Top 10 as a coding or testing standard, know that it is the bare minimum and just a starting point.

One of the difficulties of using the OWASP Top 10 as a standard is that we document AppSec risks, and not necessarily easily testable issues. For example, [A06:2025-Insecure Design](A06_2025-Insecure_Design.md) is beyond the scope of most forms of testing. Another example is testing whether in-place, in-use, and effective logging and monitoring are implemented, which can only be done with interviews and requesting a sampling of effective incident responses. A static code analysis tool can look for the absence of logging, but it might be impossible to determine if business logic or access control is logging critical security breaches. Penetration testers may only be able to determine that they have invoked incident response in a test environment, which is rarely monitored in the same way as production.

Here are our recommendations for when it is appropriate to use the OWASP Top 10:


<table>
  <tr>
   <td><strong>Use Case</strong>
   </td>
   <td><strong>OWASP Top 10 2025</strong>
   </td>
   <td><strong>OWASP Application Security Verification Standard</strong>
   </td>
  </tr>
  <tr>
   <td>Awareness
   </td>
   <td>Yes
   </td>
   <td>
   </td>
  </tr>
  <tr>
   <td>Training
   </td>
   <td>Entry level
   </td>
   <td>Comprehensive
   </td>
  </tr>
  <tr>
   <td>Design and architecture
   </td>
   <td>Occasionally
   </td>
   <td>Yes
   </td>
  </tr>
  <tr>
   <td>Coding standard
   </td>
   <td>Bare minimum
   </td>
   <td>Yes
   </td>
  </tr>
  <tr>
   <td>Secure Code review
   </td>
   <td>Bare minimum
   </td>
   <td>Yes
   </td>
  </tr>
  <tr>
   <td>Peer review checklist
   </td>
   <td>Bare minimum
   </td>
   <td>Yes
   </td>
  </tr>
  <tr>
   <td>Unit testing
   </td>
   <td>Occasionally
   </td>
   <td>Yes
   </td>
  </tr>
  <tr>
   <td>Integration testing
   </td>
   <td>Occasionally
   </td>
   <td>Yes
   </td>
  </tr>
  <tr>
   <td>Penetration testing
   </td>
   <td>Bare minimum
   </td>
   <td>Yes
   </td>
  </tr>
  <tr>
   <td>Tool support
   </td>
   <td>Bare minimum
   </td>
   <td>Yes
   </td>
  </tr>
  <tr>
   <td>Secure Supply Chain
   </td>
   <td>Occasionally
   </td>
   <td>Yes
   </td>
  </tr>
</table>


We would encourage anyone wanting to adopt an application security standard to use the [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/) (ASVS), as it’s designed to be verifiable and tested, and can be used in all parts of a secure development lifecycle.

The ASVS is the only acceptable choice for tool vendors. Tools cannot comprehensively detect, test, or protect against the OWASP Top 10 due to the nature of several of the OWASP Top 10 risks, with reference to [A06:2025-Insecure Design](A06_2025-Insecure_Design.md). OWASP discourages any claims of full coverage of the OWASP Top 10, because it’s simply untrue.
