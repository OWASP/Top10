# +A: What's next for Application Managers

## Manage the Full Application Lifecycle

Applications belong to the most complex systems humans regularly create and maintain. IT management for an application should be performed by IT specialists who are responsible for the overall IT lifecycle of an application. We suggest establishing the role of application manager as technical counterpart to the application owner. The application manager is in charge of the whole application lifecycle from the IT perspective, from collecting the requirements until the process of retiring systems, which is often overlooked. 

## Requirements and Resource Management

* Collect and negotiate the business requirements for an application with the business, including the protection requirements with regard to confidentiality, authenticity, integrity and availability of all data assets, and the expected business logic.
* Compile the technical requirements including functional and nonfunctional security requirements.
* Plan and negotiate the budget that covers all aspects of design, build, testing and operation, including security activities.

## Request for Proposals (RFP) and Contracting

* Negotiate the requirements with internal or external developers, including guidelines and security requirements with respect to your security program, e.g. SDLC, best practices.
* Rate the fulfillment of all technical requirements, including a planning and design phase.
* Negotiate all technical requirements, including design, security, and service level agreements (SLA).
* Adopt templates and checklists, such as [OWASP Secure Software Contract Annex](https://www.owasp.org/index.php/OWASP_Secure_Software_Contract_Annex). **Note**: The annex is for US contract law, so please consult qualified legal advice before using the sample annex.

## Planning and Design

* Negotiate planning and design with the developers and internal shareholders, e.g. security specialists.
* Define the security architecture, controls, and countermeasures appropriate to the protection needs and the expected threat level. This should be supported by security specialists.
* Ensure that the application owner accepts remaining risks or provides additional resources.
* In each sprint, ensure security stories are created that include constraints added for non-functional requirements.

## Deployment, Testing, and Rollout

* Automate the secure deployment of the application, interfaces and all required components, including needed authorizations.
* Test the technical functions and integration with the IT architecture and coordinate business tests.
* Create "use" and "abuse" test cases from technical and business perspectives.
* Manage security tests according to internal processes, the protection needs, and the level of security required by the application.
* Put the application in operation and migrate from previously used applications if needed.
* Finalize all documentation, including the CMDB and security architecture.

## Operations and Change Management

* Operations must include guidelines for the security management of the application (e.g. patch management).
* Raise the security awareness of users and manage conflicts about usability vs. security.
* Plan and manage changes, e.g. migrate to new versions of the application or other components like OS, middleware, and libraries.
* Update all documentation, including in the change management data base (CMDB) and the security architecture, controls, and countermeasures, including any runbooks or project documentation.

## Retiring Systems

* Any required data should be archived. All other data should be securely wiped.
* Securely retire the application, including deleting unused accounts and roles and permissions.
* Set your application's state to retired in the CMDB.
