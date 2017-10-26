# +A: What's next for Application Managers

## Manage the full Application Lifecycle

Applications are some of the most complex systems humans regularly create and maintain. IT management for an application should be performed by IT specialists who are responsible for the overall IT lifecycle of an application.

We suggest establishing application owners and application managers for every application to provide accountability, responsibility, consulted and informed (RACI), to ensure the organization who can sign off risks, and who is responsible for security design, building, testing and deploying application security.

## Requirements and Resource Management

* Collect and negotiate the business requirements for an application with the business, including receiving the protection requirements in regard to confidentiality, integrity and availability of all data assets.
* Compile the technical requirements including functional and non functional security requirements.
* Plan and negotiate the budget that covers all aspects of design, build, testing and operation, including security activities.

## Request for Proposals (RFP) and Contracting

* Negotiate with internal or external developers the requirements, including guidelines and security requirements with respect to your security program, e.g. SDLC, best practices.
* Rate the fulfillment of all technical requirements including a rough planning and design phase.
* Negotiate all technical requirements including design, security and service level agreements (SLA).
* Adopt templates and checklists, such as [OWASP Secure Software Contract Annex](https://www.owasp.org/index.php/OWASP_Secure_Software_Contract_Annex).

**NB: Please note that the Annex is a sample specific to US contract law, and is likely to need legal review in your jurisdiction. Please consult qualified legal advice before using the Annex.**

## Planning and Design

To ensure applications have a secure design, the following should be performed:
* Negotiate planning and design with the developers and internal shareholders, e.g. security specialists
* Define a security architecture, controls, and countermeasures according to the protection needs and the planned environmental security level. This should be supported by security specialists.
* Get the application owner to assume remaining risks or to provide additional resources.
* Each sprint, ensure security stories are created for functional requirements, and constraints added for non-functional requirements.

## Deployment, Testing and Rollout

To ensure secure operations and changes, the following should be performed:
* Automate the secure setup of the application, interfaces and of all components needed, including required authorizations.
* Test the technical functions and integration with the IT architecture and coordinate business tests.
* Create "use" and "abuse" test cases from technical and business perspectives.
* Manage security tests according to internal processes, the protection needs and the level of security required by the application.
* Put the application in operation and migrate from previously used applications if needed.
Finalize all documentation, including the CMDB and security architecture.

## Operating and Changes

To ensure secure operations and changes, the following should be performed:
* Operating including the security management for the application (e.g. patch management).
* Raise the security awareness of users and manage conflicts about usability vs security.
* Plan and manage changes, e.g. migrate to new versions of the application or other components like OS, middleware and libraries.
* Update all documentation, including in CMDB and the security architecture, controls, and countermeasures, including any runbooks or project documentation.

## Retiring Systems

The process of retiring systems is often overlooked. You should ensure that:
* Any required data is archived. All other data is securely wiped.
* Securely close down the application, including deleting unused accounts and roles and permissions.
* Set your application’s state to retired in the CMDB.
