# +A: What's next for Application Managers

## Manage the full Application Lifecycle

Applications are some of the most complex systems humans regularly create and maintain. IT management for an application should be performed by IT specialists who are responsible for the overall IT lifecycle of an application. Today's use of continuous integration and continuous deployment, with DevSecOps, often pushing many builds every day, is a far cry from waterfall staged practices common during the original OWASP Top 10 in 2003. 

It might be tempting to build a huge security organization, but generally, we consider embedding security as team members who are peers to developers, architects, and business owners is the fastest way to build and enable secure business. Application security must scale and become agile, by adopting the tools and practices already universal in most organizations.

OWASP recommends that organizations include security - building it in - rather than trying to test for security issues at the end. Advisory security - where security teams sit to the side and tell developers how their applications is a failed paradigm, and one of the reasons we have had such terrible breaches - we simply can't scale to the number of applications present in most organizations, and so few are built securely, let alone tested.

## Responsible, accountability, informed and consulted

Security needs to be the responsibility of a single individual or group, whether that's the application owner, application managers, security team or for small teams, a developer with interest in security. Whomever is responsible needs to have the authority to add security functional and non-functional requirements into the application, ensure that they are verified throughout the development, build, and operational phases. Where agile is used, the DevSecOps team might take over the operational aspects, but without some form of responsibility and authority, security is doomed to fail. 

We suggest establishing application managers and or application owners for every application. The application manager is the technical counterpart of the application owner from business perspective and manages the full application lifecycle, including the security of an application, associate data assets, and documentation. Application managers work together with the organization's security specialists.

## Requirements and Resource Management

* Collect and negotiate the business requirements for an application with the business, including receiving the protection requirements in regard to confidentiality, integrity and availability of all data assets
* Compile the technical requirements including functional and non functional security requirements
* Plan and negotiate the budget that covers all aspects of design, build, testing and operation, including security activities.

## Request for Proposals (RFP) and Contracting

* Negotiate with internal or external developers the requirements, including guidelines and security requirements with respect to your security program, e.g. SDLC, best practices
* Rate the fulfillment of all technical requirements including a rough planning and design
* Negotiate all technical requirements including design, security and service level agreements (SLA)
* Consider to use templates and checklists, such as [OWASP Secure Software Contract Annex](https://www.owasp.org/index.php/OWASP_Secure_Software_Contract_Annex). 

**NB:** Please note that the Annex is a sample specific to US contract law, and is likely to need legal review in your jurisdiction. Please consult qualified legal advice before using the Annex. 

## Planning and Design

* Negotiate planning and design with the developers and internal shareholders, e.g. security specialists
* Compile a security concept (e.g. architecture, measures) according the protection needs and the planned environmental security level. This should be supported by security specialists. Get the application owner to assume remaining risks or to provide additional resources.
* Plan the quality gates for the development including security gates

## Development

Please review the +D "What's next for developers" for guidance. 

## Deployment, Testing and Rollout

It's critical that security tasks  

* Automated the secure setup of the application, interfaces and of all further components needed, including required authorizations
* Test the technical functions and integration to the IT architecture, coordinate business tests. Consider to test use and abuse cases from technical and business perspectives.
* Manage security tests according to internal processes, the protection needs and the level of security where the application is going to be
* Put the application in operation and migrate form previously used applications
* Finalize all documentation, including the CMDB and security architecture.

## Operating and Changes

* Operating including the security management for the application (e.g. patch management)
* Regularly report all users and authorizations to the application owner and get them acknowledged
* Raise the security awareness of users and manage conflicts about usability vs security
* Plan and manage changes, e.g. migrate to new versions of the application or other components like OS, middleware and libraries
* Update all documentation, including in CMDB and the security concept.

## Retiring systems

An often overlooked system

* Regard any requirements for archiving data
* Securely close down the application, incl. delete unused accounts and authorization
* Set your application’s state to retired in the CMDB

## References

* Agile Application Security - Enabling Security in a Continuous Delivery Pipeline, Bell, Bruntun-Spall, Bird, and Smith. September 2017. O'Reilly. http://shop.oreilly.com/product/0636920045106.do