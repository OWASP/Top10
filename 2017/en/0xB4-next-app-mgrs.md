# +A: What's next for Application Managers

## Manage the full Application Lifecycle

Applications are quite complex today. So the IT management for an application should be done by an IT specialist who is responsible for the overall IT lifecycle of an application. OWASP recommends that organizations establish a role of application managers for every application. He is the technical counterpart of the application owner from business perspective and manages the full application lifecycle, he is also in charge of the security of an application and its documentation. Therefore he works together with the organizations security specialists. The following lists some of the key activities focusing on security related activities. 
All activities are generic and should be adopted to your local situation. Sometimes the first five activities are also named Project Manager: 

### Requirements and Resource Mgmt
* Collect and negotiate the business requirements for an application with the future application owner, including receiving the protection requirements in regard to confidentiality, integrity and availability
* Compile the technical requirements including functional and non functional security requirements.
* Plan and negotiate the budget that the future application owner spends

### Request for Proposals (RFP) and Contracting
*	Negotiate with internal or external developers the requirements, including guidelines and security requirements with respect to your security program, e.g. SDLC, best practices
*	Rate the fulfillment of all technical requirements including a rough planning and design
*	Negotiate all technical requirements including design, security and service level agreements (SLA)
* Consider to use templates and checklists, e.g. OWASP Secure Software Contract Annex

### Planning and Design
*	Negotiate planning and design with the developers and internal shareholders, e.g. security specialists
*	Compile a security concept (e.g. architecture, measures) according the protection needs and the planned environmental security level. This should be supported by security specialists.	Get the application owner to assume remaining risks or to provide additional resources.
*	Plan the quality gates for the development including security gates

### Development
*	Accompany the development (see +D)

### Deployment, Testing and Rollout
*	Coordinate the secure setup of the application, interfaces and of all further components needed, including required authorizations
*	Test the technical functions and integration to the IT architecture, coordinate business tests. Consider to test use and abuse cases from technical and business perspectives.
*	Manage security tests according to internal processes, the protection needs and the level of security where the application is going to be
*	Put the application in operation and migrate form previously used applications 
*	Finalize all documentation, including in CMDB and the security concept.  

### Operating and Changes
*	Operating including the security management for the application (e.g. patch management)
*	Regularly report all users and authorizations to the application owner and get them acknowledged
*	Raise the security awareness of users and manage conflicts about usability vs security
*	Plan and manage changes, e.g. migrate to new versions of the application or other components like OS, middleware and libraries
*	Update all documentation, including in CMDB and the security concept.

### Closing Down
*	Regard any requirements for archiving data
*	Securely close down the application, incl. delete unused accounts and authorization
*	Set your application’s state to retired in the CMDB
