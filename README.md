# Zero-Trust-Arena
A secure multi-agent AI cyber range where attacking and defending agents compete in a sandbox, and every agent and message is verified through a Zero Trust cryptographic layer.
ZERO TRUST ARENA
PRODUCT REQUIREMENTS DOCUMENT
(PRD)
A Controlled Red Team / Blue Team Cybersecurity Environment
Based on the Zero Trust Principle: Never Trust Automatically. Always Verify.
Team Members
Hira Saleem
(Team Leader)
Muhammad Waqar
Abdullah Mustafa
Peer Talha Dawood
Shumail Iqbal
Muhammad Kaif
Version 1.0  |  October 2026
For authorized laboratory use only

TABLE OF CONTENTS
1. EXECUTIVE SUMMARY	2
2. INTRODUCTION	4
3. PROBLEM STATEMENT	5
4. PROJECT OBJECTIVES	6
5. PROJECT SCOPE	7
6. SYSTEM CONCEPT	8
7. HOW ZERO TRUST ARENA WORKS: THE 5 STEPS	10
8. SYSTEM ARCHITECTURE	12
9. RED TEAM AGENTS	15
10. BLUE TEAM AGENTS	17
11. TRUST AUTHORITY	19
12. SECURE MESSAGE SYSTEM	23
13. VERIFICATION PIPELINE	25
14. JUDGE SYSTEM	27
15. FUNCTIONAL REQUIREMENTS	29
16. NON-FUNCTIONAL REQUIREMENTS	32
17. SECURITY REQUIREMENTS	33
18. DATA REQUIREMENTS	35
19. COMMUNICATION PROTOCOL	36
20. ATTACK AND DEFENSE WORKFLOW	38
21. AGENT ROLES	40
22. TECHNOLOGY STACK	41
23. SYSTEM INTERFACES	42
24. LOGGING AND MONITORING	43
25. EVALUATION METRICS	44
26. TESTING STRATEGY	46
27. THREAT MODEL	48
28. RISK ANALYSIS	49
29. FUTURE ENHANCEMENTS	50
30. PROJECT LIMITATIONS	51
31. ACCEPTANCE CRITERIA	52
32. TRACEABILITY MATRIX	53
33. GLOSSARY	55
34. CONCLUSION	56
1. EXECUTIVE SUMMARY
Zero Trust Arena is a controlled cybersecurity environment in which autonomous or semi-autonomous software agents establish identity, communicate securely, attack an authorized laboratory target, detect and respond to that activity, and are evaluated on measurable outcomes. The project applies the Zero Trust principle, “Never trust automatically. Always verify.”, to every interaction between agents and system components.
Within the proposed system, agents are intended to:
•register with a Trust Authority and obtain a verifiable identity;
•communicate through a secure message layer in which every message is signed, encrypted, and verified;
•launch controlled attacks against an authorized OWASP Juice Shop laboratory (Red Team);
•analyze security logs, detect malicious activity, and create defensive block rules (Blue Team);
•reject unauthorized, fake, expired, or tampered communication; and
•be scored by a Judge component that measures attack and defense performance and generates evaluation reports.
Authorized laboratory use only. Zero Trust Arena is designed exclusively for an authorized, isolated laboratory environment. The document does not describe, and the system shall not be used for, attacks against real-world systems, unauthorized penetration testing, or any destructive activity outside the laboratory.
1.1 Implementation Status Labels
This document separates what exists from what is proposed. The following labels are used throughout. Where the implementation status of an item is not known, the text states “Implementation status to be confirmed.” No proposed feature should be read as an implemented feature unless it is labelled CURRENT / IMPLEMENTED.
Table 1: Implementation status labels
Label	Meaning
CURRENT / IMPLEMENTED	Confirmed to exist in the project today. In this document this applies only to the Kali Linux Red environment, the Windows Blue environment, and the OWASP Juice Shop laboratory.
PROPOSED	A requirement or design element specified by this PRD that is intended to be built.
PLANNED	A proposed item scheduled for a later development stage.
ILLUSTRATIVE	An example used only to explain a concept. It is not measured data and not a statement of implementation.
FUTURE ENHANCEMENT	A possible extension beyond the current project scope.

1.2 Document Conventions
•Requirements are written using “the system shall”. Identifiers are unique: FR-xxx (functional), NFR-xxx (non-functional), SR-xxx (security), TC-xxx (test cases), and AC-xxx (acceptance criteria).
•Unless otherwise stated, every requirement in this document has the status PROPOSED.
•No performance figures, detection rates, attack success rates, response times, or agent counts are claimed. All formulas describe evaluation logic only.
2. INTRODUCTION
2.1 Background
Modern computing environments are distributed, automated, and increasingly operated by software agents that exchange information without direct human supervision. In such environments, a single forged message, impersonated identity, or silently modified instruction can have consequences that spread quickly. Traditional perimeter-based security assumes that anything inside the network boundary is trustworthy. This assumption fails when a component is compromised, misconfigured, or impersonated.
2.2 The Problem of Implicit Trust
Implicit trust means that a message or component is accepted because of where it appears to come from, such as a network location or a familiar name, rather than because it has been proven authentic. Systems that rely on implicit trust are vulnerable to spoofed senders, forged commands, and tampered data. Identity verification is therefore a prerequisite for any secure interaction between machines.
2.3 Why Secure Machine-to-Machine Communication Matters
When agents coordinate, for example when a Red agent shares a finding or a Blue agent reports a defensive action, the receiver must be able to answer four questions: who sent this, has it been altered, is it recent, and is the sender allowed to do this? Without reliable answers, the receiving component either rejects useful information or accepts harmful information. Secure machine-to-machine communication provides the means to answer these questions systematically.
2.4 Why Controlled Red Team / Blue Team Environments Are Useful
A Red Team simulates an adversary, and a Blue Team defends against it. Running both within a controlled laboratory allows security behaviour to be observed, repeated, and measured without risk to real systems. A deliberately vulnerable application such as OWASP Juice Shop provides a safe and legal target, so that attack techniques and defensive detection can be studied together.
2.5 Zero Trust in This Project
Zero Trust is a security model based on the principle: “Never trust automatically. Always verify.” In Zero Trust Arena the principle is applied to communication between agents and system components. No agent is trusted merely because it exists in the arena. Each agent must hold a registered identity, and each message it sends must pass an explicit sequence of checks before it is accepted.
2.6 Continuous Verification
Verification is not performed once at registration and then assumed. Every message is verified on receipt, because a key can be compromised, a role can change, and an identity can be revoked after registration. Continuous verification limits the time during which a compromised or misbehaving component can influence the system.
3. PROBLEM STATEMENT
Cybersecurity research and education increasingly use autonomous agents for both offensive testing and defensive monitoring. However, the environments in which these agents are developed and compared often lack an integrated mechanism to establish who an agent is, to verify what it sends, and to measure how well attacks and defenses perform. This project addresses the following problems.
Table 2: Problems addressed by Zero Trust Arena
Problem	Description
Unverified agents	Agents may participate in a system without any proof of identity, so the origin of actions and reports cannot be trusted.
Spoofed identities	A malicious component can claim to be a legitimate agent and issue instructions or reports in its name.
Fake messages	Fabricated findings, alerts, or defensive reports can mislead other agents and distort evaluation results.
Tampered messages	A legitimate message can be altered in transit, changing its meaning without the receiver noticing.
Unauthorized communication	Agents may send message types or commands that their role does not permit.
Replay and timestamp problems	A previously valid message can be resent later, or a message can carry a stale or invalid time, and still be accepted.
Delayed detection	Without correlated log analysis, malicious activity may be recognized late or not at all.
Lack of measurable response evaluation	Defensive reactions are rarely measured consistently, which makes comparison and improvement difficult.
Lack of integrated attack-defense simulation	Attack tools, defensive tooling, and trust mechanisms are commonly studied separately rather than in one coherent environment.
Difficulty evaluating cybersecurity agents in a controlled environment	Without a safe, authorized target and a neutral scorer, results are hard to reproduce and to trust.

The proposed system is intended to address these problems by combining a Trust Authority, a secure message layer with a mandatory verification pipeline, Red and Blue agents working against an authorized laboratory target, and a Judge that evaluates outcomes.
4. PROJECT OBJECTIVES
4.1 Primary Objectives
1.Establish agent identity. Every participating agent shall have an identity that other components can verify.
2.Register agents through a Trust Authority. Identity shall be issued or confirmed centrally, and unregistered agents shall have no trusted identity.
3.Secure communication. Messages exchanged between agents and components shall be signed and encrypted.
4.Verify every message. No message shall be acted upon until it passes the verification pipeline.
5.Simulate controlled cyber attacks. Red agents shall test the authorized Juice Shop laboratory within a defined scope.
6.Detect attacks through defensive agents. Blue agents shall analyze logs and identify suspicious or malicious activity.
7.Apply defensive block rules. Blue agents shall create and record rules that respond to detected activity.
8.Detect fake or invalid messages. The system shall identify and drop messages that are forged, altered, expired, replayed, or unauthorized.
9.Measure response performance. The system shall record timing and outcomes of attacks, detections, and defensive actions.
10.Generate Judge-based evaluation reports. A Judge shall compute defined metrics and produce a final report.
4.2 Secondary Objectives
•Provide a reproducible laboratory for studying attack-defense interaction.
•Maintain a complete, auditable record of registrations, messages, attacks, detections, and defenses.
•Keep components modular so that agents, detection logic, and scoring rules can be replaced or extended.
•Serve as an educational artefact that demonstrates Zero Trust principles to students and evaluators.
•Document requirements, tests, and acceptance criteria in a traceable form.
5. PROJECT SCOPE
5.1 In Scope
Table 3: In-scope items
Area	Description
Agent registration	Agents request registration and receive an identity from the Trust Authority.
Identity management	Agent identities, roles, and trust status are recorded and queried.
Secret keys	Each agent creates and protects its own secret key.
Trust Authority	Central component for registration, identity validation, and trust decisions.
Red agents	Agents that scan and test the authorized Juice Shop laboratory.
Blue agents	Agents that analyze logs, detect activity, and create block rules.
Juice Shop lab	OWASP Juice Shop used as the authorized target.
Logs	Security and system logs produced by the lab and by the arena components.
Message signing	Digital signatures on all messages.
Encryption	Confidentiality protection for message content.
Timestamp validation	Rejection of expired or invalid message times.
Permission checks	Role-based checks that a sender may perform the requested action.
Attack detection	Detection of suspicious activity by Blue agents.
Block rules	Defensive rules created and recorded in response to detections.
Judge scoring	Metric computation and performance scoring.
Reports	Generated evaluation reports.
Monitoring	Observation of system events for audit and evaluation.

5.2 Out of Scope
Table 4: Out-of-scope items
Excluded Activity	Reason
Attacking real external systems	The project is limited to an authorized laboratory target.
Unauthorized penetration testing	All testing must be explicitly authorized and scoped.
Real-world destructive operations	No activity intended to damage data or availability outside the lab.
Malware deployment outside the lab	Not permitted in any form.
Credential theft from unrelated systems	The project does not target accounts or data beyond the laboratory.
6. SYSTEM CONCEPT
Zero Trust Arena consists of eight cooperating components. This section describes each component and then explains how they interact.
6.1 Components
A. Trust Authority
The Trust Authority is the central registry. It receives registration requests, validates them, issues or confirms agent identities, records trust status, and answers identity and permission queries. Agents that are not registered are treated as untrusted.
B. Red Agents
Red agents operate in the Kali Linux environment (CURRENT). They scan and test the authorized Juice Shop laboratory, produce findings, and share findings with other Red agents. All actions are logged.
C. Blue Agents
Blue agents operate in the Windows environment (CURRENT). They inspect security logs, detect suspicious activity, correlate events, create block rules, and record their responses.
D. Juice Shop Lab
OWASP Juice Shop (CURRENT) is the intentionally vulnerable web application used as the only authorized target. It produces the activity and logs that Blue agents analyze.
E. Secure Communication Layer
The secure communication layer (PROPOSED) creates, signs, encrypts, transmits, and receives messages exchanged between agents and components.
F. Verification Pipeline
The verification pipeline (PROPOSED) applies an ordered set of checks to every received message and either accepts or drops it.
G. Judge
The Judge (PROPOSED) collects verified events, calculates metrics, and produces the final evaluation report.
H. Logging and Reporting System
The logging and reporting system (PROPOSED) records security-relevant events for audit and for the Judge, and presents results in report form.
6.2 Component Interaction
Agents first register with the Trust Authority. Red agents then test the Juice Shop lab, which generates activity and logs. Blue agents read those logs, detect suspicious behaviour, and create block rules. All messages exchanged between agents, such as findings, alerts, and reports, travel through the secure communication layer and are subject to the verification pipeline. The Judge consumes verified events and produces scores and reports. The relationships between components are shown in Section 8, and the trust relationships are shown in Section 11.
7. HOW ZERO TRUST ARENA WORKS: THE 5 STEPS
The operation of Zero Trust Arena follows a five-step workflow. The workflow is shown in Figure 1 and described in detail below.

Figure 1: Five-step operational workflow
7.1 STEP 1: REGISTER
•Every agent creates its own secret key.
•The agent sends a registration request to the Trust Authority.
•The Trust Authority verifies the request and registers the agent.
•The agent receives an identity that other components can verify.
•An unregistered agent has no trusted identity, and its messages are not accepted.
7.2 STEP 2: RED ATTACKS
•Red agents operate in the controlled Kali Linux environment.
•They scan and test the authorized Juice Shop laboratory.
•They identify permitted vulnerabilities within the authorized scope.
•Findings can be passed between Red agents through the secure message layer.
•All activity is logged.
7.3 STEP 3: BLUE DEFENDS
•Blue agents operate in the Windows environment.
•They inspect security logs and detect suspicious or malicious activity.
•They correlate related events to reach a decision.
•They create defensive block rules.
•They record each response and its timing.
7.4 STEP 4: VERIFY EVERY MESSAGE
Every message passes through the verification pipeline in the following order:
1.Identity check
2.Signature verification
3.Encryption / decryption validation
4.Timestamp validation
5.Permission check
6.Message integrity check
7.Accept or drop
[PROPOSED] If any required verification check fails, the message is rejected and dropped, and the event is logged. A message is accepted only when every required check succeeds. The detailed pipeline is specified in Section 13.
7.5 STEP 5: JUDGE SCORES
The Judge evaluates the following outcomes and produces a final report:
•attacks detected;
•response time;
•fake messages blocked;
•messages verified;
•invalid messages dropped;
•defensive rules created; and
•overall performance.
8. SYSTEM ARCHITECTURE
This section presents the proposed architecture of Zero Trust Arena. The diagram is illustrative: it shows intended components and relationships, not a confirmed implementation.

Figure 2: High-level architecture of Zero Trust Arena (illustrative)
8.1 Component Description
Table 5: Architecture components
Component	Responsibility	Environment
Trust Authority	Registers agents, issues or confirms identity, records trust status, answers identity and permission queries.	To be confirmed
Red Agents	Scan and test the authorized Juice Shop lab; generate and share findings; log actions.	Kali Linux
Blue Agents	Read logs; detect and correlate suspicious activity; create block rules; record responses.	Windows
Juice Shop Lab	Authorized, intentionally vulnerable target application; produces activity and logs.	OWASP Juice Shop
Security Logs	Record of lab and arena activity used by Blue agents and the Judge.	To be confirmed
Secure Message Layer	Creates, signs, encrypts, transmits, and receives messages.	To be confirmed
Verification Pipeline	Applies ordered checks; accepts or drops each message.	To be confirmed
Judge	Collects verified events, computes metrics, produces the final report.	To be confirmed

8.2 Implementation Status of Architecture Elements
The table below distinguishes the current environment from the illustrative architecture and from planned components. Implementation status to be confirmed applies wherever the project team has not yet verified the state of a component.
Table 6: Implementation status of architecture elements
Element	Status
Kali Linux Red environment	CURRENT / IMPLEMENTED (environment)
Windows Blue environment	CURRENT / IMPLEMENTED (environment)
OWASP Juice Shop laboratory	CURRENT / IMPLEMENTED (environment)
Trust Authority logic	PROPOSED. Implementation status to be confirmed.
Red and Blue agent logic	PROPOSED. Implementation status to be confirmed.
Secure message layer and verification pipeline	PROPOSED. Implementation status to be confirmed.
Judge and reporting	PROPOSED. Implementation status to be confirmed.
Dashboards, multi-lab support, machine-learning detection	FUTURE ENHANCEMENT

8.3 Architectural Principles
•No implicit trust: components are trusted only after verification.
•Separation of roles: Red, Blue, Judge, and Trust Authority have distinct responsibilities and permissions.
•Least privilege: each role receives only the permissions its function requires.
•Fail closed: when verification fails or cannot be completed, the message is dropped.
•Auditability: security-relevant events are recorded so that outcomes can be reviewed.
•Modularity: each component can be developed, tested, and replaced independently.
9. RED TEAM AGENTS
9.1 Purpose
Red agents simulate adversarial behaviour against the authorized Juice Shop laboratory so that Blue agents have realistic activity to detect and so that defensive performance can be measured. Red agents are a testing instrument. They exist to exercise the laboratory under controlled conditions and not to attack any other system.
9.2 Environment
Red agents operate in the Kali Linux environment (CURRENT / IMPLEMENTED as an environment). The agent logic that runs in that environment is PROPOSED. Implementation status to be confirmed.
9.3 Registration, Identity, and Secret Keys
Before taking part in the arena, each Red agent shall create its own secret key and register with the Trust Authority. After registration the agent holds an identity with the role Red. Messages the agent sends are signed with material derived from its secret key, so that other components can verify who sent them. The secret key shall be protected by the agent and shall not be exposed in logs or messages.
9.4 Authorized Attack Scope
Red agents shall act only within an explicitly configured scope, which identifies the authorized Juice Shop target and the permitted classes of testing. A Red agent shall refuse any action whose target falls outside this scope. This restriction is a core safety requirement of the project (see FR-023 and SR-016).
9.5 Scanning and Testing
Within the authorized scope, Red agents perform reconnaissance of the laboratory application and carry out controlled tests of its known, permitted weaknesses. The purpose is to generate observable activity and findings, not to cause damage. This document intentionally does not specify exploit procedures.
9.6 Finding Generation and Exchange
When a Red agent identifies a permitted weakness, it shall record a structured finding. A finding is expected to include a finding identifier, the reporting agent identity, a timestamp, the affected component of the laboratory, a short description, and the supporting evidence reference. Findings may be passed to other Red agents through the secure message layer; each exchange is a message that is signed, encrypted, and verified.
9.7 Logging
Every Red agent action, including scans, tests, findings, and messages sent, shall be logged with a timestamp and the agent identity. These records provide the ground truth that the Judge uses to determine how many attacks were launched.
9.8 Sample Controlled Attack Lifecycle
[ILLUSTRATIVE] The following lifecycle is a conceptual example of the intended behaviour. It does not describe a confirmed implementation.

Figure 3: Red agent controlled attack flow
1.The Red agent starts and presents its registered identity.
2.The agent confirms that its intended target is inside the authorized scope.
3.The agent scans the Juice Shop laboratory.
4.The agent identifies a permitted weakness.
5.The agent performs a controlled, scoped test, and the lab records the resulting activity.
6.The agent creates a structured finding.
7.The agent shares the finding with another Red agent through the secure message layer.
8.All steps are written to the log.
10. BLUE TEAM AGENTS
10.1 Purpose and Environment
Blue agents defend the laboratory by observing its logs, detecting suspicious or malicious activity, and applying defensive responses. Blue agents operate in the Windows environment (CURRENT / IMPLEMENTED as an environment). Blue agent logic is PROPOSED. Implementation status to be confirmed.
10.2 Responsibilities
Table 7: Blue agent responsibilities
Responsibility	Description
Log monitoring	Read security logs produced by the Juice Shop laboratory and by arena components.
Threat detection	Identify entries or patterns that indicate suspicious or malicious behaviour.
Event correlation	Relate multiple log entries to determine whether they form one attack.
Alert generation	Create a detection event describing what was detected, when, and with what confidence.
Decision-making	Choose whether and how to respond to a detection.
Block-rule creation	Create a defensive rule that blocks the identified activity.
Verification	Verify every message received from other components before acting on it.
Response timing	Record the time of detection and the time of defensive action.
Reporting	Report detections and actions to the Judge through the secure message layer.

10.3 How Blue Agents React to Red Activity
Red activity against the lab appears as entries in the security logs. A Blue agent reads these entries, compares them against its detection logic, and, when activity is judged suspicious, correlates it with related events. The agent then generates a detection event, decides on a response, and creates a block rule. The rule, the detection, and the timing of each step are recorded so that the Judge can later compute response time and detection performance.
[PROPOSED] The detection logic (for example, rule-based matching, thresholds, or other methods) is not specified by this PRD and remains a design decision. Implementation status to be confirmed.

Figure 4: Blue agent defense flow
10.4 Message Trust
A Blue agent shall not act on a message from another component until that message has passed the verification pipeline. For example, an unverified “block this address” instruction from an unregistered sender shall be dropped rather than applied. This prevents attackers from using the defensive system itself as a vector.
11. TRUST AUTHORITY
11.1 Role
The Trust Authority is the root of trust of the arena. It decides which agents are recognized, records the identity and role of each, and answers queries from other components about whether a given identity is currently trusted. All trust decisions in the arena ultimately depend on its records.
11.2 Registration
An agent requests registration by presenting its declared role and the key information required by the selected key scheme. The Trust Authority validates the request, checks that the identity is not already registered, assigns or confirms the identity, and writes a registration record. Malformed, duplicate, or non-permitted requests are rejected and logged.
11.3 Agent Identity
An identity is a unique identifier bound to key information held by the Trust Authority and to a role. The binding allows a receiver to confirm that a signed message really originates from the claimed sender.
11.4 Secret Key Handling
Each agent creates its own secret key. How the secret key is used and what the Trust Authority stores depends on the key scheme chosen for the implementation. Two options are described below. The choice is an open design decision and no scheme is asserted here.
Table 8: Candidate key schemes (open design decision)
Option	Description	Consideration
Asymmetric key pair	The agent keeps a private key secret and registers the corresponding public key with the Trust Authority.	The Trust Authority does not need to hold any secret. Receivers verify signatures using the registered public key.
Symmetric secret	The agent's secret is shared with the Trust Authority in a protected manner and used for message authentication.	Simpler to implement but requires protected storage of secrets at the Trust Authority and a trusted verification path.

In both options the secret key shall never appear in logs, reports, or unprotected messages.
11.5 Trust Status, Authentication, and Authorization
Each registered agent has a trust status, for example registered, suspended, or revoked. Authentication confirms that the sender is who it claims to be. Authorization confirms that the authenticated sender is allowed to perform the requested action, based on its role. The Trust Authority holds the identity and role information that makes both checks possible.
11.6 Identity Validation and Trust Decisions
When a component receives a message, it may ask the Trust Authority whether the sender is registered, whether its trust status is valid, and whether its role permits the message type. The Trust Authority answers from its records. A trust decision is therefore a recorded, reviewable outcome and not an assumption.
11.7 Revocation Concept
If an agent is found to be compromised or misbehaving, the Trust Authority shall be able to mark its identity as revoked. Messages from a revoked identity shall be rejected from that point onward. The mechanism by which revocation is distributed to all verifying components is a design decision to be confirmed.
11.8 Registration Records
Registration records are expected to contain the agent identifier, role, key metadata, registration time, trust status, and a history of status changes. They shall not contain plaintext secret keys.
11.9 Sample Registration Lifecycle
[ILLUSTRATIVE] The lifecycle below is a conceptual example.

Figure 5: Agent registration flow
1.The agent generates its secret key.
2.The agent submits a registration request stating its role.
3.The Trust Authority validates the request.
4.If valid, it stores a trust record and issues or confirms the identity; if invalid, it rejects the request.
5.The outcome is logged as an event.
6.The agent may now communicate and is subject to verification on every message.
11.10 Trust Relationships
Figure 6 summarizes the trust relationships in the arena. The Trust Authority sits at the center of the trust boundary. Red agents, Blue agents, and the Judge are inside the boundary only because they have registered. An unregistered or spoofed agent remains outside, and its messages are dropped and logged.

Figure 6: Trust relationship diagram
12. SECURE MESSAGE SYSTEM
In Zero Trust Arena every message is treated as a security-sensitive object. A message can carry a finding, an alert, a block-rule notice, or a report, and each of these influences the behaviour and the scoring of the system. A message shall therefore be authenticated, protected, and verified before it is trusted.
12.1 Message Structure
The following logical structure is proposed. Field names are illustrative.
Table 9: Proposed message fields
Field	Purpose
Message ID	Unique identifier used for logging and for replay detection.
Sender ID	Registered identity of the sending agent or component.
Receiver ID	Intended recipient.
Timestamp	Time of creation, used for freshness validation.
Message Type	Category of the message (for example finding, alert, block-rule notice, report).
Payload	The message content, protected by encryption.
Signature	Digital signature allowing the receiver to verify sender and integrity.
Encryption Metadata	Information required by the receiver to decrypt and validate the protected payload.
Permission Context	The role and action under which the sender asserts the message is sent.

12.2 Security Functions
Signing
The sender produces a signature over the message contents so that the receiver can confirm both the origin and that the contents have not changed.
Encryption
The payload is encrypted so that only the intended receiver can read it. The scheme is to be selected from established, reviewed cryptographic constructions; for example, an authenticated encryption mode from a vetted library. The project shall not design its own cryptographic algorithms.
Timestamp Validation
The receiver compares the message timestamp with its own clock. Messages outside an acceptable time window are rejected. The window is a configurable parameter that is not defined in this PRD.
Replay Resistance Concept
A replayed message is a valid message that is sent again. Replay resistance is achieved conceptually by combining the timestamp window with a record of recently seen Message IDs, so that the same message cannot be accepted twice within the window.
Integrity Verification
Any change to the signed content invalidates the signature. A receiver therefore detects modification of the payload or of the signed header fields.
Sender Verification and Receiver Authorization
The receiver confirms that the Sender ID is a registered identity and that the signature matches it. It then checks that the sender's role is authorized to send this message type to this receiver.
Acceptance and Rejection
A message is accepted only when every required check passes. Otherwise it is dropped, not passed to the receiving component, and recorded in the log with the reason for rejection.
[PROPOSED] No specific cryptographic algorithm is specified by the project at this time. Algorithm selection is listed as an open design decision in Section 22.
13. VERIFICATION PIPELINE
The verification pipeline is the mechanism that enforces the Zero Trust principle for messages. It is applied by every component that receives a message. The pipeline is ordered so that inexpensive and fundamental checks, such as identity, occur before checks that depend on them.

Figure 7: Secure message verification pipeline
13.1 Stage Description
Table 10: Verification pipeline stages
Stage	What happens	Failure outcome
Message received	The message is received with all declared fields. Required fields are checked for presence.	Missing required fields: drop and log.
1. Identity check	The Sender ID is checked against the Trust Authority records and trust status.	Unknown, suspended, or revoked sender: drop and log.
2. Signature check	The signature is verified against the sender's registered key information.	Invalid signature: drop and log.
3. Encryption / decryption validation	The payload is decrypted and the encryption metadata is validated.	Payload cannot be decrypted or metadata is invalid: drop and log.
4. Integrity check	The decrypted content is confirmed to match what was signed.	Modified payload: drop and log.
5. Timestamp check	The timestamp is within the acceptable window and the Message ID has not been seen before.	Expired timestamp or replay attempt: drop and log.
6. Permission check	The sender's role is permitted to send this message type and perform the requested action.	Unauthorized action: drop and log.
Accept / drop	If all checks passed, the message is delivered to the receiving component and the acceptance is logged.	Any failure results in drop.

13.2 Failure Cases
Table 11: Verification failure cases
Failure Case	Detected At	Result
Unknown sender	Identity check	Dropped; logged as unknown sender.
Invalid signature	Signature check	Dropped; logged as signature failure.
Modified payload	Integrity check	Dropped; logged as integrity failure.
Expired timestamp	Timestamp check	Dropped; logged as stale message.
Replay attempt	Timestamp / Message ID check	Dropped; logged as replay.
Unauthorized action	Permission check	Dropped; logged as permission failure.
Missing required fields	Message received	Dropped; logged as malformed message.

[PROPOSED] The verification sequence in Section 7.4 and the stage order above express the same intent. The relative order of the encryption, integrity, and timestamp checks may be adjusted at design time provided that every check remains mandatory and that failure at any stage causes the message to be dropped.
14. JUDGE SYSTEM
14.1 Responsibilities
The Judge is a neutral evaluator. It does not participate in attacks or defense. It collects verified events from the arena, computes the defined metrics, and produces the final report. The Judge shall be registered with the Trust Authority like any other component, and it shall accept only verified inputs.

Figure 8: Judge evaluation flow
14.2 Metrics
The Judge may compute the following metrics. Section 25 defines them in detail.
•attacks launched;
•attacks detected;
•detection rate;
•response time;
•fake messages blocked;
•invalid messages dropped;
•messages verified;
•block rules added; and
•defensive actions completed.
14.3 Evaluation Logic
The following formula is an example of evaluation logic. It is not a measured result.
Detection Rate = (Detected Attacks / Total Attacks) × 100
[ILLUSTRATIVE] Formulas in this document define how the Judge is intended to calculate results. They are evaluation logic only. No actual measured results are claimed.
14.4 Ground Truth and Final Report
To compute detection metrics the Judge requires a ground truth, which is the authoritative record of attacks that Red agents actually launched. The Judge compares this record with detection events reported by Blue agents. The final report is expected to summarize inputs, metric values, notable events, and any limitations of the run, such as missing data.
15. FUNCTIONAL REQUIREMENTS
Functional requirements specify what the proposed system shall do. All requirements have the status PROPOSED. Priority uses the terms Must (essential for the project), Should (important but not essential), and May (optional).
15.1 Registration and Identity
ID	Requirement	Priority
FR-001	The system shall allow an agent to request registration with the Trust Authority.	Must
FR-002	Each agent shall create its own secret key, and the key shall not be disclosed to any component except as required by the selected key scheme.	Must
FR-003	The Trust Authority shall assign or confirm an identity for each successfully registered agent.	Must
FR-004	The Trust Authority shall store a registration record containing at least the agent identifier, role, key metadata, trust status, and registration time.	Must
FR-005	The Trust Authority shall reject malformed registration requests and requests that duplicate an existing identity.	Must
FR-006	The Trust Authority shall record a role (Red, Blue, or Judge) for each registered agent.	Must
FR-007	The system shall treat an unregistered agent as untrusted and shall reject communication from it.	Must
FR-008	The Trust Authority shall answer trust status queries from authorized components.	Must
FR-009	The Trust Authority shall support marking an identity as revoked, and the system shall reject messages from a revoked identity.	Should

15.2 Secure Messaging and Verification
ID	Requirement	Priority
FR-010	Every message shall contain the required fields: Message ID, Sender ID, Receiver ID, Timestamp, Message Type, Payload, Signature, Encryption Metadata, and Permission Context.	Must
FR-011	The sender shall digitally sign each message before transmission.	Must
FR-012	The sender shall encrypt the message payload for the intended receiver, and the receiver shall decrypt and validate it.	Must
FR-013	The receiver shall verify that the Sender ID is a registered identity with a valid trust status.	Must
FR-014	The system shall verify the signature of every received message.	Must
FR-015	The system shall verify that the message content has not been modified since signing.	Must
FR-016	The system shall validate message timestamps and reject messages outside the configured acceptance window.	Must
FR-017	The system shall reject a message whose Message ID has already been accepted within the acceptance window.	Must
FR-018	The system shall check that the sender's role is permitted to send the message type and request the stated action.	Must
FR-019	The system shall drop any message that fails a required check and shall not deliver it to the receiving component.	Must
FR-020	The system shall log accepted and rejected messages, including sender, receiver, time, and the reason for rejection.	Must
FR-021	The system shall not partially accept a message; acceptance requires that all required checks succeed.	Must

15.3 Red Team Agents
ID	Requirement	Priority
FR-022	Red agents shall operate in the Kali Linux environment and shall target only the authorized OWASP Juice Shop laboratory.	Must
FR-023	Red agents shall be limited to a configured authorized scope and shall refuse and log any action outside that scope.	Must
FR-024	Red agents shall be able to scan and test the authorized laboratory for permitted weaknesses.	Must
FR-025	Red agents shall generate structured findings containing an identifier, reporting agent, timestamp, affected component, and description.	Must
FR-026	Red agents shall share findings with other Red agents only through the secure message layer.	Should
FR-027	Red agents shall log every attack action with a timestamp and the agent identity.	Must

15.4 Blue Team Agents
ID	Requirement	Priority
FR-028	Blue agents shall operate in the Windows environment and shall read the security logs of the laboratory.	Must
FR-029	Blue agents shall detect suspicious or malicious activity in the logs according to their detection logic.	Must
FR-030	Blue agents shall correlate related events to support detection decisions.	Should
FR-031	Blue agents shall generate a detection event for each detection, recording the time and description.	Must
FR-032	Blue agents shall create defensive block rules in response to detections.	Must
FR-033	Blue agents shall record each block rule and the time at which the response was completed.	Must
FR-034	Blue agents shall verify any message received from another component before acting on it.	Must

15.5 Judge
ID	Requirement	Priority
FR-035	The Judge shall collect attack, detection, verification, and defense events for each run.	Must
FR-036	The Judge shall compute the evaluation metrics defined in Section 25.	Must
FR-037	The Judge shall calculate response time as the interval between an attack event and the corresponding defensive action.	Must
FR-038	The Judge shall generate a final evaluation report for each run.	Must
FR-039	The Judge shall use the record of launched attacks as ground truth when computing detection metrics.	Must
FR-040	The Judge shall exclude events from unverified or unregistered sources from scoring and shall log their exclusion.	Must

15.6 Logging and Reporting
ID	Requirement	Priority
FR-041	The system shall log security-relevant events with a timestamp and the identity of the acting component.	Must
FR-042	The system shall protect logs against unauthorized modification or shall make modification detectable.	Should
FR-043	Reports shall be presented in a human-readable form.	Must
FR-044	The system may support export of reports in one or more file formats. The format is to be selected.	May

16. NON-FUNCTIONAL REQUIREMENTS
Non-functional requirements describe qualities of the proposed system. No numeric performance targets are asserted in this PRD. Where a target is needed, it shall be defined by the project team and recorded as a configurable or measured value.
Table 12: Non-functional requirements
ID	Category	Requirement
NFR-001	Security	The system shall apply the Zero Trust principle to all inter-component communication.
NFR-002	Security	The system shall use established, reviewed cryptographic libraries and shall not rely on custom-designed cryptography.
NFR-003	Reliability	The system shall continue to reject invalid messages correctly when other components fail or are unavailable.
NFR-004	Reliability	The system shall handle malformed input without crashing and shall log the event.
NFR-005	Performance	Verification of a message shall complete quickly enough that it does not prevent timely detection and response. A target value is to be defined.
NFR-006	Performance	Response-time measurement shall be accurate enough to distinguish attack time from defensive action time. Clock handling is to be defined.
NFR-007	Scalability	The design shall allow more than one Red agent and more than one Blue agent to participate in a run.
NFR-008	Scalability	The design should allow additional agents to be added without redesign of the Trust Authority or Judge.
NFR-009	Maintainability	Components shall have documented interfaces and clear separation of concerns.
NFR-010	Maintainability	Configuration values such as the timestamp window and authorized scope shall be configurable and not hard-coded.
NFR-011	Usability	Reports and logs shall be understandable by students, supervisors, and evaluators without access to source code.
NFR-012	Usability	Rejection reasons shall be stated in clear terms in the logs.
NFR-013	Auditability	Every registration, verification decision, attack, detection, and defensive action shall be traceable to an identity and a time.
NFR-014	Auditability	A run shall be reconstructable from the recorded events.
NFR-015	Availability	The Trust Authority shall be available whenever agents need to register or validate identity during a run. The availability target is to be defined.
NFR-016	Availability	When the Trust Authority cannot be reached, receivers shall fail closed rather than accept unverified messages.
NFR-017	Modularity	Red agents, Blue agents, Trust Authority, secure message layer, and Judge shall be separable modules.
NFR-018	Observability	The system shall expose enough event data to monitor registration, messaging, attack, detection, and defense activity.
NFR-019	Extensibility	The design shall allow new attack scenarios, detection methods, and metrics to be added.
NFR-020	Extensibility	The message format shall allow new message types to be introduced with explicit permission rules.

17. SECURITY REQUIREMENTS
Security requirements express how the Zero Trust principle shall be enforced. They are PROPOSED requirements. This document does not claim that the finished system is free of vulnerabilities, and security depends on correct implementation.
Table 13: Security requirements
ID	Area	Requirement
SR-001	Identity	Every participating agent and component shall have a unique identity.
SR-002	Identity	An agent without a registered identity shall have no trusted identity.
SR-003	Authentication	The system shall authenticate the sender of every message.
SR-004	Authentication	Trust shall not be carried over from earlier messages; each message shall be verified on its own.
SR-005	Authorization	The system shall authorize each action according to the sender's role.
SR-006	Authorization	Where no permission is defined, the action shall be denied.
SR-007	Confidentiality	Message payloads shall be encrypted in transit between components.
SR-008	Confidentiality	Secret keys and decrypted payload content shall not be written to general logs.
SR-009	Integrity	Every message shall be digitally signed.
SR-010	Integrity	Messages whose signed content has changed shall be rejected.
SR-011	Non-repudiation (concept)	Signed messages and logs shall allow actions to be attributed to a registered identity. This is a conceptual property of the design and not a legal guarantee.
SR-012	Replay protection	Messages outside the timestamp acceptance window shall be rejected.
SR-013	Replay protection	Previously accepted Message IDs shall be rejected within the acceptance window.
SR-014	Key protection	Secret keys shall be stored and used in a protected manner and shall not be transmitted in plaintext.
SR-015	Key protection	The system shall allow an identity to be revoked if its key is suspected to be compromised.
SR-016	Least privilege	Red agents shall be technically restricted to the authorized laboratory target and shall refuse out-of-scope actions.
SR-017	Least privilege	Each role shall be granted only the permissions necessary for its function.
SR-018	Logging	Security-relevant events shall be logged, including both accepted and rejected messages.
SR-019	Logging	Logs shall be protected against unauthorized modification or shall make modification detectable.
SR-020	Zero Trust	No component, including the Judge and the Trust Authority, shall be trusted without authenticated communication.
SR-021	Secure defaults	The default behaviour for an unverified or unknown input shall be to deny or drop.
SR-022	Secure defaults	The arena shall be operated in an isolated laboratory environment with no authorization to test external systems.
SR-023	Failure handling	Failure of any required verification step shall cause the message to be dropped.
SR-024	Failure handling	Error messages shall not reveal secret keys or internal details to unauthenticated parties.
SR-025	Failure handling	If identity validation cannot be completed, the receiver shall fail closed.
18. DATA REQUIREMENTS
This section defines the logical data entities of the proposed system. Field lists are illustrative and describe the information each entity is expected to hold. No database technology is specified here; storage selection appears in Section 22 as a proposed decision.
Table 14: Logical data entities (illustrative)
Entity	Important Fields	Description
Agent	Agent ID; name; role; environment; status	A participant in the arena (Red, Blue, or Judge).
Identity	Identity ID; agent ID; issued time; status	The verifiable identity assigned or confirmed by the Trust Authority.
Trust Record	Record ID; agent ID; trust status; status history; last updated	The Trust Authority's decision record about an agent.
Key Metadata	Key ID; agent ID; key type; creation time; status	Descriptive information about a key. It does not include plaintext secret key material.
Message	Message ID; sender ID; receiver ID; timestamp; type; payload reference; signature; encryption metadata; permission context	A secure message exchanged between components.
Attack Event	Event ID; Red agent ID; time; target component; action type; outcome	A recorded Red action. Forms the ground truth for evaluation.
Detection Event	Event ID; Blue agent ID; time; related attack event; description; confidence	A detection produced by a Blue agent.
Defense Action	Action ID; Blue agent ID; detection event ID; start time; completion time; type	A defensive response to a detection.
Block Rule	Rule ID; creator; creation time; match criteria; status	A rule that blocks identified activity.
Verification Event	Event ID; message ID; stage reached; result; reason; time	Outcome of verification for one message.
Judge Score	Score ID; run ID; metric name; value; calculation basis	A calculated metric or overall score for a run.
Report	Report ID; run ID; generation time; included metrics; limitations	The final evaluation report for a run.

19. COMMUNICATION PROTOCOL
This section describes the conceptual protocol for agent-to-agent communication. It defines the stages through which a message passes and does not prescribe a specific transport technology. Transport and format are listed as proposed decisions in Section 22.
19.1 Protocol Stages
Table 15: Communication protocol stages
Stage	Description
Message creation	The sender builds a message with all required fields, including a unique Message ID and a current timestamp.
Signing	The sender signs the message with its secret key material.
Encryption	The sender encrypts the payload for the intended receiver.
Transmission	The message is sent to the receiver.
Receiving	The receiver obtains the message and checks that required fields are present.
Verification	The receiver applies identity, signature, integrity, and timestamp checks.
Permission evaluation	The receiver checks that the sender's role may perform the requested action.
Acceptance or rejection	The message is delivered if all checks passed and dropped otherwise.
Logging	Both outcomes are logged with sender, time, and reason.

19.2 Illustrative Message Types
[ILLUSTRATIVE] The names below illustrate how the Message Type field could be used. Final message types are to be defined during design.
Table 16: Illustrative message types
Message Type	Sender Role	Receiver Role	Purpose
Registration request	Any agent	Trust Authority	Request registration and identity.
Finding share	Red agent	Red agent	Pass a finding between Red agents.
Detection alert	Blue agent	Blue agent, Judge	Report a detection.
Defense report	Blue agent	Judge	Report a block rule and response timing.
Attack record	Red agent	Judge	Provide ground truth of launched attacks.
Trust status query	Any component	Trust Authority	Ask whether an identity is currently trusted.

19.3 Conceptual Communication Sequence

Figure 9: Communication sequence between sender, Trust Authority, receiver, and audit log
In the sequence, the sender creates, signs, and encrypts the message and transmits it. The receiver requests identity and permission status from the Trust Authority, runs its verification checks, and records acceptance or rejection in the audit log. If every check passes the message is processed. Otherwise it is discarded.
20. ATTACK AND DEFENSE WORKFLOW
[PROPOSED] This is an end-to-end scenario that is controlled and authorized. It takes place only inside the laboratory against the OWASP Juice Shop target and only with registered agents.

Figure 10: End-to-end system flow
20.1 Scenario Steps
Table 17: End-to-end scenario
Step	Event	Description
1	Red agent registers	The Red agent creates its secret key and registers; the Trust Authority issues an identity.
2	Blue agent registers	The Blue agent registers in the same way.
3	Target identified	The Red agent identifies an authorized Juice Shop target within its scope.
4	Controlled testing	The Red agent performs controlled testing, and logs each action.
5	Lab activity	The lab generates activity and logs.
6	Logs read	The Blue agent receives or reads the logs.
7	Detection	The Blue agent detects suspicious behaviour and generates a detection event.
8	Block rule	The Blue agent creates a block rule and records the response time.
9	Verification	All messages exchanged during the run are verified; failures are dropped and logged.
10	Judge records	The Judge records attack, detection, verification, and defense events.
11	Metrics	The Judge calculates the defined metrics.
12	Report	A final evaluation report is generated.

20.2 Scenario Conditions
•All agents involved shall be registered before testing begins.
•The target shall be limited to the authorized laboratory.
•The laboratory shall be isolated from systems the project is not authorized to test.
•Each run shall have a recorded ground truth of launched attacks.
21. AGENT ROLES
The role matrix below summarizes the roles in the proposed system. Permissions are proposed and subject to design confirmation.
Table 18: Role matrix
Role	Responsibility	Environment	Permissions
Trust Authority	Register agents; issue or confirm identities; maintain trust records; answer trust queries; revoke identities.	To be confirmed	Read and write trust records; answer authenticated queries.
Red Agent	Scan and test the authorized lab; generate and share findings; log attacks.	Kali Linux	Act on authorized target only; send finding and attack-record messages.
Blue Agent	Read logs; detect and correlate activity; create block rules; report to Judge.	Windows	Read lab and arena logs; create block rules; send alert and defense messages.
Judge	Collect verified events; compute metrics; generate the final report.	To be confirmed	Read verified events; write scores and reports. No attack or defense actions.
Juice Shop Lab	Serve as the authorized target; produce activity and logs.	OWASP Juice Shop	Receives authorized test traffic only.
System Administrator (if applicable)	Configure the arena, scope, and acceptance windows; manage the laboratory.	To be confirmed	Configuration access. The role and its limits are to be defined.
22. TECHNOLOGY STACK
Only the technologies below the heading “Current” are known from the project description. All other categories are listed as Proposed / To Be Selected. No implementation stack is asserted.
22.1 Current Environment
Table 19: Current technologies
Category	Technology	Status
Red environment	Kali Linux	CURRENT / IMPLEMENTED
Blue environment	Windows	CURRENT / IMPLEMENTED
Controlled laboratory	OWASP Juice Shop	CURRENT / IMPLEMENTED

22.2 Open Technology Decisions
Table 20: Technologies to be selected
Category	Selection	Status
Programming language	Not selected	Proposed / To Be Selected
Agent framework	Not selected	Proposed / To Be Selected
Database / storage	Not selected	Proposed / To Be Selected
Messaging protocol and transport	Not selected	Proposed / To Be Selected
Cryptographic libraries and algorithms	Not selected. Established, reviewed libraries are required (NFR-002).	Proposed / To Be Selected
Key scheme (asymmetric or symmetric)	Not selected (see Section 11.4)	Proposed / To Be Selected
Logging system	Not selected	Proposed / To Be Selected
Dashboard / reporting presentation	Not selected	Proposed / To Be Selected
Containerization	Not selected	Proposed / To Be Selected
Deployment	Not selected	Proposed / To Be Selected

23. SYSTEM INTERFACES
The interfaces below are conceptual. No interface or API is stated to be implemented. Where implementation status is not confirmed, the status column says so.
Table 21: Conceptual system interfaces
Interface	Purpose	Information Exchanged	Status
Agent to Trust Authority	Registration, identity validation, trust queries.	Registration requests, trust status, role information.	PROPOSED
Red Agent to Red Agent	Share findings.	Signed, encrypted finding messages.	PROPOSED
Red Agent to Lab	Perform controlled testing of the authorized target.	Test requests within the authorized scope.	PROPOSED. Implementation status to be confirmed.
Lab to Logs	Record lab activity.	Application and access log entries.	Implementation status to be confirmed.
Blue Agent to Logs	Monitor activity.	Log entries read by Blue agent.	PROPOSED
Blue Agent to Defense System	Apply block rules.	Rule definitions and confirmation.	PROPOSED. Defense mechanism to be selected.
Agent to Secure Message Layer	Send and receive secure messages.	Messages with the fields in Section 12.1.	PROPOSED
System to Judge	Provide events for evaluation.	Verified attack, detection, verification, and defense events.	PROPOSED
Judge to Report	Produce evaluation output.	Metrics, scores, and summary.	PROPOSED

24. LOGGING AND MONITORING
24.1 Logged Events
Table 22: Logged event types
Event	Description	Typical Fields
Agent registration	A registration request is accepted or rejected.	Agent ID, role, outcome, time
Login / authentication	An agent or component is authenticated, or authentication fails.	Agent ID, result, time
Message sent	A component transmits a message.	Message ID, sender, receiver, type, time
Message received	A component receives a message.	Message ID, receiver, time
Message verified	A message passes all verification checks.	Message ID, checks passed, time
Message rejected	A message fails a check and is dropped.	Message ID, failed stage, reason, time
Attack launched	A Red agent performs a scoped test.	Event ID, Red agent, target component, time
Finding generated	A Red agent records a finding.	Finding ID, agent, time
Detection generated	A Blue agent records a detection.	Event ID, Blue agent, description, time
Block rule created	A Blue agent creates a block rule.	Rule ID, creator, detection ID, time
Judge score generated	The Judge records a metric or score.	Run ID, metric, value, time

24.2 Auditability
Auditability means that a reviewer can reconstruct what happened during a run, by whom, and when. Each logged event identifies the acting component and a time. Rejected messages are logged as carefully as accepted messages, because rejections are evidence of attempted spoofing, tampering, or misuse. Logs shall be protected from alteration, or alteration shall be detectable, so that the Judge and reviewers can rely on them.
24.3 Monitoring
Monitoring is the observation of these events during and after a run. A dashboard is a future enhancement. Initially, monitoring is expected to consist of reading logs and reports.
25. EVALUATION METRICS
This section defines the metrics the Judge may compute. The formulas are evaluation logic. No actual measured performance results are claimed.
25.1 Metric Definitions
1. Detection Rate
Detection Rate = (Detected Attacks / Total Attacks Launched) × 100
Proportion of launched attacks that Blue agents detected. Requires the ground-truth record of launched attacks.
2. Response Time
Response Time = Time of Defensive Action − Time of Attack Event
Computed for each detected attack. The Judge may report the average, minimum, and maximum across a run.
3. Fake Message Block Rate
Fake Message Block Rate = (Fake Messages Blocked / Fake Messages Submitted) × 100
Proportion of deliberately fake or forged test messages that were blocked. Requires a record of the fake messages that were submitted.
4. Verification Success Rate
Verification Success Rate = (Valid Messages Accepted / Valid Messages Submitted) × 100
Measures whether legitimate messages are correctly accepted. A low value would indicate that the pipeline rejects valid communication.
5. Invalid Message Rejection Rate
Invalid Message Rejection Rate = (Invalid Messages Dropped / Invalid Messages Submitted) × 100
Measures whether invalid messages, such as those with bad signatures, modified payloads, or expired timestamps, are correctly dropped.
6. Number of Registered Agents
Count of agents with a valid registration record in a run.
7. Number of Security Events
Count of logged security-relevant events in a run, optionally by event type.
8. Number of Block Rules
Count of block rules created during a run.
9. Detection Accuracy (if ground truth is available)
Detection Accuracy = (TP + TN) / (TP + TN + FP + FN)
Where TP is the number of true detections, TN the number of correctly ignored benign events, FP the number of false detections, and FN the number of missed attacks. This metric is only meaningful when benign and malicious events are labelled.
25.2 Metric Summary
Table 23: Metric inputs
Metric	Inputs Required	Ground Truth Needed
Detection Rate	Attack events; detection events	Yes
Response Time	Attack time; defensive action time	Yes
Fake Message Block Rate	Fake messages submitted; verification events	Yes
Verification Success Rate	Valid messages submitted; verification events	Yes
Invalid Message Rejection Rate	Invalid messages submitted; verification events	Yes
Number of Registered Agents	Trust records	No
Number of Security Events	Event log	No
Number of Block Rules	Defense actions	No
Detection Accuracy	Labelled benign and malicious events; detections	Yes

25.3 Illustrative Report Layout
[ILLUSTRATIVE] ILLUSTRATIVE EXAMPLE — NOT ACTUAL MEASURED DATA. The table below shows only the intended layout of a Judge report. Values are intentionally left blank and are to be filled with measured results from real runs.
Table 24: Illustrative report layout (not actual measured data)
Metric	Value	Notes
Attacks launched	[to be measured]	
Attacks detected	[to be measured]	
Detection Rate	[to be calculated]	Detected / Launched × 100
Mean Response Time	[to be calculated]	Average over detected attacks
Fake messages blocked	[to be measured]	
Invalid messages dropped	[to be measured]	
Block rules added	[to be measured]	

26. TESTING STRATEGY
The testing strategy defines how the requirements will be verified. No tests have been executed as of this document. Status for every test case below is therefore Not Executed.
26.1 Test Levels and Types
Table 25: Test types
Test Type	Purpose
Unit testing	Verify individual functions, such as signature checking or timestamp comparison, in isolation.
Integration testing	Verify that components work together, for example agent and Trust Authority.
System testing	Verify the complete arena workflow from registration to report.
Security testing	Verify that the security requirements hold when the system is subjected to invalid, forged, and unauthorized input.
Authentication testing	Verify that unknown, revoked, or spoofed identities are rejected.
Authorization testing	Verify that roles cannot perform actions they are not permitted to perform.
Message integrity testing	Verify that modified messages are detected.
Timestamp testing	Verify acceptance and rejection at the boundaries of the acceptance window.
Replay-resistance testing	Verify that a repeated message is rejected.
Invalid message testing	Verify that malformed messages and missing fields are rejected safely.
Red/Blue integration testing	Verify that Red activity is logged, detected, and answered by Blue agents.
Judge scoring validation	Verify metrics against manually calculated values on a controlled data set.

26.2 Test Cases
Test cases are PROPOSED. Each references the requirement it verifies. Input descriptions are conceptual and are refined when tests are implemented.
Table 26: Test cases
Test ID	Requirement	Scenario	Input	Expected Result	Status
TC-001	FR-001, FR-002, FR-003, FR-004	Valid agent registration	Registration request with valid role and key information	Identity issued or confirmed; registration record created; event logged	Not Executed
TC-002	FR-005	Duplicate registration	Second request using an already registered identifier	Request rejected; existing record unchanged; event logged	Not Executed
TC-003	FR-005	Malformed registration	Request with missing role or key information	Request rejected; no identity issued	Not Executed
TC-004	FR-006	Role assignment	Registration of one Red, one Blue, and one Judge agent	Each agent recorded with the correct role	Not Executed
TC-005	FR-007, FR-013	Unregistered sender	Message from an identity not in the Trust Authority records	Message dropped at identity check; event logged	Not Executed
TC-006	FR-010, FR-014 to FR-018	Valid message accepted	Correctly formed, signed, encrypted, fresh, permitted message	Message passes all checks and is delivered; acceptance logged	Not Executed
TC-007	FR-010	Missing required field	Message with the Signature or Timestamp field removed	Message dropped as malformed; event logged	Not Executed
TC-008	FR-014	Invalid signature	Valid message with an incorrect signature value	Message dropped at signature check; event logged	Not Executed
TC-009	FR-015	Modified payload	Signed message whose payload is altered after signing	Message dropped at integrity check; event logged	Not Executed
TC-010	FR-016	Expired timestamp	Message with a timestamp older than the acceptance window	Message dropped at timestamp check; event logged	Not Executed
TC-011	FR-016	Future timestamp	Message with a timestamp beyond the acceptable future tolerance	Message dropped at timestamp check; event logged	Not Executed
TC-012	FR-017	Replay attempt	A previously accepted message submitted again within the window	Second submission dropped as replay; event logged	Not Executed
TC-013	FR-018, FR-019	Unauthorized message type	Red agent sends a message type reserved for another role	Message dropped at permission check; event logged	Not Executed
TC-014	FR-012	Encryption round trip	Encrypt a payload at the sender and decrypt at the intended receiver	Receiver recovers the original payload	Not Executed
TC-015	FR-012, FR-019	Undecryptable payload	Message whose payload cannot be decrypted by the receiver	Message dropped; event logged	Not Executed
TC-016	FR-020, FR-041	Accept and reject logging	One accepted and one rejected message	Both events logged with sender, time, and reason	Not Executed
TC-017	FR-009	Revoked identity	Message from an identity marked revoked after registration	Message dropped at identity check	Not Executed
TC-018	FR-008	Trust status query	Authorized component queries the status of a registered agent	Correct trust status returned	Not Executed
TC-019	FR-027	Red activity logging	Red agent performs a scoped test of the lab	Action recorded with timestamp and agent identity	Not Executed
TC-020	FR-022, FR-023	Out-of-scope target refused	Red agent instructed to act on a target outside the authorized scope	Action refused and refusal logged	Not Executed
TC-021	FR-024, FR-025	Structured finding	Red agent identifies a permitted weakness in the lab	Finding created with all required fields	Not Executed
TC-022	FR-026	Authenticated finding exchange	Red agent shares a finding with another Red agent	Message verified and accepted by receiver	Not Executed
TC-023	FR-028, FR-029, FR-031	Selected event detected	Lab logs containing a selected simulated attack pattern	Detection event generated by Blue agent	Not Executed
TC-024	FR-030	Event correlation	Several related log entries from one simulated activity	Entries correlated into one detection	Not Executed
TC-025	FR-032, FR-033	Block rule created and recorded	Detection event requiring a defensive response	Block rule created; rule and response time recorded	Not Executed
TC-026	FR-034	Blue verifies before acting	Block instruction from an unregistered sender	Instruction dropped; no rule applied	Not Executed
TC-027	FR-035	Judge collects events	Attack, detection, verification, and defense events in the log	Judge holds all verified events for the run	Not Executed
TC-028	FR-036, FR-037, FR-039	Judge metric validation	Controlled data set with known attack and detection counts	Calculated metrics equal manually computed values	Not Executed
TC-029	FR-038, FR-043	Final report generation	Completed run with collected events	Report generated containing defined metrics	Not Executed
TC-030	FR-040	Judge rejects unverified input	Event submitted by an unverified source	Event excluded from scoring; rejection logged	Not Executed
TC-031	FR-042	Log tamper detection	Attempt to modify an existing log entry	Modification prevented or detected	Not Executed
TC-032	FR-022 to FR-038	End-to-end scenario	Complete controlled scenario from registration to report	All stages complete; report generated	Not Executed

27. THREAT MODEL
The table below identifies potential threats to the proposed system and the intended mitigation for each. Impact and likelihood are qualitative judgements made at the design stage and shall be reviewed after implementation and testing. Residual risk describes what remains after the mitigation. No mitigation is claimed to eliminate a threat completely.
Table 27: Threat model
Threat	Impact	Likelihood	Mitigation	Residual Risk
Impersonation of an agent	High	Medium	Registration with the Trust Authority; identity and signature checks on every message.	Risk remains if a key is stolen.
Spoofed agents	High	Medium	Unregistered senders are untrusted and dropped at the identity check.	Low if registration is controlled.
Message tampering	High	Medium	Digital signatures and integrity check.	Low if signature handling is correct.
Replay of valid messages	Medium	Medium	Timestamp window and Message ID tracking.	Replays inside the window depend on correct ID tracking.
Unauthorized commands	High	Medium	Role-based permission check; deny by default.	Depends on correct permission rules.
Malicious registered agent	High	Low to Medium	Least privilege; logging; revocation; Judge excludes unverified or inconsistent events.	A registered agent can still act within its role until revoked.
Compromised key	High	Low to Medium	Protected key storage; revocation capability.	Messages signed before revocation may remain valid.
Log manipulation	High	Low to Medium	Log protection or tamper detection; restricted write access.	Depends on how log protection is implemented.
Privilege escalation	High	Low	Least privilege; permission check at each receiver.	Depends on implementation quality.
Denial of service	Medium	Medium	Fail-closed design; rate limiting is a future consideration.	Availability may be reduced during an attack.
False findings	Medium	Medium	Findings are signed, attributed, and compared with logs by the Judge.	A trusted agent could still submit inaccurate findings.
Fake defense events	Medium	Medium	Defense reports are verified and cross-checked with block-rule records.	Cross-checking depends on available data.

28. RISK ANALYSIS
The risk table covers technical, security, operational, and project risks. Ratings are qualitative and reviewed as the project progresses.
Table 28: Risk table
Risk	Impact	Likelihood	Mitigation	Priority
Unclear key scheme leads to inconsistent security design (technical)	High	Medium	Decide the key scheme early and document it in the design.	High
Incorrect cryptographic usage (security)	High	Medium	Use established libraries; review code; test negative cases.	High
Verification pipeline becomes a bottleneck (technical)	Medium	Low to Medium	Measure verification time; optimize after correctness is verified.	Medium
Clock differences between components affect timestamp checks (technical)	Medium	Medium	Define clock handling and tolerance; test boundary cases.	Medium
Detection logic misses selected attacks or raises false alarms (technical)	Medium	Medium	Define test scenarios; use ground truth; refine detection logic.	Medium
Red agents act outside the authorized scope (security)	High	Low	Technical scope restriction; isolated lab; logging.	High
Key exposure through logs or configuration (security)	High	Low to Medium	Exclude secrets from logs; protected storage; reviews.	High
Lab environment is misconfigured or not isolated (operational)	High	Low to Medium	Isolate the lab; document setup; verify before each run.	High
Environment-specific dependencies cause setup failures (operational)	Medium	Medium	Document dependencies; prepare repeatable setup steps.	Medium
Metrics are unreliable because tests are poorly designed (operational)	Medium	Medium	Define ground truth and repeatable scenarios.	Medium
Scope grows beyond available time (project)	Medium	Medium	Prioritize Must requirements; label other items as planned or future.	Medium
Implementation status is misreported (project)	Medium	Low to Medium	Apply the status labels in Section 1.1 consistently.	Medium
Team availability or workload constraints (project)	Medium	Medium	Assign module owners; track progress regularly.	Medium

29. FUTURE ENHANCEMENTS
[FUTURE ENHANCEMENT] The items below are possible extensions. They are not part of the current scope and are not implemented.
Table 29: Future enhancements
Enhancement	Description
More autonomous agents	Agents that make more independent decisions about testing and defense.
Advanced threat intelligence	Use of structured intelligence about attack patterns in detection.
Machine-learning-assisted detection	Detection methods that learn from labelled laboratory data.
Adaptive defense	Block rules and policies that adjust to observed attacker behaviour.
Richer Judge analytics	Deeper analysis such as trends, per-agent comparisons, and confidence measures.
Historical dashboards	Visual presentation of results across multiple runs.
Replayable attack scenarios	Stored scenarios that can be repeated for consistent comparison.
Multi-lab support	Support for more than one authorized laboratory target.
Containerized environments	Packaging of the lab and agents for repeatable deployment.
Stronger policy engines	More expressive and auditable permission and policy rules.
Advanced identity lifecycle	Key rotation, expiry, renewal, and finer-grained trust states.
Scalable agent orchestration	Coordination of larger numbers of agents.

30. PROJECT LIMITATIONS
The following limitations apply to the project as described in this document.
•Controlled laboratory environment. Results apply to the laboratory and may not generalize to production systems.
•Limited number of agents. The prototype is expected to run a small number of agents.
•Limited attack scenarios. Only selected, authorized scenarios against Juice Shop are in scope.
•Prototype-level automation. Agents are expected to automate selected tasks and not the whole of a real security operation.
•Environment-specific dependencies. The design depends on the Kali Linux, Windows, and Juice Shop environments.
•Metrics depend on test quality. Metric values are only as meaningful as the scenarios, ground truth, and data collection behind them.
•Security depends on correct implementation. A sound design can still be weakened by implementation errors.
•Open design decisions. Key scheme, cryptographic choices, and technology stack are not yet selected.
31. ACCEPTANCE CRITERIA
Acceptance criteria define measurable conditions that shall be satisfied for the project to be considered successful. They apply to the proposed system and are verified using the test cases in Section 26.
Table 30: Acceptance criteria
ID	Title	Criterion	Related Requirements
AC-001	Registration	A valid agent can register and receive an identity, and a registration record is created.	FR-001 to FR-006
AC-002	Unknown sender rejection	Messages from unregistered or unknown agents are rejected.	FR-007, FR-013
AC-003	Valid message acceptance	Valid, correctly signed, fresh, permitted messages pass verification and are delivered.	FR-010, FR-014 to FR-018, FR-021
AC-004	Signature verification	Messages with invalid signatures are rejected.	FR-014
AC-005	Integrity verification	Messages with a modified payload are rejected.	FR-015
AC-006	Timestamp validation	Messages with expired or invalid timestamps are rejected.	FR-016
AC-007	Replay protection	A message that is replayed within the acceptance window is rejected.	FR-017
AC-008	Authorization	Unauthorized messages are dropped and not passed to the receiver.	FR-018, FR-019
AC-009	Message logging	Accepted and rejected messages are logged with sender, time, and reason.	FR-020, FR-041, FR-042
AC-010	Red activity logging	Red agent activity generates log entries with timestamp and agent identity.	FR-027
AC-011	Scope enforcement	Red agents refuse targets outside the authorized scope.	FR-022, FR-023
AC-012	Blue detection	Blue agents detect the selected set of simulated events in the lab logs.	FR-028 to FR-031
AC-013	Block rules	Block rules are created in response to detections and are recorded.	FR-032, FR-033
AC-014	Judge metrics	The Judge collects events and computes metrics that match manual calculation on a controlled data set.	FR-035 to FR-037, FR-039, FR-040
AC-015	Evaluation report	The Judge generates a final evaluation report.	FR-038, FR-043
AC-016	Revocation	Messages from a revoked identity are rejected.	FR-008, FR-009
AC-017	Authenticated finding exchange	Findings shared between Red agents are authenticated and verified.	FR-024 to FR-026
AC-018	Verify before acting	Blue agents verify messages before acting on them.	FR-034

32. TRACEABILITY MATRIX
The matrix connects each functional requirement to its feature, the test case that verifies it, and the acceptance criterion it supports. All test cases currently have the status Not Executed.
Table 31: Requirements traceability matrix
Requirement ID	Feature	Test Case	Acceptance Criterion
FR-001 to FR-004	Agent registration and identity	TC-001	AC-001
FR-005	Registration validation	TC-002, TC-003	AC-001
FR-006	Role assignment	TC-004	AC-001
FR-007	Unregistered agents untrusted	TC-005	AC-002
FR-008	Trust status query	TC-018	AC-016
FR-009	Identity revocation	TC-017	AC-016
FR-010	Required message fields	TC-006, TC-007	AC-003
FR-011	Message signing	TC-006, TC-008	AC-003, AC-004
FR-012	Payload encryption	TC-014, TC-015	AC-003
FR-013	Sender identity verification	TC-005	AC-002
FR-014	Signature verification	TC-008	AC-004
FR-015	Integrity verification	TC-009	AC-005
FR-016	Timestamp validation	TC-010, TC-011	AC-006
FR-017	Replay rejection	TC-012	AC-007
FR-018	Permission check	TC-013	AC-008
FR-019	Drop failed messages	TC-013, TC-015	AC-008
FR-020	Message logging	TC-016	AC-009
FR-021	No partial acceptance	TC-006, TC-008	AC-003
FR-022	Red environment and authorized target	TC-020, TC-032	AC-011
FR-023	Authorized scope enforcement	TC-020	AC-011
FR-024	Scanning and testing	TC-021	AC-017
FR-025	Structured findings	TC-021	AC-017
FR-026	Finding exchange	TC-022	AC-017
FR-027	Red action logging	TC-019	AC-010
FR-028	Blue log monitoring	TC-023	AC-012
FR-029	Threat detection	TC-023	AC-012
FR-030	Event correlation	TC-024	AC-012
FR-031	Detection events	TC-023	AC-012
FR-032	Block-rule creation	TC-025	AC-013
FR-033	Block-rule and timing record	TC-025	AC-013
FR-034	Verify before acting	TC-026	AC-018
FR-035	Judge event collection	TC-027	AC-014
FR-036	Metric computation	TC-028	AC-014
FR-037	Response time calculation	TC-028	AC-014
FR-038	Final report generation	TC-029	AC-015
FR-039	Ground truth usage	TC-028	AC-014
FR-040	Exclusion of unverified events	TC-030	AC-014
FR-041	Security event logging	TC-016	AC-009
FR-042	Log protection	TC-031	AC-009
FR-043	Human-readable reports	TC-029	AC-015
FR-044	Report export (optional)	TC-029 (format to be defined)	AC-015
FR-022 to FR-038	End-to-end scenario	TC-032	AC-010, AC-012, AC-013, AC-015

33. GLOSSARY
Table 32: Glossary
Term	Definition
Zero Trust	A security model in which no user, device, or component is trusted automatically. Every access or message must be verified.
Agent	A software component that performs tasks autonomously or semi-autonomously. In this project: Red, Blue, or Judge agents.
Trust Authority	The central component that registers agents, issues or confirms identities, and records trust status.
Red Team	The group of agents that simulate attacker behaviour against the authorized laboratory.
Blue Team	The group of agents that monitor, detect, and defend against the activity.
Judge	The component that evaluates attack and defense performance and produces reports.
Authentication	The process of confirming that an entity is who it claims to be.
Authorization	The process of determining whether an authenticated entity is permitted to perform an action.
Encryption	Transforming data so that only an authorized party can read it.
Digital Signature	A value created with a secret key that lets a receiver confirm the origin and integrity of data.
Integrity	The property that data has not been altered without detection.
Timestamp	A recorded time attached to a message or event, used for freshness checks and measurement.
Replay Attack	An attack in which a previously valid message is captured and sent again.
Block Rule	A defensive rule that prevents identified activity from continuing.
Juice Shop	OWASP Juice Shop, an intentionally vulnerable web application used as the authorized laboratory target.
Threat Detection	The identification of activity that indicates malicious or suspicious behaviour.
Verification	The act of checking that identity, signature, integrity, timestamp, and permission are valid before accepting a message.

34. CONCLUSION
Zero Trust Arena is designed as a controlled cybersecurity arena in which software agents are not trusted by default. Within the proposed design, agents:
•establish identity through a Trust Authority;
•communicate securely through signed and encrypted messages;
•attack only within an authorized laboratory;
•detect and defend through log analysis and block rules;
•have every message verified before it is accepted; and
•are continuously evaluated through recorded security events, producing measurable results.
This PRD has defined the problem, objectives, scope, architecture, workflow, requirements, data, tests, threats, and acceptance criteria needed to build and evaluate the system. It has also stated plainly which parts exist today, namely the Kali Linux and Windows environments and the OWASP Juice Shop laboratory, and which parts are proposed or planned.
The value of the project lies in combining identity, secure communication, controlled attack and defense, and neutral evaluation in one coherent environment. Its conclusions will depend on the quality of the implementation and of the test scenarios used. By recording the evidence and applying the Zero Trust principle consistently, Zero Trust Arena provides a sound basis for studying how autonomous security agents can be made accountable and measurable.
