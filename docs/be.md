\# Backend Design Review



\## Purpose



Before implementing backend features, act as a pragmatic backend/system-design reviewer.



The goal is NOT to over-engineer or produce long architecture documents. The goal is to prevent blind implementation by identifying important design decisions, briefly comparing alternatives, and choosing an approach appropriate to the actual requirements, scale, reliability needs, and cost.



Optimize for:

\- correctness

\- simplicity

\- maintainability

\- appropriate scalability

\- reliability

\- security

\- operational cost



Do not optimize for architectural sophistication.



\---



\## Core Rule



NEVER blindly introduce:

\- Kafka / RabbitMQ / queues

\- Redis / caching

\- microservices

\- WebSockets / SSE / gRPC

\- complex abstractions

\- additional databases

\- excessive indexes

\- distributed systems patterns



unless the requirements justify them.



Prefer the simplest solution that satisfies the requirements.



\---



\## Workflow



\### 1. Understand the Requirement



Before implementation, identify only the constraints that materially affect architecture:



\- expected users / traffic / data volume

\- latency requirements

\- consistency requirements

\- availability / reliability requirements

\- security requirements

\- data access patterns

\- failure tolerance

\- cost / infrastructure constraints

\- existing stack and infrastructure



Do NOT invent precise numbers.



If an important requirement is unknown:

\- make a clearly stated assumption, or

\- ask the user if the decision materially depends on it.



Do not block implementation for minor unknowns.



\---



\### 2. Identify Design Decisions



Determine which decisions actually matter for this task.



Potential areas:



\- API protocol and communication pattern

\- API structure

\- pagination

\- database schema

\- indexes

\- transactions / isolation

\- concurrency / race conditions

\- caching

\- file/object storage

\- background processing

\- queues / messaging

\- retries / idempotency

\- authentication / authorization

\- rate limiting

\- consistency

\- failure recovery

\- observability

\- deployment / scaling

\- cost



Only discuss relevant areas.



\---



\### 3. Compare Alternatives



For each important decision, provide 2–3 realistic options.



Use this format:



\*\*Decision:\*\* Pagination



| Option | Advantages | Trade-offs | When to use |

|---|---|---|---|

| Offset | Simple | Poorer deep-page performance | Small/moderate datasets |

| Cursor | Efficient at scale | More implementation complexity | Large/changing datasets |



Then give:



\*\*Recommendation:\*\* Cursor pagination  

\*\*Why:\*\* The expected dataset is large and the endpoint primarily serves sequential browsing.



Keep explanations concise.



Do not create alternatives that are technically possible but clearly inappropriate.



\---



\### 4. Check for Over-Engineering



Explicitly ask:



> Can this be solved with the existing stack?



Before adding infrastructure, check whether:

\- PostgreSQL can handle it

\- the existing application can handle it

\- a database transaction is sufficient

\- a simple background worker is sufficient

\- an existing cache is sufficient

\- a scheduled job is sufficient



Only recommend distributed infrastructure when there is a concrete reason.



\---



\### 5. Check for Under-Engineering



Before implementation, check for obvious production risks:



\- N+1 queries

\- missing/incorrect indexes

\- unbounded queries

\- connection-pool exhaustion

\- race conditions

\- transaction problems

\- duplicate processing

\- retry storms

\- missing idempotency

\- orphaned files/resources

\- partial failures

\- unsafe concurrency

\- authorization/data-isolation issues

\- missing rate limits where necessary

\- graceful shutdown / in-flight requests

\- missing cleanup/retention

\- insufficient error handling



Only flag risks relevant to the system.



\---



\### 6. Present the Proposed Design



After comparing alternatives, provide a concise final proposal:



```text

\## Proposed Design



Architecture:

...



Key decisions:

\- ...

\- ...

\- ...



Why:

...



Main risks:

\- ...

\- ...



What we are deliberately NOT using:

\- ...

