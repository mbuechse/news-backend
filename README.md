# news-backend
Very early stage of a bespoke backend that I conceived

Proof of concept. Definitely sketchy, in the spirit of [Stop future proofing software](https://blog.cerebralab.com/#!/a/Stop%20future%20proofing%20software)

Features:
* ultra-simple NoSQL storage in RDBMS (in this case, `sqlite`)
  * probably not unlike a typical IndexedDB implementation
  * single table for all objects plus "projections" for member fields needed in queries
  * modular schema (see `db.go`)
* (unidirectional, on demand) sync of JSON object graphs from server to client via "REST" API
* common queries (corresponding to views in the frontend) are materialized (because writes are super rare compared to reads)
* materialized views are augmented by a "prefetch" attribute (a list of all objects reachable from the query result) that reduces the number of roundtrips to at most two (fetch query result, fetch missing references)
* job queue with (currently) five workers (simple thanks to goroutines and channels)
* intermediate representation of JSON objects similar to e-mail (header + body)
* privilege-based object transformation (not everyone can see everything)
* authentication via JSON Web Token
