# Architecture Decisions

## Decision: Single-threaded live capture

**Context**: Production-grade DPI engines (e.g., the reference architecture I studied) commonly use a multi-threaded pipeline — a reader thread, load-balancer threads distributing work by 5-tuple hash, and multiple fast-path worker threads doing the actual parsing in parallel — specifically to handle high packet rates (10Gbps+ datacenter-scale traffic) without dropping packets.

**Decision**: I built single-threaded capture first and measured actual performance before adding complexity.

**Evidence**: Under simulated heavy load (concurrent 4K video streaming + large file download), measured packet drop rate was 0.0% using `pcap_stats()`. A single core effortlessly processed 190,637 packets with zero buffer overflows.

**Conclusion**: Single-threaded capture is more than sufficient for typical home/laptop network traffic rates. The parser is highly optimized, and typical gigabit traffic simply isn't fast enough to overwhelm a modern CPU on a single core. Introducing multithreading would have only added unnecessary synchronization overhead, mutex contention, and complexity without providing any tangible performance benefit. Drops would need to become measurable (likely pushing multi-gigabit rates with pure IPv4/TLS payload storms) before justifying the load-balancer + fast-path architecture. 

This mirrors a real engineering tradeoff: complexity should be justified by measured need, not added preemptively.
