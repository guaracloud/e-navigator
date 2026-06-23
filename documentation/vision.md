# E-Navigator

## Vision

Provide a zero-configuration observability, profiling, security, and diagnostics platform for workloads using ebpf and other means.

Users should be able to deploy an application and immediately answer:

- What is happening?
- Why is it happening?
- Who is affected?
- What changed?
- What should I do next?

The platform should require no SDKs, no sidecars, and minimal configuration whenever possible through the use of eBPF and other means, e-navigator produces OpenTelemetry compatible metrics, signals, data and information as much as possible.

The main purpose is to be used within Kubernetes, but aimed to general use as well.

In a perfect world and application, we want to replace external flow agent, external profile backend, trace backend with a single super eficient tool built with Rust.

## Core Observability Pillars

### 1. Infrastructure Observability

#### Node Metrics

Collect and visualize:

- CPU usage
- CPU saturation
- Load average
- Memory usage
- Memory pressure
- Swap usage
- Disk usage
- Disk I/O throughput
- Disk I/O latency
- Filesystem latency
- Network throughput
- Network packet loss
- TCP retransmits
- TCP resets

### 2. Runtime Observability

#### Container Metrics

Per container:

- CPU usage
- Memory usage
- RSS
- Heap size
- Open file descriptors
- Thread count
- Process count
- Open sockets
- Allocation rate
- Garbage collection activity

#### Process Visibility

Track:

- Process creation
- Process termination
- Runtime duration
- Resource consumption

### 3. Service Discovery & Dependency Mapping

Automatically discover:

- Service-to-service communication
- Pod-to-pod communication
- External dependencies
- Databases
- Message brokers
- Third-party APIs

Example:

Frontend
→ API

API
→ PostgreSQL
→ Redis
→ Stripe
→ S3

Worker
→ OpenAI

For every dependency collect:

- Requests per second
- Traffic volume
- Latency
- Error rate
- Availability

### 4. Network Observability

#### Connection Metrics

Per pod and service:

- Active connections
- New connections
- Failed connections
- TCP latency
- Retransmits
- Resets
- Timeouts
- Connection duration

#### Traffic Metrics

Track:

- Ingress traffic
- Egress traffic
- Traffic destinations
- Traffic sources
- Protocol distribution

#### DNS Observability

Track:

- DNS requests
- Lookup latency
- NXDOMAIN responses
- SERVFAIL responses
- Query volume
- Domains accessed

Example:

api-pod

- api.openai.com
- api.stripe.com
- github.com
- amazonaws.com

### 5. Distributed Tracing

#### Request Visibility

Track:

- Request ID
- Trace ID
- Service path
- Latency
- Errors
- Retries
- Timeouts

Example:

GET /checkout

Frontend
20ms

API
220ms

PostgreSQL
180ms

Total
240ms

#### Trace Analysis

Provide:

- Critical path analysis
- Slowest span detection
- Dependency bottlenecks
- Error propagation visualization

### 6. Continuous Profiling

#### CPU Profiling

Per workload:

- CPU flamegraphs
- Hot functions
- Hot call stacks
- CPU time attribution

Examples:

- processOrder()
- generateInvoice()
- bcrypt.hash()
- pdfRenderer()

#### Memory Profiling

Track:

- Allocation rate
- Allocation hotspots
- Retained memory
- Memory growth trends
- Leak indicators

#### Lock Profiling

Track:

- Mutex contention
- Wait duration
- Blocking operations
- Synchronization bottlenecks

### 7. Runtime Security

#### Process Monitoring

Detect:

- Shell execution
- Suspicious binaries
- Reverse shells
- Unexpected child processes

Examples:

- bash
- sh
- curl
- nc
- socat

#### Secret Access

Detect:

- Service account token access
- Kubernetes secret access
- Sensitive file reads

#### Lateral Movement

Detect:

- Internal network scanning
- Service probing
- Unauthorized communication

#### Crypto Miner Detection

Detect indicators:

- High sustained CPU
- Mining pools
- Mining protocols
- Known mining binaries

## Tech stack

- Rust
- Cargo
- eBpf
- OpenTelemetry
