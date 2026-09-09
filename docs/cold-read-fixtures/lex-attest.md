# Fixture: `lex-attest`

> **A study fixture, not a real deployment.** Every digest, registry host,
> Secret name and cluster DNS name below is a consistent invention. Ports,
> environment variables, storage and outbound destinations come from the
> service's own README.

## What the service does

An attestation sidecar: an append-only, hash-chained event log with an
authenticated HTTP API, so a system in any language can sign, chain and verify
evidence without adopting Lex.

Four calls: append an event, link an event to a parent, walk a chain back to
its root, and verify a device signature. Separately, it can **publish anchors**
— committing a chain head to an outside destination so the log cannot later be
rewritten quietly.

Facts that bear on a manifest:

- It listens on `:8090` and authenticates with a bearer token (`ATTEST_KEY`).
- It stores its own database. `DB_PATH` selects SQLite (default) or Postgres.
- Anchor publication makes **outbound** calls. Destinations are
  **caller-supplied** per request — a webhook URL in the request body — with
  OpenTimestamps as a standing option.
- It runs under the Lex runtime, which is started with these effects allowed:
  `net, io, time, env, sql, fs_read, fs_write, concurrent, random, crypto, llm, proc, approval`.

That last point is worth sitting with rather than transcribing. A Lex effect
and a trust dimension are not the same vocabulary, and the effect list is what
the *runtime* was given, not what the workload needs.

## The deployment

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: evidence
  labels:
    lex.dev/gated: "true"        # opted in to the admission wall
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: lex-attest
  namespace: evidence
---
apiVersion: v1
kind: Secret
metadata:
  name: lex-attest-auth          # holds ATTEST_KEY
  namespace: evidence
type: Opaque
---
apiVersion: v1
kind: Secret
metadata:
  name: lex-attest-signing       # the device-verification keypair
  namespace: evidence
type: Opaque
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: lex-attest-data
  namespace: evidence
spec:
  accessModes: ["ReadWriteOnce"]
  resources:
    requests:
      storage: 20Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: lex-attest
  namespace: evidence
spec:
  replicas: 1
  template:
    spec:
      serviceAccountName: lex-attest
      containers:
        - name: attest
          # fixture digest — this artifact does not exist
          image: registry.internal.example/evidence/lex-attest@sha256:3f9c1a77b0e24d6a8c5b31ef07429dd6541ab2c8093e7f6b1d4a05c8e2b7369f
          ports:
            - containerPort: 8090
          env:
            - name: PORT
              value: "8090"
            - name: DB_PATH
              value: /data/attest.db
            - name: ATTEST_KEY
              valueFrom:
                secretKeyRef:
                  name: lex-attest-auth
                  key: token
          volumeMounts:
            - name: data
              mountPath: /data
          resources:
            requests: { cpu: 250m, memory: 512Mi }
            limits:   { cpu: "1",  memory: 1Gi }
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: lex-attest-data
```

## What the cluster already enforces

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: lex-attest
  namespace: evidence
spec:
  podSelector:
    matchLabels: { app: lex-attest }
  policyTypes: ["Ingress", "Egress"]
  ingress:
    - from:
        - namespaceSelector:
            matchLabels: { name: settlement }
      ports:
        - port: 8090
  egress:
    - to:
        - namespaceSelector:
            matchLabels: { name: kube-system }
      ports:
        - port: 53
          protocol: UDP
    - ports:                      # anchor publication: 443, anywhere
        - port: 443
          protocol: TCP
```

Note what that last rule does and does not say. It is the shape a
hostname-less policy language forces, and it is the substrate limitation the
egress caution in the lex-k8s README is about.

## The ceiling you must narrow

```
parent: cluster/platform-default
```

which grants, in `lex-system`:

```json
{
  "goal": { "description": "platform ceiling for tenant workloads" },
  "grant": { "filesystem": "ReadWrite", "network": "Allowlist", "exec": "Sandboxed" },
  "budget": { "wall_clock_secs": 86400, "max_commands": 100000,
              "max_money_cents": 50000, "max_api_calls": 1000000 },
  "isolation_floor": "Gvisor",
  "egress": ["*.internal.example:443", "alice.opentimestamps.org:443",
             "bob.opentimestamps.org:443"]
}
```

## What you decide

The grant, the egress list, the budget, the isolation floor, and — for the
admission wall — a `LexManifest` naming that parent.

Two things here have no obviously right answer, which is the point:

- The service publishes to destinations **a caller names at request time**. A
  static allowlist cannot enumerate them.
- It holds a signing key, and the parent's floor is `Gvisor`. A child may only
  narrow, and the floor narrows *upward*.

Log what you decide and why. If you conclude the workload cannot be expressed
under this ceiling, that is a finding, not a failure.
