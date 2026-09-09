# Fixture: `lex-guard`

> **A study fixture, not a real deployment.** Every digest, registry host,
> Secret name and cluster DNS name below is a consistent invention. The
> executors and what they reach come from the service's own README.

## What the service does

Spending guardrails for agents: capability-gated budget tokens with an
attestation trail. An agent asks to spend; `lex-guard` decides against a
policy and, if it approves, actually settles the payment.

Facts that bear on a manifest:

- The policy is compiled to a checkable spec, so the decision itself is
  inspectable.
- Executors are pluggable, and two of them reach the outside world:
  - `http_exec` posts to a real payment endpoint — the fixture below wires it
    to Stripe Issuing.
  - `x402_exec` settles over the x402 `402 Payment Required` handshake and
    returns an **on-chain transaction hash** as the spend reference.
- It keeps an attestation trail of decisions, so it has durable state.

This is the one service in the study whose *purpose* is bounding spend, so its
manifest budget and its own policy are two budgets pointed at the same thing.
Working out how they relate is part of the exercise, and neither README says.

## The deployment

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: settlement
  labels:
    lex.dev/gated: "true"
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: lex-guard
  namespace: settlement
---
apiVersion: v1
kind: Secret
metadata:
  name: lex-guard-stripe          # Stripe Issuing API key
  namespace: settlement
type: Opaque
---
apiVersion: v1
kind: Secret
metadata:
  name: lex-guard-signer          # x402 settlement signing key
  namespace: settlement
type: Opaque
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: lex-guard-trail
  namespace: settlement
spec:
  accessModes: ["ReadWriteOnce"]
  resources:
    requests:
      storage: 10Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: lex-guard
  namespace: settlement
spec:
  replicas: 1
  template:
    spec:
      serviceAccountName: lex-guard
      containers:
        - name: guard
          # fixture digest — this artifact does not exist
          image: registry.internal.example/settlement/lex-guard@sha256:7c2e58ab9d1f406e83b7c05d2a91feb4738052ce16a9bd3f0c847e2b95d1a608
          ports:
            - containerPort: 8070
          env:
            - name: PORT
              value: "8070"
            - name: TRAIL_PATH
              value: /trail/guard.db
            - name: STRIPE_URL
              value: https://api.stripe.com/v1/issuing/authorizations
            - name: STRIPE_API_KEY
              valueFrom:
                secretKeyRef: { name: lex-guard-stripe, key: key }
            - name: X402_SIGNER_KEY
              valueFrom:
                secretKeyRef: { name: lex-guard-signer, key: key }
            - name: ATTEST_URL
              value: http://lex-attest.evidence.svc.cluster.local:8090
          volumeMounts:
            - name: trail
              mountPath: /trail
          resources:
            requests: { cpu: 250m, memory: 512Mi }
            limits:   { cpu: "1",  memory: 1Gi }
      volumes:
        - name: trail
          persistentVolumeClaim:
            claimName: lex-guard-trail
```

## What the cluster already enforces

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: lex-guard
  namespace: settlement
spec:
  podSelector:
    matchLabels: { app: lex-guard }
  policyTypes: ["Ingress", "Egress"]
  ingress:
    - from:
        - namespaceSelector:
            matchLabels: { name: agents }
      ports:
        - port: 8070
  egress:
    - to:
        - namespaceSelector:
            matchLabels: { name: kube-system }
      ports:
        - port: 53
          protocol: UDP
    - to:
        - namespaceSelector:
            matchLabels: { name: evidence }
      ports:
        - port: 8090
    - ports:                      # Stripe, and an x402 RPC endpoint
        - port: 443
          protocol: TCP
```

## The ceiling you must narrow

```
parent: cluster/platform-default
```

```json
{
  "goal": { "description": "platform ceiling for tenant workloads" },
  "grant": { "filesystem": "ReadWrite", "network": "Allowlist", "exec": "Sandboxed" },
  "budget": { "wall_clock_secs": 86400, "max_commands": 100000,
              "max_money_cents": 50000, "max_api_calls": 1000000 },
  "isolation_floor": "Gvisor",
  "egress": ["*.internal.example:443", "api.stripe.com:443"]
}
```

## What you decide

The grant, the egress list, the budget, the isolation floor, and a
`LexManifest` naming that parent.

The question worth spending your confusion on: the parent's
`max_money_cents` is 50000. This service **moves money on behalf of other
agents**, and it has its own policy governing how much. Does the manifest
budget bound what `lex-guard` itself may spend, what it may approve on behalf
of others, or something else entirely? Whatever you conclude, log how you
concluded it — and if the answer is not determinable from what you were given,
that is the finding.
