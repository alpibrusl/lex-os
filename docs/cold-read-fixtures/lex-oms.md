# Fixture: `lex-oms`

> **A study fixture, not a real deployment.** Every digest, registry host,
> Secret name and cluster DNS name below is a consistent invention. Ports and
> the service's dependencies come from its own README.

## What the service does

An HTTP order management server: it accepts orders, applies exchange fills to
update order state and a position book, and serves portfolio risk. It is the
hub of a small stack rather than a leaf, which is what makes its egress a real
decision.

Facts that bear on a manifest:

- It listens on `:8080`.
- It keeps order and position state, so it is not stateless.
- It calls **`lex-risk`** for portfolio Greeks, notional and margin.
- `POST /mifid-report` builds a regulatory transaction report using
  **`lex-finance`**. That endpoint is stateless by design: there is no
  instrument master and no counterparty-LEI store, so callers supply the
  reference data in the request body.
- Exchange fills arrive from outside the cluster.

## The deployment

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: trading
  labels:
    lex.dev/gated: "true"
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: lex-oms
  namespace: trading
---
apiVersion: v1
kind: Secret
metadata:
  name: lex-oms-db               # Postgres DSN
  namespace: trading
type: Opaque
---
apiVersion: v1
kind: Secret
metadata:
  name: lex-oms-venue            # exchange API credential
  namespace: trading
type: Opaque
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: lex-oms
  namespace: trading
spec:
  replicas: 2
  template:
    spec:
      serviceAccountName: lex-oms
      containers:
        - name: oms
          # fixture digest — this artifact does not exist
          image: registry.internal.example/trading/lex-oms@sha256:b41d7e05c9382af610d5be7724c8f39a0e6d21bb85c470f3ea9d18c60b7f2a45
          ports:
            - containerPort: 8080
          env:
            - name: PORT
              value: "8080"
            - name: RISK_URL
              value: http://lex-risk.trading.svc.cluster.local:8081
            - name: FINANCE_URL
              value: http://lex-finance.trading.svc.cluster.local:8082
            - name: DB_URL
              valueFrom:
                secretKeyRef: { name: lex-oms-db, key: dsn }
            - name: VENUE_TOKEN
              valueFrom:
                secretKeyRef: { name: lex-oms-venue, key: token }
          resources:
            requests: { cpu: 500m, memory: 1Gi }
            limits:   { cpu: "2",  memory: 2Gi }
```

State lives in a Postgres reached at
`postgres.data.svc.cluster.local:5432` — outside this namespace, inside the
cluster.

## What the cluster already enforces

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: lex-oms
  namespace: trading
spec:
  podSelector:
    matchLabels: { app: lex-oms }
  policyTypes: ["Ingress", "Egress"]
  ingress:
    - from:
        - namespaceSelector:
            matchLabels: { name: edge }
      ports:
        - port: 8080
  egress:
    - to:
        - namespaceSelector:
            matchLabels: { name: kube-system }
      ports:
        - port: 53
          protocol: UDP
    - to:
        - podSelector:
            matchLabels: { app: lex-risk }
        - podSelector:
            matchLabels: { app: lex-finance }
    - to:
        - namespaceSelector:
            matchLabels: { name: data }
      ports:
        - port: 5432
    - ports:                      # venue API, on the public internet
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
  "egress": ["*.internal.example:443", "*.svc.cluster.local:*"]
}
```

## What you decide

The grant, the egress list, the budget, the isolation floor, and a
`LexManifest` naming that parent.

Worth noticing before you start: this workload has **two replicas**, and it is
a server that is meant to stay up. Both facts sit awkwardly against fields
shaped for a bounded job. Record where, rather than picking a number and moving
on.
