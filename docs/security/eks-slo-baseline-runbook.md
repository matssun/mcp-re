<!-- SPDX-License-Identifier: Apache-2.0 -->

# EKS ADR-051 §7 SLO baseline + AWS KMS live lanes — runbook

The AWS counterpart to [`gke-slo-baseline-runbook.md`](gke-slo-baseline-runbook.md).
Same envelope, same Job spec, same gate — only the cluster substrate and the
registry differ. Everything here is **torn down after each run**; the repo keeps the
*setup*, not live cloud resources.

- Account `455880745808`, region `eu-north-1`.
- Artifacts: `deploy/eks/mcp-re-slo-cluster.yaml`, `deploy/docker/Dockerfile.bench`,
  `tools/slo/run_slo_job.sh`, `scripts/slo_gate.py`,
  `docs/bench/adr-051-slo-targets.json`, `scripts/test-aws-cloud.sh.example`.

## Run everything locally first (non-negotiable)

Identical rule to the GKE runbook, for the identical reason: AWS is not where bugs
get found.

```sh
scripts/local_gate.sh --with-kind    # stages 1-5, including the fleet proofs on kind
```

Stage 5 additionally rehearses the **exact** SLO Job spec this runbook schedules —
`PROVIDER=kind tools/slo/run_slo_job.sh - kind-local 1 kind_1core.json` runs the same
manifest, the same Redis sidecars, the same bench image and the same marker-based
report extraction on a local kind node. Its throughput number is **not** a baseline
and must never be fed to `slo_gate.py`; its value is that every piece of plumbing
between `kubectl apply` and a parsed report is proven before an EC2 instance exists.

Two things the kind rehearsal structurally cannot cover, and which therefore fail
first on a real cluster if they are wrong:

- the `eks.amazonaws.com/nodegroup` node label, which only exists on EKS nodes;
- ECR authentication on the node's pull.

## 0. AWS KMS live lanes (independent of the cluster)

These need no cluster and no cluster spend — just the KMS key.

```sh
cp scripts/test-aws-cloud.sh.example work/test-aws-cloud.sh   # work/ is gitignored
./work/test-aws-cloud.sh
```

It creates (idempotently, via `alias/mcp-re-ed25519-object`) one
`ECC_NIST_EDWARDS25519` CMK and runs, against it: object signing, delegated-required
serving + authority flip, delegated-signing custody, and the HTTP profile. It then
probes the FIPS endpoint and schedules the key for deletion.
See [`cloud-kms-claims-map.md`](cloud-kms-claims-map.md) for what each lane earns and
[`aws-kms-fips-protection-level.md`](aws-kms-fips-protection-level.md) for why the
FIPS probe is recorded separately and never rides along with the custody claim.

Two lanes are deliberately NOT in that script:

- **Delegated TLS** needs a SECOND, DISTINCT key, because what it proves is that the
  TLS server key and the object-signing key are separate security principals an
  operator can scope with separate policies. Reusing one key would demonstrate the
  opposite, so the script skips the lane loudly rather than substituting.

  ```sh
  export MCP_RE_AWS_KMS_TLS_KEY_ID=<a second ECC_NIST_EDWARDS25519 key>
  ./work/test-aws-cloud.sh     # now includes the delegated-TLS lane
  ```

- **Root rotation** creates and destroys TWO disposable keys, so it is its own fenced
  runner rather than something folded into a lane script:

  ```sh
  MCP_RE_LIVE_KMS_TESTS=1 MCP_RE_ALLOW_TEST_KMS_CREATE=1 \
    docs/security/aws-kms-root-rotation.sh
  ```

  It refuses to run outside the account allowlist, only ever creates keys under the
  fenced `alias/mcp-re-live-test-*` prefix, and registers each created ARN for
  teardown before it is aliased.

Cost: `$1.00`/month prorated hourly per CMK, plus ~`$0.15` per 10,000 asymmetric
requests. A full run is a few cents.

### 0b. IRSA — the run that makes the custody claim equal to GKE's

Everything above authenticates with the static `AWS_*` pair in your shell. That is
fine for a laptop-run lane and is NOT the posture an EKS deployment should have: a
long-lived IAM key pair does not expire and authorizes `kms:Sign` for as long as the
Secret exists. The GKE runs' headline is the opposite — the pod holds no key material
and no long-lived credential, only a short-lived assertion naming it.

The AWS equivalent is IRSA, and it is what `--aws-kms-use-web-identity` takes. One
setup run per cluster:

```sh
MCP_RE_CONFIRM_IRSA_KMS_SETUP=1 docs/security/eks-kms-irsa-setup.sh
export MCP_RE_AWS_KMS_ROLE_ARN="$(aws iam get-role --role-name mcp-re-kms-signer \
  --query 'Role.Arn' --output text)"
```

That creates an IAM role whose trust policy pins BOTH `:sub` (one
namespace/serviceaccount — without it any pod in the cluster could assume it and sign
with the fleet's root key) and `:aud` (`sts.amazonaws.com`), and grants exactly
`kms:Sign` + `kms:GetPublicKey` on the one key ARN.

To run a live lane through IRSA rather than static keys, set
`MCP_RE_AWS_USE_WEB_IDENTITY=1` — inside a pod, where the projected token exists:

```sh
MCP_RE_AWS_USE_WEB_IDENTITY=1 cargo test -p mcp-re-proxy \
  --features aws_kms_keysource --test aws_kms_live_test -- --ignored --nocapture
```

The offline twin (`aws_irsa_web_identity_test`, 12 cases against a fake STS) runs on
every push and guards the wiring. It cannot guard the thing that actually breaks
first: whether EKS projects the token at the path the adapter reads, with an audience
the trust policy accepts. That is what an on-cluster run is for — the GKE twin found
its equivalent (the WI metadata token URL) exactly this way.

## 0c. The four fleet coherence proofs on EKS

Same harness, same chart, same assertions as GKE — only the substrate differs:

```sh
export ECR_REGISTRY=<acct>.dkr.ecr.eu-north-1.amazonaws.com
export MCP_RE_FIXTURES_DIR=<emit_mtls_fixtures output>
export MCP_RE_AWS_KMS_KEY_ID=alias/mcp-re-ed25519-object
export MCP_RE_AWS_KMS_ROLE_ARN=<from 0b>
PROVIDER=eks docs/security/gke-multi-replica-validation.sh
PROVIDER=eks docs/security/gke-multi-replica-validation.sh --teardown
```

It creates the cluster `--with-oidc` (no OIDC provider, no IRSA, no custody claim) and
turns on **VPC CNI NetworkPolicy enforcement**, failing the run if it cannot. On EKS a
NetworkPolicy is accepted and enforces nothing unless the addon has it enabled — the
same state the v0.11/v0.12.1 GKE runs were in, where the four proofs passed and the
inner-plane policy filtered no packets, so any pod could POST past the PEP with no
signature, no replay admission and no audit record.

Run `PROVIDER=kind` first. It is the identical test for free.

## 1. ECR repository + the bench image

The bench image is a from-source Rust build with a **warmed `target/`** so the Job
runs with no recompile. Build it natively for the node architecture — the cluster is
Graviton (arm64) precisely so an Apple-silicon developer box builds it natively
instead of crawling through QEMU.

```sh
ACCT=$(aws sts get-caller-identity --query Account --output text)
REGION=eu-north-1
ECR_REGISTRY=$ACCT.dkr.ecr.$REGION.amazonaws.com
TAG=$(tr -d '[:space:]' < VERSION)          # never retype the tag

aws ecr create-repository --region $REGION --repository-name mcp-re-slo-bench || true
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $ECR_REGISTRY

docker build --platform linux/arm64 -f deploy/docker/Dockerfile.bench \
  -t $ECR_REGISTRY/mcp-re-slo-bench:$TAG .
docker push $ECR_REGISTRY/mcp-re-slo-bench:$TAG
```

`.dockerignore` keeps `target/` (tens of GB, host-arch) out of the build context.

## 2. Cluster

The cluster config carries a literal `OPERATOR_CIDR` placeholder for the
control-plane endpoint allowlist. eksctl's default is `0.0.0.0/0` — the Kubernetes
API reachable from the whole internet for the life of the run — so the placeholder is
there to make an unset allowlist FAIL rather than silently mean "everyone".

```sh
sed -i "s|OPERATOR_CIDR|$(curl -fsS https://checkip.amazonaws.com)/32|" \
  deploy/eks/mcp-re-slo-cluster.yaml
eksctl create cluster -f deploy/eks/mcp-re-slo-cluster.yaml
kubectl create namespace mcp-re
```

Two managed nodegroups, `m7g.2xlarge` and `c7g.2xlarge`, 8 vCPU each. 16 vCPU total
against the account's 32-vCPU `L-1216C47A` quota, so both classes run concurrently.
The config disables the NAT gateway (nodes are in public subnets and never use it)
and sets a 100 GiB gp3 root volume (the warmed bench image overruns the 20 GiB
default during the pull).

## The Free Tier instance-type block (why the baseline is not measurable here yet)

**On a Free Tier plan account the §7 declared-hardware baseline cannot be run at
all**, and no quota increase changes that. Creating the `m7g.2xlarge` /
`c7g.2xlarge` nodegroups above fails at instance launch:

```text
Code=AsgInstanceLaunchFailures
Message=Could not launch On-Demand Instances. InvalidParameterCombination -
        The specified instance type is not eligible for Free Tier.
```

The CloudFormation nodegroup stack then rolls back and deletes the nodegroup, so
the symptom is a ~25-minute `CREATING` with an empty `health.issues[]`, followed by
`eksctl` exiting on its own wait timeout — the eligibility error only appears in the
nodegroup stack's `CREATE_FAILED` event, not in `describe-nodegroup`.

This is an **account-plan restriction, not a quota**. `L-1216C47A` on this account was
raised to 32 vCPU and is irrelevant while the plan blocks the instance family. Every
free-tier-eligible type is 2 vCPU and burstable:

| Type | Arch | vCPU | Memory |
|---|---|---|---|
| `t4g.micro` / `t4g.small` | arm64 | 2 | 1 / 2 GiB |
| `t3.micro` / `t3.small` | x86_64 | 2 | 1 / 2 GiB |
| `c7i-flex.large` / `m7i-flex.large` | x86_64 | 2 | 4 / 8 GiB |

A 1→N scaling curve needs an N-core class, and a throughput floor measured on a
credit-based burstable instance would not be a floor. So the baseline needs the
account moved to a **paid plan** — an owner/billing action, exactly like the GCP
free-trial upgrade described in
[`gke-slo-baseline-runbook.md`](gke-slo-baseline-runbook.md#the-cpus_all_regions-quota-why-16-blocked-the-second-8-vcpu-pool).
Until then, `deploy/eks/mcp-re-slo-cluster.yaml` records the intended shape and the
plumbing dry-run below is what the account can actually execute.

### Plumbing dry-run on a free-tier node

Proves the two things a kind rehearsal structurally cannot: the real
`eks.amazonaws.com/nodegroup` selector, and ECR authentication on a real node pull.
Like the kind rehearsal, its throughput number is **NOT a baseline** and must never
reach `slo_gate.py`.

```sh
eksctl create nodegroup --cluster mcp-re-slo --region eu-north-1 \
  --name ng-t4gs --node-type t4g.small --nodes 1 --node-volume-size 60 \
  --node-ami-family AmazonLinux2023
# 2 vCPU / 2 GiB, so the declared-hardware resource requests cannot be used as-is.
PROVIDER=eks CPU_REQUEST=1 MEM_REQUEST=1Gi \
  REDIS_IMG=public.ecr.aws/docker/library/redis:7-alpine \
  ECR_REGISTRY=$ECR_REGISTRY \
  tools/slo/run_slo_job.sh ng-t4gs t4g.small 1 t4g_1core.json
```

`t4g.small` allocatable is `cpu=1930m mem=1399616Ki`, so the declared-hardware
`CPU_REQUEST=6` / `MEM_REQUEST=2Gi` cannot be admitted — the pod would sit Pending
until the Job timed out, with no scheduling error on the Job itself.

**Run of 2026-08-01 — PASSED**, `8000/8000` successes, `156.3` rps under the canonical
v2 envelope (`hardware_class=t4g.small`, `declared_cores=1`, concurrency 128,
`carrier=rfc9421+rfc9530`). The rps figure is meaningless as a floor — a 2-vCPU
burstable instance — and is recorded only to show the lane ran. What it establishes:

```text
pod node      = ip-192-168-24-104.eu-north-1.compute.internal
pod selector  = {"eks.amazonaws.com/nodegroup":"ng-t4gs"}
pull event    = Successfully pulled image
                455880745808.dkr.ecr.eu-north-1.amazonaws.com/mcp-re-slo-bench:0.16.0
                in 36.158s. Image size: 887881847 bytes.
```

That is a real authenticated pull from private ECR onto a real EKS node through the
real nodegroup selector — the two things the kind rehearsal cannot reach. The rest of
the lane (Job spec, Redis sidecars, marker-based report extraction, JSON schema) was
already proven on kind and behaved identically here.

## 3. The measurements

The SLO Job is **self-contained**: `tls_load_harness_bench` spawns its own
`mcp-re-proxy` async fleet and echo backend inside the Job pod. No fleet Deployment,
Service, load balancer or shared Redis is required — the Job's three Redis sidecars
supply the WAIT-2 durability tier.

```sh
export ECR_REGISTRY REDIS_IMG=public.ecr.aws/docker/library/redis:7-alpine
PROVIDER=eks tools/slo/run_slo_job.sh ng-m7g2x m7g.2xlarge 1 m7g_1core.json
PROVIDER=eks tools/slo/run_slo_job.sh ng-m7g2x m7g.2xlarge 8 m7g_8core.json
PROVIDER=eks tools/slo/run_slo_job.sh ng-c7g2x c7g.2xlarge 1 c7g_1core.json
PROVIDER=eks tools/slo/run_slo_job.sh ng-c7g2x c7g.2xlarge 8 c7g_8core.json

python3 scripts/slo_gate.py --report m7g_8core.json \
  --baseline m7g_1core.json --scaled m7g_8core.json \
  --targets docs/bench/adr-051-slo-targets.json
```

`REDIS_IMG` points at the ECR Public Gallery mirror rather than Docker Hub: an
anonymous Docker Hub pull from EC2 is rate-limited per source IP, and three sidecars
per Job pod is exactly the shape that trips it. ECR Public needs no credentials and
has no such limit.

The canonical v2 envelope (concurrency 128 / 8000 requests, cold TLS1.3-mTLS) is
pinned by `run_slo_job.sh`; it is the same envelope as the local lane and the GKE
run, which is what makes the three comparable.

## Teardown

```sh
eksctl delete cluster -f deploy/eks/mcp-re-slo-cluster.yaml --disable-nodegroup-eviction
aws ecr delete-repository --region eu-north-1 --repository-name mcp-re-slo-bench --force
```

Then **verify**, rather than assume, that nothing billable survived — a failed
CloudFormation delete leaves instances running:

```sh
aws ec2 describe-instances --region eu-north-1 \
  --filters Name=instance-state-name,Values=running,pending \
  --query 'Reservations[].Instances[].[InstanceId,InstanceType]' --output text
aws eks list-clusters --region eu-north-1
aws cloudformation describe-stacks --region eu-north-1 \
  --query 'Stacks[?starts_with(StackName,`eksctl-mcp-re-slo`)].[StackName,StackStatus]' --output text
aws ec2 describe-nat-gateways --region eu-north-1 \
  --filter Name=state,Values=available --query 'NatGateways[].NatGatewayId' --output text
aws ec2 describe-volumes --region eu-north-1 \
  --filters Name=status,Values=available --query 'Volumes[].VolumeId' --output text
aws elbv2 describe-load-balancers --region eu-north-1 \
  --query 'LoadBalancers[].LoadBalancerName' --output text
```

All six must come back empty. The KMS CMK is handled separately by
`work/test-aws-cloud.sh` (7-day scheduled deletion is the KMS minimum window); it is
the only thing intentionally left behind, at ~`$1`/month prorated.
