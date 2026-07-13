<!-- SPDX-License-Identifier: Apache-2.0 -->

# GKE fleet validation + ADR-051 §7 SLO baseline — runbook

A **rerunnable** procedure to stand the MCP-RE HTTP-profile fleet up on a real GKE
cluster, re-prove the live obligations, and measure the ADR-MCPRE-051 §7 SLO
baseline on declared cloud hardware. Use it to **re-baseline on a new major
release** or **before/after a performance-optimisation pass**.

Everything here is **torn down after each run** (see [Teardown](#teardown)); the
repo keeps the *setup*, not live cloud resources. First run took ~40 min end to
end; a rerun with images cached is ~15 min.

> **Canonical envelope (v2, RFC 9421) — ONE runbook, the involved config.** The
> load harness and its baseline were rebuilt on the RFC 9421 + RFC 9530 serving
> carrier (the object/JCS carrier and its harness were deleted in the ADR-MCPRE-050
> cutover). The single canonical measurement envelope is **concurrency 128 / 8000
> requests, cold TLS1.3-mTLS** — the SAME for the local baseline AND this GKE run.
> The earlier GKE run used the lighter v1 defaults (concurrency 64 / 2000), so it
> was never comparable to the local baseline; `tools/slo/run_slo_job.sh` now pins
> 128/8000 explicitly. **Run the local baseline first** (`cargo test --release -p
> mcp-re-proxy --features async_serve --test tls_load_harness_bench
> tls_load_harness_bench -- --ignored`, then `scripts/adr051_slo_gate.py`) and
> confirm it is green before spending on GKE. The GKE production floors in
> `adr-051-slo-targets.json` are **DECLARED under this v2 envelope** (re-measured
> 2026-07-13, v0.12); rerun this runbook to refresh them on a new major release.

- Project: `project-b19bbb5e-9be8-4fcb-a2f` (`MCP-S tests`, isolated — **never** the
  security-apps cluster), zone `us-central1-a`.
- Artifacts referenced: `deploy/docker/Dockerfile{,.inner,.bench}`,
  `deploy/cloudbuild/*.yaml`, `deploy/helm/mcp-re-proxy`, `deploy/k8s/inner-fastmcp.yaml`,
  `tools/slo/run_slo_job.sh`, `docs/security/mcp_re_gke_client.py`,
  `docs/bench/adr-051-slo-targets.json`, `scripts/slo_gate.py`.

## 0. One-time project setup (idempotent)

```sh
gcloud config set project project-b19bbb5e-9be8-4fcb-a2f
# APIs
gcloud services enable container.googleapis.com artifactregistry.googleapis.com cloudbuild.googleapis.com
# Cloud Build uses the Compute default SA; grant it build+push+log rights (2024+ default-SA change)
CBSA="$(gcloud projects describe project-b19bbb5e-9be8-4fcb-a2f --format='value(projectNumber)')-compute@developer.gserviceaccount.com"
for r in roles/cloudbuild.builds.builder roles/storage.objectViewer roles/artifactregistry.writer roles/logging.logWriter; do
  gcloud projects add-iam-policy-binding project-b19bbb5e-9be8-4fcb-a2f --member="serviceAccount:$CBSA" --role="$r" --condition=None
done
# Artifact Registry repo + docker auth
gcloud artifacts repositories create mcp-re --repository-format=docker --location=us-central1 || true
gcloud auth configure-docker us-central1-docker.pkg.dev --quiet
# kubectl needs the GKE auth plugin (already at ~/google-cloud-sdk/bin here)
export USE_GKE_GCLOUD_AUTH_PLUGIN=True
```

## 1. Build the amd64 images (native, on Cloud Build — no local QEMU)

```sh
gcloud builds submit --config deploy/cloudbuild/mcp-re-images.yaml .   # proxy + FastMCP inner
gcloud builds submit --config deploy/cloudbuild/slo-bench.yaml .       # SLO baseline runner
```

`.gcloudignore` keeps the upload to ~24 MiB (excludes `target/`, ~49 GB). The proxy
image is a from-source release build (~2 min on `E2_HIGHCPU_8`); the bench image
warms `target/` so the Job runs with no recompile.

## 2. Cluster + shared Redis

```sh
gcloud container clusters create mcp-re-fleet --zone us-central1-a \
  --num-nodes 2 --machine-type e2-standard-2 --disk-size 30 --no-enable-basic-auth
gcloud container clusters get-credentials mcp-re-fleet --zone us-central1-a
kubectl create namespace mcp-re
# Redis (shared replay + trust-epoch tier) — see gke-multi-replica-validation.sh for the manifest
kubectl -n mcp-re apply -f - <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata: { name: mcp-re-redis }
spec: { replicas: 1, selector: { matchLabels: { app: mcp-re-redis } },
  template: { metadata: { labels: { app: mcp-re-redis } },
    spec: { containers: [ { name: redis, image: redis:7, args: ["--appendonly","yes"], ports: [ { containerPort: 6379 } ] } ] } } }
---
apiVersion: v1
kind: Service
metadata: { name: mcp-re-redis }
spec: { selector: { app: mcp-re-redis }, ports: [ { port: 6379, targetPort: 6379 } ] }
YAML
```

## 3. Material + deploy the fleet (strict + exact binding + FastMCP inner)

```sh
AR=us-central1-docker.pkg.dev/project-b19bbb5e-9be8-4fcb-a2f/mcp-re
# Fresh material bundle, incl. the SHORT-LIVED client cert strict requires (< 3600s).
rm -rf /tmp/gke_mat && mkdir -p /tmp/gke_mat
cargo run -q -p mcp-re-demo --example emit_mtls_fixtures -- /tmp/gke_mat
kubectl -n mcp-re create secret generic mcp-re-proxy-material \
  --from-file=tls.crt=/tmp/gke_mat/server_cert.pem --from-file=tls.key=/tmp/gke_mat/server_key.pem \
  --from-file=client-ca.pem=/tmp/gke_mat/client_ca.pem --from-file=trust.json=/tmp/gke_mat/trust.json \
  --from-file=signing-seed=/tmp/gke_mat/signing_seed --dry-run=client -o yaml | kubectl apply -n mcp-re -f -
# FastMCP inner (AR image)
sed "s#image: mcp-re-inner-fastmcp:0.12.0#image: $AR/mcp-re-inner-fastmcp:0.12.0#" \
  deploy/k8s/inner-fastmcp.yaml | kubectl apply -n mcp-re -f -
# Proxy fleet (RFC 9421 serving path, ADR-MCPRE-050). The identity tuple
# {audience, targetUri, trustDomain} comes from the chart defaults, which MATCH what
# emit_mtls_fixtures + mcp_re_gke_client.py sign (audience did:example:server-1,
# target-uri https://proxy.internal:8600/mcp, trust-domain example.com). Inner path
# has NO trailing slash (FastMCP in-cluster 307-redirects /mcp/ -> /mcp).
# Transport binding is ALWAYS `exact` — there is no `none` option (a decoupled
# channel<->signer posture is refused). This requires the SLO load client to present
# a client cert whose URI SAN is the RESOLVED actor_id (role:trust_domain:signer:
# keyid), NOT the bare signer — the same leaf shape emit_mtls_fixtures /
# mcp_re_gke_client.py mint for the multi-replica proof. Validate locally end-to-end
# (accepted + replay) before this deploy via tools' deploy-config check.
helm upgrade --install mcp-re-proxy deploy/helm/mcp-re-proxy -n mcp-re \
  --set image.repository="$AR/mcp-re-proxy" --set-string image.tag=0.12.0 \
  --set replicaCount=3 --set fleet=true \
  --set 'inner.httpUrls={http://mcp-re-inner-fastmcp:8620/mcp}' \
  --set replay.redisUrl=redis://mcp-re-redis:6379 \
  --set revocation.trustEpochRedisUrl=redis://mcp-re-redis:6379 \
  --set drainPreStopSeconds=6 --wait --timeout 4m
```

The four-proof harness reads the gke-client identity from env — set them to the
fixture material + the chart's identity tuple (note `MCP_RE_TARGET_URI` /
`MCP_RE_TRUST_DOMAIN`, new for the RFC 9421 audience tuple):

```sh
export MCP_RE_SERVER_NAME=proxy.internal MCP_RE_AUDIENCE=did:example:server-1 \
  MCP_RE_TARGET_URI=https://proxy.internal:8600/mcp MCP_RE_TRUST_DOMAIN=example.com \
  MCP_RE_SIGNER_ID=did:example:agent-1 MCP_RE_KEY_ID=key-1 \
  MCP_RE_SIGNING_KEY_SEED=@/tmp/gke_mat/client_signing_seed \
  MCP_RE_SERVER_SIGNER=did:example:server-1 MCP_RE_SERVER_KEY_ID=server-key-1 \
  MCP_RE_SERVER_PUBKEY=@/tmp/gke_mat/server_pubkey \
  MCP_RE_TRUST_EPOCH=epoch-1 \
  MCP_RE_TLS_CERT=/tmp/gke_mat/client_cert_short.pem MCP_RE_TLS_KEY=/tmp/gke_mat/client_key_short.pem \
  MCP_RE_SERVER_CA=/tmp/gke_mat/server_ca.pem
```

Live proofs (cross-replica replay, LB zero-drop): drive `docs/security/mcp_re_gke_client.py`
with `/tmp/gke_mat/client_cert_short.pem` + `client_key_short.pem` (see
`gke-multi-replica-validation.sh` for the four-proof harness; note it also drives
Proof 2 trust-epoch — see the [trust-epoch note](#trust-epoch-caveat)).

## 4. The SLO baseline (§7 declared-hardware run)

> **The SLO Job is self-contained.** `tools/slo/run_slo_job.sh` runs
> `tls_load_harness_bench`, which spawns its **own** `mcp-re-proxy` + echo backend
> *inside the Job pod* and drives them with in-pod clients — it does **not** use the
> deployed fleet Service. So the fleet only needs to be up for the four live proofs
> (§3), **not** for the SLO measurement. That is what lets the baseline fit inside
> the 16-vCPU free-trial quota (below).

**DEFAULT (fits the free-trial 16-vCPU cap — no billing upgrade needed).** The two
class pools are 8 vCPU each = 16 = the quota exactly, so run the SLO phase with the
**fleet torn down** and both classes **concurrently**:

```sh
# (proofs already done in §3) — delete the fleet's default-pool to free its 4 vCPU:
gcloud container clusters resize mcp-re-fleet --node-pool default-pool --num-nodes 0 \
  --zone us-central1-a --quiet
# Both 8-vCPU class pools now fit (8 + 8 = 16 <= 16); create them and run in parallel:
gcloud container node-pools create pool-e2s8 --cluster mcp-re-fleet --zone us-central1-a \
  --machine-type e2-standard-8 --num-nodes 1 --disk-size 40
gcloud container node-pools create pool-c3s8 --cluster mcp-re-fleet --zone us-central1-a \
  --machine-type c3-standard-8 --num-nodes 1 --disk-size 40
tools/slo/run_slo_job.sh pool-e2s8 e2-standard-8 1 e2_1core.json
tools/slo/run_slo_job.sh pool-e2s8 e2-standard-8 8 e2_8core.json
tools/slo/run_slo_job.sh pool-c3s8 c3-standard-8 1 c3_1core.json
tools/slo/run_slo_job.sh pool-c3s8 c3-standard-8 8 c3_8core.json
# Gate: capacity on the N-core report + 1->N scaling (per class)
python3 scripts/slo_gate.py --report e2_8core.json --baseline e2_1core.json --scaled e2_8core.json \
  --targets docs/bench/adr-051-slo-targets.json
```

*Serial fallback (fleet stays up):* keep the default-pool, run ONE 8-vCPU pool at a
time (4 + 8 = 12 <= 16), delete it before creating the next. A few extra minutes.

To declare/refresh the targets: pick the **weaker** measured class as the floor,
set `capacity_targets`/`scaling_targets`/`hardware_class`/`measured_on` +
the `measurements` block in `docs/bench/adr-051-slo-targets.json`, `status:declared`.
Measure under the **v2 canonical envelope** (RFC 9421, 128/8000 — `run_slo_job.sh`
pins it). The 2026-07-10 numbers there are the SUPERSEDED object/JCS run.

> **Quota — you are on a FREE-TRIAL account, so 16 is locked.** Raising
> `CPUS_ALL_REGIONS` to 32 (to keep the fleet up AND run both classes at once)
> requires **upgrading the project to a paid billing account** ("Upgrade my account"
> in the console) — an owner/billing action; the console greys out "Edit quota" until
> then. **You do not need it:** the DEFAULT sequence above fits inside 16 by dropping
> the fleet during the SLO phase. See [the quota section](#the-cpus_all_regions-quota-why-16-blocked-the-second-8-vcpu-pool).

## Teardown

```sh
kubectl -n mcp-re delete svc mcp-re-proxy-lb --ignore-not-found   # release the L4 LB forwarding rule cleanly
gcloud container clusters delete mcp-re-fleet --zone us-central1-a --quiet   # nodes + LB + workloads
# Optional (zero AR storage; rebuild via step 1 on rerun):
for i in mcp-re-proxy mcp-re-inner-fastmcp mcp-re-slo-bench; do
  gcloud artifacts docker images delete "us-central1-docker.pkg.dev/project-b19bbb5e-9be8-4fcb-a2f/mcp-re/$i:0.12.0" --delete-tags --quiet || true
done
```

**Not deleted / not billable idle:** the KMS keys in `mcps-test-ring` (Cloud KMS
does not allow keyring/key deletion — `work/test-gcp-cloud.sh` reuses them; a
software Ed25519 key version is a few cents/month), the Compute-SA IAM grant, and
the enabled APIs. Leave them — they cost ~nothing and save setup on rerun.

## The CPUS_ALL_REGIONS quota (why 16 blocked the second 8-vCPU pool)

`CPUS_ALL_REGIONS` is a **global** Compute Engine quota: the maximum number of
vCPUs you may run **summed across every region at once**. On this project it is
**16**. It is *separate* from the **per-region** `CPUS` quota (us-central1 = 200,
barely touched) — the global cap is the binding one here.

At the moment of failure we had: default-pool `2 × e2-standard-2` = 4 vCPU, plus
`c3-standard-8` = 8 vCPU → 12. Adding `e2-standard-8` (8) → 20 > 16, so the second
8-vCPU pool's node could not schedule (`GCE_QUOTA_EXCEEDED`). That is why the two
classes were baselined **serially** (swap the pool between them; the fleet's
4-vCPU default-pool fits alongside one 8-vCPU pool: 12 ≤ 16).

**On this project the 16 is LOCKED — it is a free-trial account.** The console
greys out "Edit quota" and shows *"Free trial accounts have limited quota during
their trial period; upgrade to a paid account to increase your quota."* Raising
`CPUS_ALL_REGIONS` to 32 therefore requires an **owner/billing action** — "Upgrade
my account" (top of any console page) — not a permissions or CLI fix. Once upgraded,
32 fits both 8-vCPU class pools + the 4-vCPU fleet (20 ≤ 32) so all three run at
once; the ceiling is only a cap (you are billed for VMs actually run) and the repo
always tears down, so the bump is low-risk. View the current value with:

```sh
gcloud compute project-info describe --project=project-b19bbb5e-9be8-4fcb-a2f \
  --flatten="quotas[]" --format="table(quotas.metric,quotas.limit,quotas.usage)" | grep -i CPUS_ALL_REGIONS
```

**You do NOT need to upgrade.** Because the SLO Job is self-contained (spawns its
own proxy in-pod, does not use the fleet), the DEFAULT sequence in §4 runs the SLO
phase with the **fleet torn down**: two 8-vCPU class pools = 16 = the cap exactly,
both classes in parallel, zero billing change. Upgrading to a paid account + raising
to 32 is purely a convenience (keep the live-proof fleet up *while* measuring SLO).
