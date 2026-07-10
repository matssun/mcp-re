<!-- SPDX-License-Identifier: Apache-2.0 -->

# GKE fleet validation + ADR-051 §7 SLO baseline — runbook

A **rerunnable** procedure to stand the MCP-RE HTTP-profile fleet up on a real GKE
cluster, re-prove the live obligations, and measure the ADR-MCPRE-051 §7 SLO
baseline on declared cloud hardware. Use it to **re-baseline on a new major
release** or **before/after a performance-optimisation pass**.

Everything here is **torn down after each run** (see [Teardown](#teardown)); the
repo keeps the *setup*, not live cloud resources. First run took ~40 min end to
end; a rerun with images cached is ~15 min.

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
sed "s#image: mcp-re-inner-fastmcp:0.11.0#image: $AR/mcp-re-inner-fastmcp:0.11.0#" \
  deploy/k8s/inner-fastmcp.yaml | kubectl apply -n mcp-re -f -
# Proxy fleet. audience is the canonical form the gke client signs; inner path has NO trailing slash
# (FastMCP in-cluster 307-redirects /mcp/ -> /mcp, which the proxy treats as inner-unavailable).
CANON='mcp-re-audience:v1:scheme=https;host=proxy.internal;port=8600;tenant=default;route=/mcp;realm=mcp-re'
helm upgrade --install mcp-re-proxy deploy/helm/mcp-re-proxy -n mcp-re \
  --set image.repository="$AR/mcp-re-proxy" --set-string image.tag=0.11.0 \
  --set replicaCount=3 --set strict=true --set fleet=true \
  --set 'inner.httpUrls={http://mcp-re-inner-fastmcp:8620/mcp}' \
  --set-string identity.audience="$CANON" --set-string transportBinding=exact \
  --set replay.redisUrl=redis://mcp-re-redis:6379 \
  --set revocation.trustEpochRedisUrl=redis://mcp-re-redis:6379 \
  --set drainPreStopSeconds=6 --wait --timeout 4m
```

Live proofs (cross-replica replay, LB zero-drop): drive `docs/security/mcp_re_gke_client.py`
with `/tmp/gke_mat/client_cert_short.pem` + `client_key_short.pem` (see
`gke-multi-replica-validation.sh` for the four-proof harness; note it also drives
Proof 2 trust-epoch — see the [trust-epoch note](#trust-epoch-caveat)).

## 4. The SLO baseline (§7 declared-hardware run)

For each machine class, run at 1 core and at N cores on a dedicated node pool:

```sh
gcloud container node-pools create pool-e2s8 --cluster mcp-re-fleet --zone us-central1-a \
  --machine-type e2-standard-8 --num-nodes 1 --disk-size 40
tools/slo/run_slo_job.sh pool-e2s8 e2-standard-8 1 e2_1core.json
tools/slo/run_slo_job.sh pool-e2s8 e2-standard-8 8 e2_8core.json
# Gate: capacity on the N-core report + 1->N scaling
python3 scripts/slo_gate.py --report e2_8core.json --baseline e2_1core.json --scaled e2_8core.json \
  --targets docs/bench/adr-051-slo-targets.json
```

To declare/refresh the targets: pick the **weaker** measured class as the floor,
set `capacity_targets`/`scaling_targets`/`hardware_class`/`measured_on` +
the `measurements` block in `docs/bench/adr-051-slo-targets.json`, `status:declared`.
The 2026-07-10 baseline (e2-standard-8 floor, c3-standard-8 reference) is recorded there.

> **Quota:** two 8-vCPU pools + the fleet exceed `CPUS_ALL_REGIONS` (16, see below).
> Run classes **serially** — delete one 8-vCPU pool before creating the next; the
> fleet (default-pool, 4 vCPU) stays up. Or raise the quota (see below).

## Teardown

```sh
kubectl -n mcp-re delete svc mcp-re-proxy-lb --ignore-not-found   # release the L4 LB forwarding rule cleanly
gcloud container clusters delete mcp-re-fleet --zone us-central1-a --quiet   # nodes + LB + workloads
# Optional (zero AR storage; rebuild via step 1 on rerun):
for i in mcp-re-proxy mcp-re-inner-fastmcp mcp-re-slo-bench; do
  gcloud artifacts docker images delete "us-central1-docker.pkg.dev/project-b19bbb5e-9be8-4fcb-a2f/mcp-re/$i:0.11.0" --delete-tags --quiet || true
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

**Can it be raised?** Yes — `gcloud compute regions describe` shows it, and you
request an increase in *IAM & Admin → Quotas* (filter "CPUs (all regions)"), or via
`gcloud`. Small bumps on an established billing account are often auto-approved in
minutes; larger ones take a review.

**Is raising it a good idea?** For this use, **raising it is fine and low-risk** —
it is only a *ceiling*, not a reservation, so you are billed for VMs you actually
run, not for the quota. A modest bump (e.g. to 32) would let both 8-vCPU pools run
concurrently and cut the baseline from serial to parallel. The reasons to be
cautious are the usual ones: (1) a higher ceiling means a runaway script or a
forgotten cluster can rack up **more** cost before hitting the wall — the low
default is a guardrail; (2) it does not change per-run cost at all. Given this repo
**always tears the cluster down** after a run, the guardrail value is small and a
bump to ~32 is reasonable if you want parallel multi-class baselines. Leave it at
16 if you are happy running classes serially (a few extra minutes, zero extra cost,
and the low ceiling keeps a stray VM from getting expensive).
