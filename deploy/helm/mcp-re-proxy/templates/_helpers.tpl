{{/* SPDX-License-Identifier: Apache-2.0 */}}
{{- define "mcp-re-proxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "mcp-re-proxy.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "mcp-re-proxy.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "mcp-re-proxy.labels" -}}
app.kubernetes.io/name: {{ include "mcp-re-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "mcp-re-proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "mcp-re-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
The ServiceAccount name the pod runs as. When serviceAccount.create is true and
no explicit name is given, it is the fullname; otherwise the given name (or
"default" when creation is disabled and no name is set).
*/}}
{{- define "mcp-re-proxy.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "mcp-re-proxy.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Fail-closed guardrail: --fleet must not run on a node-local replay cache. The
shared tier is expressed via replay.redisUrl + a redis-wait-quorum / linearizable
durabilityTier; refuse to render an unsafe fleet chart.
*/}}
{{- define "mcp-re-proxy.validate" -}}
{{- if not (gt (len .Values.inner.httpUrls) 0) -}}
{{- fail "inner plane required (ADR-MCPRE-051 §3): set inner.httpUrls to one or more Streamable-HTTP backends. MCP-RE is HTTP-profile only — a stdio-only server is fronted by an EXTERNAL plain-MCP adapter (e.g. FastMCP) that exposes HTTP. The proxy launches no subprocess and fails closed with no --inner-http-url." -}}
{{- end -}}
{{- if .Values.fleet -}}
{{- if not .Values.replay.redisUrl -}}
{{- fail "fleet=true requires replay.redisUrl (a shared replay store); a node-local cache cannot maintain cross-verifier replay state" -}}
{{- end -}}
{{- if not (or (hasPrefix "redis-wait-quorum:" .Values.replay.durabilityTier) (eq .Values.replay.durabilityTier "linearizable")) -}}
{{- fail "fleet=true requires replay.durabilityTier of redis-wait-quorum:<q>:<ms> or linearizable (the strict-production minimum)" -}}
{{- end -}}
{{- end -}}
{{- if eq .Values.keySource "gcpKms" -}}
{{- if not .Values.gcpKms.keyVersion -}}
{{- fail "keySource=gcpKms requires gcpKms.keyVersion (the Cloud KMS key-version resource path)" -}}
{{- end -}}
{{- else if not (eq .Values.keySource "fileSeed") -}}
{{- fail "keySource must be fileSeed or gcpKms" -}}
{{- end -}}
{{/*
The replay tier and the trust-epoch counter carry admitted nonces and the epoch that
drives credential minting. Under fleet=true, refuse a plaintext endpoint unless the
operator has deliberately set replay.allowPlaintextRedis.
*/}}
{{- if and .Values.fleet (not .Values.replay.allowPlaintextRedis) -}}
{{- if hasPrefix "redis://" .Values.replay.redisUrl -}}
{{- fail "replay.redisUrl is plaintext redis:// — this hop carries the admitted replay nonces, and an unauthenticated peer can DEL/FLUSHDB them to re-open the replay window fleet-wide. Use rediss:// with credentials (rediss://:<password>@host:6379), or set replay.allowPlaintextRedis=true to accept the risk deliberately." -}}
{{- end -}}
{{- if hasPrefix "redis://" .Values.revocation.trustEpochRedisUrl -}}
{{- fail "revocation.trustEpochRedisUrl is plaintext redis:// — an attacker who can write this key forces every replica to re-mint delegated credentials under an epoch verifiers reject (a fleet-wide response-signing outage). Use rediss:// with credentials, or set replay.allowPlaintextRedis=true to accept the risk deliberately." -}}
{{- end -}}
{{- end -}}
{{/*
The audience tuple and trust epoch are the identity of ONE dispatch boundary (RE-15).
A shipped placeholder that renders into working flags would be shared by every install
that did not override it, so refuse the placeholders outright.
*/}}
{{- if not .Values.identity.allowExampleFixtures -}}
{{- if or (hasPrefix "did:example:" .Values.identity.audience) (hasPrefix "did:example:" .Values.identity.serverSigner) -}}
{{- fail "identity.audience / identity.serverSigner still hold the chart's did:example: placeholder. The audience tuple is what binds a signed request to THIS dispatch boundary; two installs sharing it accept each other's requests under a shared trust anchor. Set them to this deployment's own identifiers, or set identity.allowExampleFixtures=true if this is a fenced validation run driven by emit_mtls_fixtures." -}}
{{- end -}}
{{- if eq .Values.identity.trustDomain "example.com" -}}
{{- fail "identity.trustDomain still holds the chart's example.com placeholder; set this deployment's own trust domain, or identity.allowExampleFixtures=true for a fenced validation run" -}}
{{- end -}}
{{- if eq .Values.identity.delegatedTrustEpoch "epoch-1" -}}
{{- fail "identity.delegatedTrustEpoch still holds the chart's epoch-1 placeholder. The epoch is the fleet-wide kill switch for delegated keys — sharing it across installs means advancing it on one advances it on all. Set a value owned by this deployment." -}}
{{- end -}}
{{- end -}}
{{- if not .Values.identity.targetUri -}}
{{- fail "identity.targetUri is required: the signed request's audience block must match it AND the request @target-uri" -}}
{{- end -}}
{{/*
transportBinding: only "" (omit the flag, proxy default `exact`) or "exact" produce a
pod that starts. `none` is rejected at argument parse; lb-assertion/attested-ingress
are refused at boot on the RFC 9421 carrier. Fail at render rather than CrashLoop.
*/}}
{{- if not (or (eq .Values.transportBinding "") (eq .Values.transportBinding "exact")) -}}
{{- fail (printf "transportBinding=%q cannot start on the RFC 9421 serving path. Use \"\" (omit the flag; the proxy defaults to exact) or \"exact\". `none` is rejected at argument parse; `lb-assertion` and `attested-ingress` parse but are refused at boot (owner-signed ingress rebinding pending)." .Values.transportBinding) -}}
{{- end -}}
{{- end -}}
