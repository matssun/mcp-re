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
True when the response-signing key is custodied by a cloud KMS rather than a mounted
seed. Both KMS modes share the same three consequences — no --signing-key-seed, the
seed must be absent from the material Secret, and the startup posture is "no signing
key material in the pod" — so they are asked once here rather than enumerated at
every use, which is how the awsKms path would otherwise have silently kept mounting
a seed the proxy never reads.
*/}}
{{- define "mcp-re-proxy.kmsCustody" -}}
{{- if or (eq .Values.keySource "gcpKms") (eq .Values.keySource "awsKms") -}}true{{- end -}}
{{- end -}}

{{/*
True when the TLS server private key is ALSO custodied by KMS, under either cloud.
The chart must then omit --tls-key: the proxy refuses an exported TLS key alongside
a delegated one.
*/}}
{{- define "mcp-re-proxy.delegatedTls" -}}
{{- if and (eq .Values.keySource "gcpKms") .Values.gcpKms.tlsKeyVersion -}}true{{- end -}}
{{- if and (eq .Values.keySource "awsKms") .Values.awsKms.tlsKeyId -}}true{{- end -}}
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
{{- else if eq .Values.keySource "awsKms" -}}
{{- if not .Values.awsKms.region -}}
{{- fail "keySource=awsKms requires awsKms.region" -}}
{{- end -}}
{{- if not .Values.awsKms.keyId -}}
{{- fail "keySource=awsKms requires awsKms.keyId (a key id, ARN or alias)" -}}
{{- end -}}
{{/*
The custody claim this chart exists to make is "no key material in the pod". Under
awsKms that holds only on the IRSA path: with useWebIdentity=false the deployment
must mount a long-lived IAM key pair, which is a non-expiring credential authorizing
KMS Sign for as long as the Secret exists — strictly weaker than the GKE
Workload-Identity posture the gcpKms path takes. Refuse to render it silently.
*/}}
{{- if not .Values.awsKms.useWebIdentity -}}
{{- if not .Values.awsKms.allowStaticCredentials -}}
{{- fail "awsKms.useWebIdentity=false means this pod authenticates to KMS with a LONG-LIVED IAM key pair from awsKms.credentialsSecretName. That credential does not expire and authorizes kms:Sign for as long as the Secret exists — weaker than the IRSA posture, and weaker than the gcpKms Workload-Identity path this chart's custody claim is written against. Prefer useWebIdentity=true with an eks.amazonaws.com/role-arn annotation on the ServiceAccount. To accept the static-credential posture deliberately, set awsKms.allowStaticCredentials=true." -}}
{{- end -}}
{{- if not .Values.awsKms.credentialsSecretName -}}
{{- fail "awsKms.useWebIdentity=false requires awsKms.credentialsSecretName (a Secret with aws-access-key-id / aws-secret-access-key)" -}}
{{- end -}}
{{- end -}}
{{/*
IRSA is delivered by an annotation on the pod's ServiceAccount; without it EKS
injects no AWS_ROLE_ARN and the proxy fails closed at startup. Catching it here
turns a CrashLoop into a render error naming the annotation.
*/}}
{{- if .Values.awsKms.useWebIdentity -}}
{{- if not (get .Values.serviceAccount.annotations "eks.amazonaws.com/role-arn") -}}
{{- fail "awsKms.useWebIdentity=true needs the pod's ServiceAccount annotated with eks.amazonaws.com/role-arn: <role>. That annotation is what makes EKS project the token and set AWS_ROLE_ARN / AWS_WEB_IDENTITY_TOKEN_FILE; without it the proxy has no credentials and refuses to start. Set serviceAccount.annotations." -}}
{{- end -}}
{{- end -}}
{{- else if not (eq .Values.keySource "fileSeed") -}}
{{- fail "keySource must be fileSeed, gcpKms or awsKms" -}}
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
{{/*
Admission ceilings (MCPRE-114). Two render-time refusals, because both bad inputs
would otherwise produce a chart that looks bounded and is not:

  * 0 — Helm treats it as falsy, so the `if` in deployment.yaml would omit the flag
    and the proxy would fall back to its own fail-safe per-core ceiling of 256 after
    the operator wrote a ceiling of zero: silently 256x the boundary they asked for.
    The CLI rejects `--max-in-flight 0` for the same reason.
  * both set — the CLI's precedence silently discards the fleet-wide total in favour
    of the per-core value; the rendered args would show one flag while values.yaml
    shows two intents.
*/}}
{{- range $key, $value := .Values.admission -}}
{{- $text := toString $value -}}
{{- if and (ne $text "") (not (regexMatch "^[1-9][0-9]*$" $text)) -}}
{{- fail (printf "admission.%s=%q must be a positive integer, or \"\" to omit the flag and take the proxy's own fail-safe per-core ceiling of 256. 0 is refused rather than read as unset: it looks like a tightening but would mean no ceiling at all." $key $text) -}}
{{- end -}}
{{- end -}}
{{- if and .Values.admission.maxInFlight .Values.admission.maxInFlightTotal -}}
{{- fail "set admission.maxInFlight OR admission.maxInFlightTotal, not both: the per-core value takes precedence and the fleet-wide total would be silently discarded. Use maxInFlightTotal to size against the fleet (divided evenly across cores) or maxInFlight to pin each core directly." -}}
{{- end -}}

{{/*
The DRAIN INVARIANT. The kubelet's terminationGracePeriodSeconds clock starts at pod
DELETION, not at SIGTERM, so the preStop delay is spent inside it:

  drainPreStopSeconds + proxyDrainGraceSeconds < drainGracePeriodSeconds

Violated, the pod is SIGKILLed while the proxy still believes it may drain, and an
admitted request dies with neither a signed response nor a signed rejection — the
opposite of the ADR-MCPRE-051 §6 zero-abandoned property. It cannot be checked at
the proxy: only the chart knows the kubelet's two numbers.
*/}}
{{- $pre := int .Values.drainPreStopSeconds -}}
{{- $proxyDrain := int .Values.proxyDrainGraceSeconds -}}
{{- $kubelet := int .Values.drainGracePeriodSeconds -}}
{{- if lt $proxyDrain 30 -}}
{{- fail (printf "proxyDrainGraceSeconds=%d is below the proxy's 30s request deadline: an admitted request cannot finish inside the drain window, so a rolling update abandons it" $proxyDrain) -}}
{{- end -}}
{{- if ge (add $pre $proxyDrain) $kubelet -}}
{{- fail (printf "drainPreStopSeconds(%d) + proxyDrainGraceSeconds(%d) >= drainGracePeriodSeconds(%d): the kubelet SIGKILLs at %ds while the proxy drains until %ds, so in-flight requests are killed mid-flight with no signed response and no rejection evidence. Raise drainGracePeriodSeconds or lower the other two." $pre $proxyDrain $kubelet $kubelet (add $pre $proxyDrain)) -}}
{{- end -}}

{{/*
The `live` and `push` revocation tiers state their window in terms of consulting the
trust store, so the store has to be re-readable. The proxy refuses the combination at
startup; catching it here names the value instead of CrashLooping the pods.
*/}}
{{- if and (or (eq .Values.revocation.tier "live") (hasPrefix "push:" .Values.revocation.tier)) (not .Values.revocation.trustReloadSeconds) -}}
{{- fail (printf "revocation.tier=%q requires revocation.trustReloadSeconds: both tiers advertise a revocation window measured in consulting the trust store, and with trust.json read once at startup a revoked request-signer key would keep verifying until every replica restarts" .Values.revocation.tier) -}}
{{- end -}}

{{/*
ADR-MCPS-035 audit sink and the #415 §10 verified-context carrier: both are
enumerations the proxy refuses at parse. Catching a typo here names the value rather
than CrashLooping the pods on an argument error.
*/}}
{{- if not (has .Values.auditSink (list "none" "stderr")) -}}
{{- fail (printf "auditSink=%q must be \"none\" or \"stderr\"" .Values.auditSink) -}}
{{- end -}}
{{- if not (has .Values.verifiedContextCarrier (list "disabled" "trusted")) -}}
{{- fail (printf "verifiedContextCarrier=%q must be \"disabled\" or \"trusted\"" .Values.verifiedContextCarrier) -}}
{{- end -}}

{{/*
The connection-age bound is the only thing that re-checks an established peer's
certificate against an expiry or a reloaded CRL. Zero disables it, and the proxy
refuses that at parse; a value above the cert-lifetime ceiling would let a
connection outlive the credential that authenticated it.
*/}}
{{- $connAge := int .Values.maxConnectionAgeSeconds -}}
{{- if le $connAge 0 -}}
{{- fail "maxConnectionAgeSeconds must be > 0: with no bound, a peer holding a revoked or expired client certificate keeps full authenticated access for as long as it keeps one connection open, and --client-crl reload reaches only new connections" -}}
{{- end -}}
{{- if gt $connAge (int .Values.maxClientCertLifetimeSeconds) -}}
{{- fail (printf "maxConnectionAgeSeconds(%d) exceeds maxClientCertLifetimeSeconds(%d): the connection would outlive the certificate that authenticated it" $connAge (int .Values.maxClientCertLifetimeSeconds)) -}}
{{- end -}}
{{- end -}}
