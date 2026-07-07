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
{{- end -}}
