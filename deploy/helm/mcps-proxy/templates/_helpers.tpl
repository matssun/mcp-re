{{/* SPDX-License-Identifier: Apache-2.0 */}}
{{- define "mcps-proxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "mcps-proxy.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "mcps-proxy.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "mcps-proxy.labels" -}}
app.kubernetes.io/name: {{ include "mcps-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "mcps-proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "mcps-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Fail-closed guardrail: --fleet must not run on a node-local replay cache. The
shared tier is expressed via replay.redisUrl + a redis-wait-quorum / linearizable
durabilityTier; refuse to render an unsafe fleet chart.
*/}}
{{- define "mcps-proxy.validate" -}}
{{- if .Values.fleet -}}
{{- if not .Values.replay.redisUrl -}}
{{- fail "fleet=true requires replay.redisUrl (a shared replay store); a node-local cache cannot maintain cross-verifier replay state" -}}
{{- end -}}
{{- if not (or (hasPrefix "redis-wait-quorum:" .Values.replay.durabilityTier) (eq .Values.replay.durabilityTier "linearizable")) -}}
{{- fail "fleet=true requires replay.durabilityTier of redis-wait-quorum:<q>:<ms> or linearizable (the strict-production minimum)" -}}
{{- end -}}
{{- end -}}
{{- end -}}
