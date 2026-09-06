{{- define "asv.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "asv.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "asv.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "asv.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "asv.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: agent-shutdown-verification
{{- end }}

{{- define "asv.selectorLabels" -}}
app.kubernetes.io/name: {{ include "asv.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: controller
{{- end }}

{{- define "asv.controllerServiceAccountName" -}}
{{- default (printf "%s-controller" (include "asv.fullname" .)) .Values.serviceAccount.controller.name }}
{{- end }}

{{- define "asv.probeServiceAccountName" -}}
{{- default (printf "%s-probe" (include "asv.fullname" .)) .Values.serviceAccount.probe.name }}
{{- end }}

{{- define "asv.pvcName" -}}
{{- default (include "asv.fullname" .) .Values.persistence.existingClaim }}
{{- end }}

