{{- define "postern.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "postern.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "postern.selectorLabels" -}}
app.kubernetes.io/name: {{ include "postern.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "postern.labels" -}}
{{ include "postern.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
{{- end -}}

{{- define "postern.secretName" -}}
{{- default (printf "%s-key" (include "postern.fullname" .)) .Values.secretKey.existingSecret -}}
{{- end -}}

{{- define "postern.tlsSecretName" -}}
{{- default (printf "%s-tls" (include "postern.fullname" .)) .Values.ingress.tls.secretName -}}
{{- end -}}

{{- define "postern.issuerName" -}}
{{- printf "%s-acme" (include "postern.fullname" .) -}}
{{- end -}}
