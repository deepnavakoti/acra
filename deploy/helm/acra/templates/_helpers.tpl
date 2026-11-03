{{- define "acra.name" -}}acra{{- end -}}

{{- define "acra.fullname" -}}
{{- if contains "acra" .Release.Name -}}{{ .Release.Name | trunc 40 | trimSuffix "-" }}{{- else -}}{{ printf "%s-acra" .Release.Name | trunc 40 | trimSuffix "-" }}{{- end -}}
{{- end -}}

{{- define "acra.labels" -}}
app.kubernetes.io/name: acra
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "acra.selector" -}}
app.kubernetes.io/name: acra
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "acra.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}

{{- define "acra.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}{{ default (include "acra.fullname" .) .Values.serviceAccount.name }}{{- else -}}{{ default "default" .Values.serviceAccount.name }}{{- end -}}
{{- end -}}

{{- define "acra.secretName" -}}
{{- default (printf "%s-auth" (include "acra.fullname" .)) .Values.auth.existingSecret -}}
{{- end -}}

{{/* env for token-based auth, shared by apiserver and gate */}}
{{- define "acra.authEnv" -}}
- name: ACRA_API_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ include "acra.secretName" . }}
      key: api-token
      {{- if .Values.auth.existingSecret }}
      optional: true
      {{- end }}
- name: ACRA_API_TOKENS
  valueFrom:
    secretKeyRef:
      name: {{ include "acra.secretName" . }}
      key: api-tokens
      optional: true
{{- end -}}

{{- define "acra.podSpecCommon" -}}
serviceAccountName: {{ include "acra.serviceAccountName" . }}
{{- with .Values.imagePullSecrets }}
imagePullSecrets: {{ toYaml . | nindent 2 }}
{{- end }}
securityContext: {{ toYaml .Values.podSecurityContext | nindent 2 }}
{{- end -}}
