{{- define "malanalyzer.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "malanalyzer.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 48 | trimSuffix "-" -}}
{{- else -}}
{{- if contains (include "malanalyzer.name" .) .Release.Name -}}
{{- .Release.Name | trunc 48 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "malanalyzer.name" .) | trunc 48 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- define "malanalyzer.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | quote }}
app.kubernetes.io/name: {{ include "malanalyzer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "malanalyzer.selectorLabels" -}}
app.kubernetes.io/name: {{ include "malanalyzer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: server
{{- end -}}
{{- define "malanalyzer.pvc" -}}
{{- default (printf "%s-data" (include "malanalyzer.fullname" .)) .Values.persistence.existingClaim -}}
{{- end -}}
{{- define "malanalyzer.serviceAccount" -}}
{{- default (printf "%s-worker" (include "malanalyzer.fullname" .)) .Values.serviceAccount.name -}}
{{- end -}}
{{- define "malanalyzer.analysisServiceAccount" -}}
{{- default (printf "%s-analysis" (include "malanalyzer.fullname" .)) .Values.analysisServiceAccount.name -}}
{{- end -}}
{{- define "malanalyzer.analysisImage" -}}
{{- printf "%s:%s" (default (printf "%s-tools" .Values.image.repository) .Values.analysis.image.repository) (default .Values.image.tag .Values.analysis.image.tag) -}}
{{- end -}}
{{- define "malanalyzer.analysisPullSecrets" -}}
{{- $names := .Values.analysis.imagePullSecrets -}}
{{- if not $names -}}
{{- $names = list -}}
{{- range .Values.imagePullSecrets -}}
{{- $names = append $names .name -}}
{{- end -}}
{{- end -}}
{{- toJson $names -}}
{{- end -}}
