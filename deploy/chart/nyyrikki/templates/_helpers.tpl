{{- define "nyyrikki.name" -}}{{ .Release.Name }}-nyyrikki{{- end -}}
{{- define "nyyrikki.labels" -}}
app.kubernetes.io/name: nyyrikki
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}
{{- define "nyyrikki.selector" -}}
app.kubernetes.io/name: nyyrikki
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "nyyrikki.image" -}}
{{- if .Values.image.digest -}}{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}{{- end -}}
{{- end -}}
{{- /* "true" once if any target is in-cluster, whatever their number. */ -}}
{{- define "nyyrikki.inCluster" -}}
{{- $in := false -}}
{{- range .Values.targets }}{{ if .inCluster }}{{ $in = true }}{{ end }}{{ end -}}
{{- if $in }}true{{ end -}}
{{- end -}}
