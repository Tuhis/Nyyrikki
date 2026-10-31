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

{{/* "true" when any target is an SSH target (docs/07 §5.5). */}}
{{- define "nyyrikki.hasSSH" -}}
{{- $ssh := false -}}
{{- range .Values.targets }}{{ if .ssh }}{{ $ssh = true }}{{ end }}{{ end -}}
{{- $ssh -}}
{{- end -}}

{{/* "true" while the deprecated R10 Secret secrets.sshUserCA is set (docs/08 D14). */}}
{{- define "nyyrikki.sshCompat" -}}
{{- if .Values.secrets.sshUserCA.name }}true{{ end -}}
{{- end -}}

{{/* "true" when the hook Job makes the CA Secret (docs/08 D16): ssh.generateCA, by default true with an SSH target unless secrets.sshUserCA is set. */}}
{{- define "nyyrikki.generateCA" -}}
{{- if not (or (kindIs "invalid" .Values.ssh.generateCA) (kindIs "bool" .Values.ssh.generateCA)) -}}
{{- /* A quoted value would otherwise fall back to the default and render the hook's create grant (round 1 of #42). */ -}}
{{- fail "ssh.generateCA must be true, false or empty, not a string" -}}
{{- end -}}
{{- $gen := and (eq (include "nyyrikki.hasSSH" .) "true") (ne (include "nyyrikki.sshCompat" .) "true") -}}
{{- if kindIs "bool" .Values.ssh.generateCA -}}
{{- if and .Values.ssh.generateCA (eq (include "nyyrikki.sshCompat" .) "true") -}}
{{- fail "ssh.generateCA can't be true while secrets.sshUserCA is set: migrate first, as NOTES.txt and docs/08 D14 say" -}}
{{- end -}}
{{- $gen = and .Values.ssh.generateCA (eq (include "nyyrikki.hasSSH" .) "true") -}}
{{- else if and $gen .Values.ssh.userCAPublicKeys -}}
{{- /* Every R10 release lists its CA key here, and may have relied on secrets.sshUserCA's old default name: making a fresh CA would switch it to one no host trusts. Ask instead of guessing. */ -}}
{{- fail "ssh.userCAPublicKeys is set but secrets.sshUserCA is not. If this release was installed before docs/08 (R10), set secrets.sshUserCA.name to its old default, nyyrikki-ssh-user-ca, to keep the CA your hosts trust, then migrate as NOTES.txt and docs/08 D14 say. Otherwise set ssh.generateCA explicitly" -}}
{{- end -}}
{{- if $gen }}true{{ end -}}
{{- end -}}

{{/* "true" when the rotation CronJobs render (docs/08 D16): ssh.caJobs, by default the value of generateCA; only with an SSH target. */}}
{{- define "nyyrikki.caJobs" -}}
{{- if not (or (kindIs "invalid" .Values.ssh.caJobs) (kindIs "bool" .Values.ssh.caJobs)) -}}
{{- fail "ssh.caJobs must be true, false or empty, not a string" -}}
{{- end -}}
{{- $jobs := eq (include "nyyrikki.generateCA" .) "true" -}}
{{- if kindIs "bool" .Values.ssh.caJobs -}}
{{- $jobs = and .Values.ssh.caJobs (eq (include "nyyrikki.hasSSH" .) "true") -}}
{{- end -}}
{{- if $jobs }}true{{ end -}}
{{- end -}}

{{/* The pod security context every Nyyrikki pod uses. */}}
{{- define "nyyrikki.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
fsGroup: 65532
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{/* The container security context every Nyyrikki container uses. */}}
{{- define "nyyrikki.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: [ALL]
{{- end -}}
