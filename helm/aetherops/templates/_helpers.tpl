{{- define "aetherops.namespace" -}}
{{- .Values.namespace | default "ebpf-system" -}}
{{- end -}}

{{- define "aetherops.image" -}}
{{- $registry := .registry | default "" -}}
{{- $repository := .repository -}}
{{- $tag := .tag | default "latest" -}}
{{- if $registry -}}
{{- printf "%s/%s:%s" $registry $repository $tag -}}
{{- else -}}
{{- printf "%s:%s" $repository $tag -}}
{{- end -}}
{{- end -}}

{{- define "aetherops.tracer.name" -}}
ebpf-tracer
{{- end -}}

{{- define "aetherops.tracer.labels" -}}
app: {{ include "aetherops.tracer.name" . }}
{{- end -}}

{{- define "aetherops.core.name" -}}
aetherops-core
{{- end -}}

{{- define "aetherops.core.labels" -}}
app: {{ include "aetherops.core.name" . }}
{{- end -}}
