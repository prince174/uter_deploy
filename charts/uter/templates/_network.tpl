{{- define "uter.egressPeer" -}}
{{- if eq .mode "pod" }}
namespaceSelector:
  matchLabels:
    kubernetes.io/metadata.name: {{ .namespace | quote }}
podSelector:
  matchLabels:
    {{ .podLabelKey | quote }}: {{ .podLabelValue | quote }}
{{- else }}
ipBlock:
  cidr: {{ printf "%s/32" .ipv4 | quote }}
{{- end }}
{{- end }}
