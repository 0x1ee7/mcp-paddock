{{- define "paddock.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "paddock.labels" -}}
app.kubernetes.io/part-of: mcp-paddock
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "paddock.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{/* Pod-level settings shared by every workload. */}}
{{- define "paddock.podSpec" -}}
automountServiceAccountToken: false
securityContext:
  {{- toYaml .Values.podSecurityContext | nindent 2 }}
{{- with .Values.runtimeClassName }}
runtimeClassName: {{ . }}
{{- end }}
{{- end -}}

{{- define "paddock.otelEnv" -}}
{{- with .Values.otel.endpoint }}
- name: OTEL_EXPORTER_OTLP_ENDPOINT
  value: {{ . | quote }}
{{- end }}
{{- end -}}

{{/* Egress every workload needs: DNS, and telemetry when configured. */}}
{{- define "paddock.baseEgress" -}}
- to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
      podSelector:
        matchLabels:
          k8s-app: kube-dns
  ports:
    - { port: 53, protocol: UDP }
    - { port: 53, protocol: TCP }
{{- if .Values.otel.endpoint }}
- to:
    - namespaceSelector:
        matchLabels:
          {{- toYaml .Values.networkPolicy.otelNamespaceSelector | nindent 10 }}
  ports:
    - port: {{ .Values.networkPolicy.otelPort }}
{{- end }}
{{- end -}}
