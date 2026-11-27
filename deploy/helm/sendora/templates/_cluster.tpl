{{/* Topology spread for a cluster component. (dict "ctx" . "component" "web" "cfg" .Values.cluster.web) */}}
{{- define "sendora.topologySpread" -}}
{{- if .cfg.topologySpread.enabled }}
topologySpreadConstraints:
  - maxSkew: {{ .cfg.topologySpread.maxSkew }}
    topologyKey: {{ .cfg.topologySpread.topologyKey }}
    whenUnsatisfiable: {{ .cfg.topologySpread.whenUnsatisfiable }}
    labelSelector:
      matchLabels:
        {{- include "sendora.selectorLabels" (dict "ctx" .ctx "component" .component) | nindent 8 }}
{{- end }}
{{- end -}}

{{- define "sendora.podScheduling" -}}
{{- with .cfg.nodeSelector }}
nodeSelector: {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .cfg.tolerations }}
tolerations: {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .cfg.affinity }}
affinity: {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .cfg.priorityClassName }}
priorityClassName: {{ . }}
{{- end }}
{{- end -}}

{{- define "sendora.clusterCommonEnv" -}}
- name: SENDORA_FLAVOUR
  value: cluster
# The image sets SENDORA_DB_INITIALIZE=false for the SQLite flavours; the cluster flavour refuses the
# variable whenever it is non-empty, so it is emptied here.
- name: SENDORA_DB_INITIALIZE
  value: ""
- name: HOST
  value: "0.0.0.0"
- name: PORT
  value: "8080"
- name: DATA_DIR
  value: /data
- name: SENDORA_BASE_DOMAIN
  value: {{ .Values.baseDomain | quote }}
- name: SENDORA_PG_POOLER
  value: {{ .Values.cluster.postgres.pooler | quote }}
- name: SENDORA_PG_SSLMODE
  value: {{ .Values.cluster.postgres.sslMode | quote }}
{{- if ne .Values.cluster.postgres.sslMode "require" }}
- name: SENDORA_PG_CA_FILE
  value: /etc/pg-ca/ca.crt
{{- end }}
- name: SENDORA_PG_PLATFORM_DATABASE
  value: {{ .Values.cluster.postgres.platformDatabase | quote }}
- name: SENDORA_PG_POOLERS
  value: {{ .Values.cluster.postgres.poolers | quote }}
- name: SENDORA_PLATFORM_MFA_REQUIRED
  value: {{ .Values.cluster.platformMfaRequired | toString | quote }}
- name: SENDORA_KEY_OPS_PER_HOUR
  value: {{ .Values.keys.opsPerHour | quote }}
{{- with .Values.cluster.leaseName }}
- name: SENDORA_LEASE_NAME
  value: {{ . | quote }}
{{- end }}
{{- with .Values.cluster.coordPollSeconds }}
- name: SENDORA_COORD_POLL_SECONDS
  value: {{ . | quote }}
{{- end }}
{{- with .Values.cluster.leaseSeconds }}
- name: SENDORA_LEASE_SECONDS
  value: {{ . | quote }}
{{- end }}
- name: SENDORA_POD_NAME
  valueFrom:
    fieldRef:
      fieldPath: metadata.name
{{- end -}}

{{- define "sendora.pgCAVolume" -}}
{{- if ne .Values.cluster.postgres.sslMode "require" }}
- name: pg-ca
  secret:
    secretName: {{ .Values.cluster.postgres.caSecret.name }}
    items:
      - key: {{ .Values.cluster.postgres.caSecret.key }}
        path: ca.crt
{{- end }}
{{- end -}}
{{- define "sendora.pgCAMount" -}}
{{- if ne .Values.cluster.postgres.sslMode "require" }}
- name: pg-ca
  mountPath: /etc/pg-ca
  readOnly: true
{{- end }}
{{- end -}}

{{- define "sendora.dataVolume" -}}
- name: files
  {{- if .Values.persistence.enabled }}
  persistentVolumeClaim:
    claimName: {{ include "sendora.pvcName" . }}
  {{- else }}
  emptyDir: {}
  {{- end }}
{{- end -}}

{{/* NetworkPolicy fragments. */}}
{{- define "sendora.npInternet" -}}
{{- if .Values.networkPolicy.internetEgress.enabled }}
- to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
          - 169.254.0.0/16
  ports:
    {{- range .Values.networkPolicy.internetEgress.ports }}
    - protocol: TCP
      port: {{ . }}
    {{- end }}
{{- end }}
{{- end -}}
{{- define "sendora.npPostgres" -}}
namespaceSelector: {{ toJson (default dict .Values.networkPolicy.postgres.namespaceSelector) }}
{{- with .Values.networkPolicy.postgres.podSelector }}
podSelector: {{ toJson . }}
{{- end }}
{{- end -}}

{{/* Optional root init container that makes the data volume owned by the Sendora user. */}}
{{- define "sendora.volumeOwnerInit" -}}
{{- if .Values.volumePermissions.enabled }}
initContainers:
  - name: volume-owner
    image: {{ if .Values.volumePermissions.image.repository }}{{ printf "%s:%s" .Values.volumePermissions.image.repository .Values.volumePermissions.image.tag | quote }}{{ else }}{{ include "sendora.image" . | quote }}{{ end }}
    imagePullPolicy: {{ .Values.image.pullPolicy }}
    command:
      - "sh"
      - "-c"
      - "chown {{ .Values.podSecurityContext.runAsUser }}:{{ .Values.podSecurityContext.runAsGroup }} /data && chmod 700 /data"
    securityContext:
      runAsUser: 0
      runAsNonRoot: false
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
        add:
          - CHOWN
          - FOWNER
    resources:
      requests:
        cpu: 10m
        memory: 16Mi
      limits:
        memory: 64Mi
    volumeMounts:
      - name: {{ ternary "files" "data" (eq .Values.flavour "cluster") }}
        mountPath: /data
{{- end }}
{{- end -}}
