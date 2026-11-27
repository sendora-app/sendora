{{/* Names, labels and shared fragments of the Sendora chart. */}}

{{- define "sendora.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "sendora.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "sendora.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Common labels. Call with (dict "ctx" . "component" "web"). */}}
{{- define "sendora.labels" -}}
helm.sh/chart: {{ include "sendora.chart" .ctx }}
{{ include "sendora.selectorLabels" . }}
app.kubernetes.io/version: {{ .ctx.Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .ctx.Release.Service }}
app.kubernetes.io/part-of: sendora
sendora.io/flavour: {{ .ctx.Values.flavour | quote }}
{{- end -}}

{{- define "sendora.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sendora.name" .ctx }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* Component of the single-process flavours. */}}
{{- define "sendora.isCluster" -}}{{ if eq .Values.flavour "cluster" }}true{{ end }}{{- end -}}

{{- define "sendora.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}
{{- end -}}

{{- define "sendora.imagePullSecrets" -}}
{{- with (concat (.Values.imagePullSecrets | default list) (.Values.image.pullSecrets | default list)) }}
imagePullSecrets:
{{- range . }}
  - name: {{ if kindIs "string" . }}{{ . }}{{ else }}{{ .name }}{{ end }}
{{- end }}
{{- end }}
{{- end -}}

{{/* Names of resources. */}}
{{- define "sendora.webName" -}}{{ printf "%s-web" (include "sendora.fullname" .) | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "sendora.controllerName" -}}{{ printf "%s-controller" (include "sendora.fullname" .) | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "sendora.keysServiceName" -}}{{ printf "%s-controller-keys" (include "sendora.fullname" .) | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "sendora.configName" -}}{{ printf "%s-config" (include "sendora.fullname" .) | trunc 63 | trimSuffix "-" }}{{- end -}}
{{/* "true" when the master key Secret is mounted as a DIRECTORY of master-<n> files (D46): forced by
masterKey.mountAsDirectory, otherwise detected from a secretKey of the form master-<n> (or empty). */}}
{{- define "sendora.keyDirMode" -}}
{{- $m := .Values.masterKey.mountAsDirectory -}}
{{- if kindIs "bool" $m -}}{{ if $m }}true{{ end }}
{{- else if or (not .Values.masterKey.secretKey) (regexMatch "^master-[0-9]+$" .Values.masterKey.secretKey) -}}true
{{- end -}}
{{- end -}}

{{/* Value of SENDORA_DB_KEY_FILE for a mount directory (ctx dict "ctx" "dir"). */}}
{{- define "sendora.keyFilePath" -}}
{{- if include "sendora.keyDirMode" .ctx }}{{ .dir }}{{ else }}{{ printf "%s/%s" .dir .ctx.Values.masterKey.secretKey }}{{ end -}}
{{- end -}}

{{- define "sendora.keySecretName" -}}{{ default (printf "%s-key" (include "sendora.fullname" .)) .Values.masterKey.existingSecret }}{{- end -}}
{{- define "sendora.setupSecretName" -}}{{ default (printf "%s-setup" (include "sendora.fullname" .)) .Values.setupCode.existingSecret }}{{- end -}}
{{- define "sendora.keysTLSSecretName" -}}{{ default (printf "%s-keys-tls" (include "sendora.fullname" .)) .Values.cluster.keyEndpoint.tls.existingSecret }}{{- end -}}
{{- define "sendora.keysCAConfigMapName" -}}{{ printf "%s-keys-ca" (include "sendora.fullname" .) | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "sendora.pvcName" -}}{{ default (printf "%s-data" (include "sendora.fullname" .)) .Values.persistence.existingClaim }}{{- end -}}

{{- define "sendora.webServiceAccount" -}}
{{- if .Values.serviceAccount.web.name -}}{{ .Values.serviceAccount.web.name }}{{- else if .Values.serviceAccount.create -}}{{ include "sendora.webName" . }}{{- else -}}default{{- end -}}
{{- end -}}
{{- define "sendora.controllerServiceAccount" -}}
{{- if .Values.serviceAccount.controller.name -}}{{ .Values.serviceAccount.controller.name }}{{- else if .Values.serviceAccount.create -}}{{ include "sendora.controllerName" . }}{{- else -}}default{{- end -}}
{{- end -}}
{{- define "sendora.appServiceAccount" -}}
{{- if .Values.serviceAccount.app.name -}}{{ .Values.serviceAccount.app.name }}{{- else if .Values.serviceAccount.create -}}{{ include "sendora.fullname" . }}{{- else -}}default{{- end -}}
{{- end -}}

{{/* https URL of the controller key endpoint as seen by web pods. */}}
{{- define "sendora.keyURL" -}}
{{- printf "https://%s.%s.svc.%s:%v" (include "sendora.keysServiceName" .) .Release.Namespace .Values.clusterDomain (.Values.cluster.keyEndpoint.port) -}}
{{- end -}}

{{/* Base domain without ":port" (for ingress host rules). */}}
{{- define "sendora.baseHost" -}}{{ index (splitList ":" .Values.baseDomain) 0 }}{{- end -}}

{{/* Ingress hosts: explicit list, or the wildcard + base host for multi/cluster. */}}
{{- define "sendora.ingressHosts" -}}
{{- if .Values.ingress.hosts -}}
{{- toYaml .Values.ingress.hosts -}}
{{- else if ne .Values.flavour "single" -}}
{{- toYaml (list (printf "*.%s" (include "sendora.baseHost" .)) (include "sendora.baseHost" .)) -}}
{{- end -}}
{{- end -}}

{{/* Pod/container security contexts (restricted Pod Security Standard). */}}
{{- define "sendora.podSecurityContext" -}}
{{- toYaml .Values.podSecurityContext -}}
{{- end -}}
{{- define "sendora.containerSecurityContext" -}}
{{- toYaml .Values.containerSecurityContext -}}
{{- end -}}

{{/* Settings from values.config as ConfigMap data (values quoted). */}}
{{- define "sendora.configData" -}}
{{- range $k, $v := .Values.config }}
{{ $k }}: {{ $v | toString | quote }}
{{- end }}
{{- end -}}

{{/* Kubernetes DNS peer for NetworkPolicy egress. */}}
{{- define "sendora.dnsPeer" -}}
- to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
      podSelector:
        matchLabels:
          k8s-app: kube-dns
  ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
{{- end -}}

{{/* Fail early on inconsistent values. */}}
{{- define "sendora.validate" -}}
{{- if not (has .Values.flavour (list "single" "multi" "cluster")) -}}
{{- fail (printf "flavour must be single, multi or cluster (got %q)" (toString .Values.flavour)) -}}
{{- end -}}
{{- if and (ne .Values.flavour "single") (not .Values.baseDomain) -}}
{{- fail "baseDomain is required for the multi and cluster flavours (tenants are served on <slug>.<baseDomain>)" -}}
{{- end -}}
{{- if and .Values.setupCode.value .Values.setupCode.existingSecret -}}
{{- fail "setupCode.value and setupCode.existingSecret are mutually exclusive" -}}
{{- end -}}
{{- if and (not .Values.masterKey.existingSecret) (not .Values.masterKey.generate) -}}
{{- fail "no master key: set masterKey.existingSecret (recommended; Secret with the 32-byte key file under masterKey.secretKey) or masterKey.generate=true (convenience, read the warnings in values.yaml)" -}}
{{- end -}}
{{- if and (kindIs "bool" .Values.masterKey.mountAsDirectory) (not .Values.masterKey.mountAsDirectory) (not .Values.masterKey.secretKey) -}}
{{- fail "masterKey.secretKey is required when masterKey.mountAsDirectory is false" -}}
{{- end -}}
{{- if and .Values.ingress.enabled (eq .Values.flavour "single") (not .Values.ingress.hosts) -}}
{{- fail "ingress.hosts is required for the single flavour when ingress.enabled" -}}
{{- end -}}
{{- if eq .Values.flavour "cluster" -}}
{{- $c := .Values.cluster -}}
{{- if not $c.postgres.pooler -}}{{- fail "cluster.postgres.pooler (host:port of the read-write PgBouncer) is required" -}}{{- end -}}
{{- if not $c.postgres.direct -}}{{- fail "cluster.postgres.direct (host:port of the read-write PostgreSQL service) is required" -}}{{- end -}}
{{- if not $c.postgres.provisionerSecret.name -}}{{- fail "cluster.postgres.provisionerSecret.name is required (Secret with username and password of sendora_provisioner)" -}}{{- end -}}
{{- if and (ne $c.postgres.sslMode "require") (not $c.postgres.caSecret.name) -}}{{- fail "cluster.postgres.caSecret.name is required unless cluster.postgres.sslMode=require (Secret with the CloudNativePG server CA)" -}}{{- end -}}
{{- if and $c.keyEndpoint.tls.generate $c.keyEndpoint.tls.existingSecret -}}{{- fail "cluster.keyEndpoint.tls.generate and .existingSecret are mutually exclusive" -}}{{- end -}}
{{- if and (not $c.keyEndpoint.tls.generate) (not $c.keyEndpoint.tls.existingSecret) -}}{{- fail "key endpoint TLS: set cluster.keyEndpoint.tls.existingSecret (production) or cluster.keyEndpoint.tls.generate=true (tests, small installs)" -}}{{- end -}}
{{- end -}}
{{- end -}}

{{/* Env shared by the single-process flavours and both cluster roles. */}}
{{- define "sendora.setupCodeEnv" -}}
- name: {{ if eq .Values.flavour "single" }}SENDORA_SETUP_CODE{{ else }}SENDORA_PLATFORM_SETUP_CODE{{ end }}
  valueFrom:
    secretKeyRef:
      name: {{ include "sendora.setupSecretName" . }}
      key: {{ .Values.setupCode.secretKey }}
{{- end -}}

{{- define "sendora.setupCodeEnabled" -}}
{{- if or .Values.setupCode.existingSecret .Values.setupCode.value .Values.setupCode.generate }}true{{ end -}}
{{- end -}}
