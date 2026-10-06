{{/* Names, labels and shared parts of the Qualor chart. */}}
{{- define "qualor.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
  43 characters: the StatefulSet <fullname>-postgres then stays within 52, the
  most a StatefulSet name can have (its controller-revision-hash label adds 11 characters to it).
*/}}
{{- define "qualor.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 43 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 43 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "qualor.labels" -}}
app.kubernetes.io/name: {{ include "qualor.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "qualor.selectorLabels" -}}
app.kubernetes.io/name: {{ include "qualor.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: server
{{- end -}}

{{/* The test hook's labels: the NetworkPolicy always lets it reach the server. */}}
{{- define "qualor.testSelectorLabels" -}}
app.kubernetes.io/name: {{ include "qualor.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: test
{{- end -}}

{{- define "qualor.postgresSelectorLabels" -}}
app.kubernetes.io/name: {{ include "qualor.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: postgres
{{- end -}}

{{- define "qualor.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{/* Always pinned by digest: qualor.validate refuses the bundled PostgreSQL without one. */}}
{{- define "qualor.postgresImage" -}}
{{- $i := .Values.database.bundled.image -}}
{{- printf "%s:%s@%s" $i.repository $i.tag $i.digest -}}
{{- end -}}

{{- define "qualor.secretName" -}}
{{- default (printf "%s-secrets" (include "qualor.fullname" .)) .Values.secrets.existingSecret -}}
{{- end -}}

{{- define "qualor.postgresSecretName" -}}
{{- default (printf "%s-postgres" (include "qualor.fullname" .)) .Values.database.bundled.existingSecret -}}
{{- end -}}

{{- define "qualor.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "qualor.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Refuse values that cannot work, each with a message that says what to change. */}}
{{- define "qualor.validate" -}}
{{- $v := .Values -}}
{{- if not (has $v.database.mode (list "embedded" "external" "bundled")) -}}
{{- fail "database.mode must be embedded, external or bundled" -}}
{{- end -}}
{{- if and (eq $v.database.mode "embedded") (ne (int $v.replicaCount) 1) -}}
{{- fail "database.mode=embedded runs one server per volume: set replicaCount to 1, or use database.mode=external" -}}
{{- end -}}
{{- if and (not $v.secrets.existingSecret) (or (not $v.secrets.secretKey) (not $v.secrets.bootstrapAdminPassword)) -}}
{{- fail "set secrets.existingSecret, or both secrets.secretKey (32+ characters) and secrets.bootstrapAdminPassword (12+)" -}}
{{- end -}}
{{- if and (eq $v.database.mode "external") (not $v.database.external.existingSecret) -}}
{{- fail "database.mode=external needs database.external.existingSecret (a Secret holding DATABASE_URL)" -}}
{{- end -}}
{{- if and (eq $v.database.mode "bundled") (not $v.database.bundled.existingSecret) (not $v.database.bundled.password) -}}
{{- fail "database.mode=bundled needs database.bundled.existingSecret or database.bundled.password (hex)" -}}
{{- end -}}
{{- if and $v.ingress.enabled (not $v.ingress.host) -}}
{{- fail "ingress.enabled needs ingress.host" -}}
{{- end -}}
{{- if and $v.database.external.caSecret (ne $v.database.mode "external") -}}
{{- fail "database.external.caSecret needs database.mode=external" -}}
{{- end -}}
{{- if $v.database.external.caSecret -}}
{{- range $v.extraEnv -}}
{{- if eq .name "NODE_EXTRA_CA_CERTS" -}}
{{- fail "database.external.caSecret sets NODE_EXTRA_CA_CERTS: remove it from extraEnv" -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{/* The schema checks these too; they hold when a caller skips it (--skip-schema-validation). */}}
{{- if not $v.secrets.existingSecret -}}
{{- if or (lt (len $v.secrets.secretKey) 32) (lt (len $v.secrets.bootstrapAdminPassword) 12) -}}
{{- fail "secrets.secretKey needs 32+ characters and secrets.bootstrapAdminPassword 12+" -}}
{{- end -}}
{{- end -}}
{{- if and (eq $v.database.mode "bundled") $v.database.bundled.password (not (regexMatch "^[0-9a-fA-F]+$" $v.database.bundled.password)) -}}
{{- fail "database.bundled.password must be hex (it goes into a URL)" -}}
{{- end -}}
{{/*
  Images: never latest, and a third-party image only by digest. The schema
  refuses a latest tag too; these hold when a caller skips it (--skip-schema-validation).
*/}}
{{- if eq (lower (default .Chart.AppVersion $v.image.tag)) "latest" -}}
{{- fail "image.tag latest is refused: set a release version, or image.digest" -}}
{{- end -}}
{{- if and $v.image.digest (not (regexMatch "^sha256:[0-9a-f]{64}$" $v.image.digest)) -}}
{{- fail "image.digest must be sha256:<64 hex>" -}}
{{- end -}}
{{- if eq $v.database.mode "bundled" -}}
{{- if eq (lower $v.database.bundled.image.tag) "latest" -}}
{{- fail "database.bundled.image.tag latest is refused: set a PostgreSQL version and its digest" -}}
{{- end -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" $v.database.bundled.image.digest) -}}
{{- fail "database.bundled.image.digest must pin the bundled PostgreSQL (sha256:<64 hex>)" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "qualor.containerSecurity" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: [ALL]
{{- end -}}

{{/* The /tmp every container mounts, with a size limit. */}}
{{- define "qualor.tmpVolume" -}}
- name: tmp
  emptyDir:
    sizeLimit: {{ . }}
{{- end -}}

{{- define "qualor.podSecurity" -}}
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
fsGroup: 65532
fsGroupChangePolicy: OnRootMismatch
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "qualor.env" -}}
{{- $v := .Values -}}
{{- if eq $v.database.mode "embedded" }}
- name: DATABASE_URL
  value: ""
{{- else if eq $v.database.mode "external" }}
- name: DATABASE_URL
  valueFrom:
    secretKeyRef:
      name: {{ $v.database.external.existingSecret }}
      key: {{ $v.database.external.urlKey }}
{{- else }}
- name: POSTGRES_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "qualor.postgresSecretName" . }}
      key: POSTGRES_PASSWORD
- name: DATABASE_URL
  value: {{ printf "postgres://qualor:$(POSTGRES_PASSWORD)@%s-postgres:5432/qualor" (include "qualor.fullname" .) | quote }}
{{- end }}
- name: QUALOR_SECRET_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "qualor.secretName" . }}
      key: QUALOR_SECRET_KEY
- name: QUALOR_BOOTSTRAP_ADMIN_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "qualor.secretName" . }}
      key: QUALOR_BOOTSTRAP_ADMIN_PASSWORD
- name: QUALOR_BOOTSTRAP_ADMIN_USERNAME
  value: {{ $v.config.bootstrapAdminUsername | quote }}
- name: QUALOR_WORKER_CONCURRENCY
  value: {{ $v.config.workerConcurrency | quote }}
- name: QUALOR_LOG_LEVEL
  value: {{ $v.config.logLevel | quote }}
{{- if and (eq $v.database.mode "external") $v.database.external.caSecret }}
- name: NODE_EXTRA_CA_CERTS
  value: /etc/qualor/database-ca/ca.crt
{{- end }}
{{- with $v.config.publicUrl }}
- name: QUALOR_PUBLIC_URL
  value: {{ . | quote }}
{{- end }}
{{- with $v.config.trustProxy }}
- name: QUALOR_TRUST_PROXY
  value: {{ . | quote }}
{{- end }}
{{- with $v.config.scmInternalHosts }}
- name: QUALOR_SCM_INTERNAL_HOSTS
  value: {{ . | quote }}
{{- end }}
{{- with $v.config.llmInternalHosts }}
- name: QUALOR_LLM_INTERNAL_HOSTS
  value: {{ . | quote }}
{{- end }}
{{- with $v.config.ssoInternalHosts }}
- name: QUALOR_SSO_INTERNAL_HOSTS
  value: {{ . | quote }}
{{- end }}
{{- if $v.config.forcePasswordSignIn }}
- name: QUALOR_FORCE_PASSWORD_SIGN_IN
  value: "true"
{{- end }}
{{- if eq (toString $v.config.telemetry) "false" }}
- name: QUALOR_TELEMETRY
  value: "false"
{{- end }}
{{- with $v.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{/*
  checksum/secret hashes both chart-managed Secrets: the server reads the bundled
  PostgreSQL password too. The chart generates no random value, so it changes only with a value.
*/}}
{{- define "qualor.podTemplate" -}}
metadata:
  labels:
    {{- include "qualor.selectorLabels" . | nindent 4 }}
  annotations:
    checksum/secret: {{ include (print .Template.BasePath "/secret.yaml") . | sha256sum }}
    {{- with .Values.podAnnotations }}
    {{- toYaml . | nindent 4 }}
    {{- end }}
spec:
  serviceAccountName: {{ include "qualor.serviceAccountName" . }}
  automountServiceAccountToken: false
  enableServiceLinks: false
  {{- with .Values.imagePullSecrets }}
  imagePullSecrets:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  terminationGracePeriodSeconds: 60
  securityContext:
    {{- include "qualor.podSecurity" . | nindent 4 }}
  {{- if eq .Values.database.mode "bundled" }}
  {{/* The server starts only once its database answers, instead of crash-looping. */}}
  initContainers:
    - name: wait-for-postgres
      image: {{ include "qualor.postgresImage" . | quote }}
      command:
        - sh
        - -c
        - {{ printf "until pg_isready -h %s-postgres -p 5432 -U qualor -d qualor -q; do sleep 2; done" (include "qualor.fullname" .) | quote }}
      securityContext:
        {{- include "qualor.containerSecurity" . | nindent 8 }}
      resources:
        requests: { cpu: 10m, memory: 16Mi }
        limits: { memory: 64Mi }
      volumeMounts:
        - name: tmp
          mountPath: /tmp
  {{- end }}
  containers:
    - name: server
      image: {{ include "qualor.image" . | quote }}
      imagePullPolicy: {{ .Values.image.pullPolicy }}
      ports:
        - name: http
          containerPort: 8080
          protocol: TCP
      env:
        {{- include "qualor.env" . | nindent 8 }}
      securityContext:
        {{- include "qualor.containerSecurity" . | nindent 8 }}
      startupProbe:
        httpGet: { path: /readyz, port: http }
        periodSeconds: 5
        timeoutSeconds: 3
        failureThreshold: 30
      readinessProbe:
        httpGet: { path: /readyz, port: http }
        periodSeconds: 10
        timeoutSeconds: 3
      livenessProbe:
        httpGet: { path: /healthz, port: http }
        periodSeconds: 20
        timeoutSeconds: 3
        failureThreshold: 3
      resources:
        {{- toYaml .Values.resources | nindent 8 }}
      volumeMounts:
        - name: tmp
          mountPath: /tmp
        {{- if eq .Values.database.mode "embedded" }}
        - name: data
          mountPath: /var/lib/qualor
        {{- end }}
        {{- if and (eq .Values.database.mode "external") .Values.database.external.caSecret }}
        - name: database-ca
          mountPath: /etc/qualor/database-ca
          readOnly: true
        {{- end }}
  volumes:
    {{- include "qualor.tmpVolume" "256Mi" | nindent 4 }}
    {{- with .Values.database.external }}
    {{- if and (eq $.Values.database.mode "external") .caSecret }}
    - name: database-ca
      secret:
        secretName: {{ .caSecret }}
        items:
          - key: {{ .caKey }}
            path: ca.crt
    {{- end }}
    {{- end }}
  {{- with .Values.nodeSelector }}
  nodeSelector:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with .Values.tolerations }}
  tolerations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with .Values.affinity }}
  affinity:
    {{- toYaml . | nindent 4 }}
  {{- end }}
{{- end -}}
