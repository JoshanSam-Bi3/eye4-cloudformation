#!/bin/bash
set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
EKS_CLUSTER_NAME="EksCluster"
AWS_REGION=$(aws configure get region)
PROM_NAMESPACE="prometheus"
PROM_SA_NAME="prometheus-server"
RELEASE_NAME="eye4-prom"
ROLE_NAME="Eye4-AMP"
CHART_VERSION="82.1.1"   # Set desired version

# ── Derived values ───────────────────────────────────────────────────────────
echo "── Discovering AWS configuration ──"

ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)

OIDC_ISSUER=$(aws eks describe-cluster \
  --name "$EKS_CLUSTER_NAME" \
  --region "$AWS_REGION" \
  --query 'cluster.identity.oidc.issuer' \
  --output text | sed 's|https://||')

OIDC_PROVIDER_ARN="arn:aws:iam::${ACCOUNT_ID}:oidc-provider/${OIDC_ISSUER}"

AMP_WORKSPACE_ID=$(aws amp list-workspaces \
  --region "$AWS_REGION" \
  --query 'workspaces[0].workspaceId' \
  --output text)

AMP_WORKSPACE_ARN="arn:aws:aps:${AWS_REGION}:${ACCOUNT_ID}:workspace/${AMP_WORKSPACE_ID}"

AMP_REMOTE_WRITE_URL="https://aps-workspaces.${AWS_REGION}.amazonaws.com/workspaces/${AMP_WORKSPACE_ID}/api/v1/remote_write"

ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"

echo "  Account ID    : $ACCOUNT_ID"
echo "  OIDC Issuer   : $OIDC_ISSUER"
echo "  AMP Workspace : $AMP_WORKSPACE_ID"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# Create/Update IRSA Role
# ══════════════════════════════════════════════════════════════════════════════

echo "── Creating/updating IRSA role ──"

TRUST_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "${OIDC_PROVIDER_ARN}" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "${OIDC_ISSUER}:aud": "sts.amazonaws.com",
        "${OIDC_ISSUER}:sub": "system:serviceaccount:${PROM_NAMESPACE}:${PROM_SA_NAME}"
      }
    }
  }]
}
EOF
)

if aws iam get-role --role-name "${ROLE_NAME}" >/dev/null 2>&1; then
  aws iam update-assume-role-policy \
    --role-name "${ROLE_NAME}" \
    --policy-document "${TRUST_POLICY}"
  echo "  ✓ Updated existing role"
else
  aws iam create-role \
    --role-name "${ROLE_NAME}" \
    --assume-role-policy-document "${TRUST_POLICY}" \
    --description "IRSA role for Prometheus remote_write to AMP"
  echo "  ✓ Created role"
fi

aws iam put-role-policy \
  --role-name "${ROLE_NAME}" \
  --policy-name "${ROLE_NAME}-RemoteWrite" \
  --policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [{
      \"Effect\": \"Allow\",
      \"Action\": [\"aps:RemoteWrite\"],
      \"Resource\": \"${AMP_WORKSPACE_ARN}\"
    }]
  }"

echo "  ✓ IAM role ready"

# ══════════════════════════════════════════════════════════════════════════════
# Namespace + ServiceAccount
# ══════════════════════════════════════════════════════════════════════════════

echo "── Configuring namespace and ServiceAccount ──"

kubectl create namespace "${PROM_NAMESPACE}" 2>/dev/null || true

kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${PROM_SA_NAME}
  namespace: ${PROM_NAMESPACE}
  annotations:
    eks.amazonaws.com/role-arn: ${ROLE_ARN}
EOF

echo "  ✓ ServiceAccount ready"

# ══════════════════════════════════════════════════════════════════════════════
# Login to OCI registry
# ══════════════════════════════════════════════════════════════════════════════

echo "── Logging into OCI registry ──"

helm registry login ghcr.io \
  -u anonymous \
  -p anonymous >/dev/null 2>&1 || true

# ══════════════════════════════════════════════════════════════════════════════
# Deploy kube-prometheus-stack from OCI
# ══════════════════════════════════════════════════════════════════════════════

echo "── Deploying kube-prometheus-stack from OCI ──"

TMP_VALUES=$(mktemp)

cat > "$TMP_VALUES" <<EOF
prometheus:
  serviceAccount:
    create: false
    name: ${PROM_SA_NAME}

  prometheusSpec:
    serviceAccountName: ${PROM_SA_NAME}
    externalLabels:
      cluster: ${EKS_CLUSTER_NAME}
    remoteWrite:
      - url: ${AMP_REMOTE_WRITE_URL}
        sigv4:
          region: ${AWS_REGION}
        queueConfig:
          maxSamplesPerSend: 1000
          maxShards: 200
          capacity: 2500
    serviceMonitorSelectorNilUsesHelmValues: false
    podMonitorSelectorNilUsesHelmValues: false

grafana:
  enabled: true

alertmanager:
  enabled: true
EOF

helm upgrade --install "${RELEASE_NAME}" \
  oci://ghcr.io/prometheus-community/charts/kube-prometheus-stack \
  --version "${CHART_VERSION}" \
  --namespace "${PROM_NAMESPACE}" \
  --values "${TMP_VALUES}" \
  --create-namespace

rm -f "${TMP_VALUES}"

echo "  ✓ Monitoring stack deployed"

# ══════════════════════════════════════════════════════════════════════════════
# Apply PodMonitors for Kafka (Strimzi) and CNPG
# ══════════════════════════════════════════════════════════════════════════════

echo "── Applying PodMonitors ──"

pm_yaml=$(mktemp)
cat > "$pm_yaml" <<EOF
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  name: strimzi-cluster-operator-metrics
  namespace: prometheus
  labels:
    app: strimzi
    release: eye4-prom
spec:
  selector:
    matchLabels:
      strimzi.io/kind: cluster-operator
  namespaceSelector:
    matchNames:
      - strimzi
  podMetricsEndpoints:
    - path: /metrics
      port: http
---

apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  name: strimzi-entity-operator-metrics
  namespace: prometheus
  labels:
    app: strimzi
    release: eye4-prom
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: entity-operator
  namespaceSelector:
    matchNames:
      - strimzi
  podMetricsEndpoints:
    - path: /metrics
      port: healthcheck
---
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  name: strimzi-bridge-metrics
  namespace: prometheus
  labels:
    app: strimzi
    release: eye4-prom
spec:
  selector:
    matchLabels:
      strimzi.io/kind: KafkaBridge
  namespaceSelector:
    matchNames:
      - strimzi
  podMetricsEndpoints:
    - path: /metrics
      port: rest-api
---
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  name: strimzi-kafka-resources-metrics
  namespace: prometheus
  labels:
    app: strimzi
    release: eye4-prom
spec:
  selector:
    matchExpressions:
      - key: strimzi.io/kind
        operator: In
        values: ["Kafka", "KafkaConnect", "KafkaMirrorMaker", "KafkaMirrorMaker2"]
  namespaceSelector:
    matchNames:
      - strimzi
  podMetricsEndpoints:
    - path: /metrics
      port: tcp-prometheus
      relabelings:
        - separator: ;
          regex: __meta_kubernetes_pod_label_(strimzi_io_.+)
          replacement: $1
          action: labelmap
        - sourceLabels: [__meta_kubernetes_namespace]
          separator: ;
          regex: (.*)
          targetLabel: namespace
          replacement: $1
          action: replace
        - sourceLabels: [__meta_kubernetes_pod_name]
          separator: ;
          regex: (.*)
          targetLabel: kubernetes_pod_name
          replacement: $1
          action: replace
        - sourceLabels: [__meta_kubernetes_pod_node_name]
          separator: ;
          regex: (.*)
          targetLabel: node_name
          replacement: $1
          action: replace
        - sourceLabels: [__meta_kubernetes_pod_host_ip]
          separator: ;
          regex: (.*)
          targetLabel: node_ip
          replacement: $1
          action: replace
---
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  name: cnpg-postgresql-metrics
  namespace: prometheus
  labels:
    app: postgresql
    release: eye4-prom
spec:
  selector:
    matchLabels:
      cnpg.io/cluster: pg-eks
  namespaceSelector:
    matchNames:
      - cnpg-postgresql
  podMetricsEndpoints:
    - path: /metrics
      port: metrics
EOF

kubectl apply -f "$pm_yaml"
rm -f "$pm_yaml"
echo "  ✓ PodMonitors applied (Kafka + CNPG)"

# ══════════════════════════════════════════════════════════════════════════════
# Status
# ══════════════════════════════════════════════════════════════════════════════

echo ""
echo "── Monitoring stack status ──"
kubectl get pods -n "${PROM_NAMESPACE}" -o wide

echo ""
echo "── Grafana credentials ──"
echo "  Port-forward:"
echo "  kubectl port-forward -n ${PROM_NAMESPACE} svc/${RELEASE_NAME}-grafana 3000:80"
echo ""
echo -n "  Password: "
kubectl get secret -n "${PROM_NAMESPACE}" "${RELEASE_NAME}-grafana" \
  -o jsonpath="{.data.admin-password}" 2>/dev/null | base64 --decode 2>/dev/null || echo "(pending)"

echo ""
echo "✓ Setup complete"
echo "Metrics flow:"
echo "Pods → Prometheus → AMP → Grafana"

aws iam put-role-policy \
  --role-name Eye4WebApiIrsaRole \
  --policy-name AmpQueryAccess \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "aps:QueryMetrics",
          "aps:GetLabels",
          "aps:GetSeries",
          "aps:GetMetricMetadata"
        ],
        "Resource": "arn:aws:aps:ap-southeast-2:682853212408:workspace/ws-5bc3489f-0384-46cb-b6a2-61ca4bf76136"
      }
    ]
  }'
