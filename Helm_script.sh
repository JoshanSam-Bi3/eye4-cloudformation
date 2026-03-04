set -e  # Exit on any error

# ============================================================
# Colors for output
# ============================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;37m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# ============================================================
# Helper functions
# ============================================================
info()    { echo -e "${CYAN}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
fail()    { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }
step()    { echo -e "\n${BOLD}${CYAN}════════════════════════════════════════════════════════${NC}"; \
            echo -e "${BOLD}${CYAN}  STEP $1${NC}"; \
            echo -e "${BOLD}${CYAN}════════════════════════════════════════════════════════${NC}"; }
 
echo -e "${CYAN}"
cat <<'BANNER'

  ███████╗██╗   ██╗███████╗██╗  ██╗    █████╗ ██╗
  ██╔════╝╚██╗ ██╔╝██╔════╝██║  ██║   ██╔══██╗██║
  █████╗   ╚████╔╝ █████╗  ███████║   ███████║██║
  ██╔══╝    ╚██╔╝  ██╔══╝  ╚════██║   ██╔══██║██║
  ███████╗   ██║   ███████╗     ██║   ██║  ██║██║
  ╚══════╝   ╚═╝   ╚══════╝     ╚═╝   ╚═╝  ╚═╝╚═╝

  Full Deployment Automation Script
  CloudFormation → OIDC → Helm → Ingress → Port Forward

BANNER
echo -e "${NC}"
# Get AWS Account Credentials and OIDC info

aws configure 

AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)
AWS_ACCESS_KEY=$(aws configure get aws_access_key_id)
AWS_SECRET_KEY=$(aws configure get aws_secret_access_key)
AWS_REGION=$(aws configure get region)

echo "AWS Account ID: $AWS_ACCOUNT_ID"
echo "AWS Region: $AWS_REGION"

# Kubectl Connection

# read -p "Enter stack Name to be created: " STACK_NAME

read -p "Enter the Admin ARN(Eg.arn:aws:iam::<ACCOUNT_ID>:user/<user-email>): " ADMIN_ROLE_ARN

# DEPLOYMENT_ID=$(LC_ALL=C tr -dc a-z0-9 </dev/urandom | head -c 16 ; echo)

# aws cloudformation create-stack --stack-name eye4-infra-only-stack \
#   --stack-name $STACK_NAME \
#   --template-body $(curl -sL raw.githubusercontent.com/JoshanSam-Bi3/eye4-cloudformation/refs/heads/main/eks-infra-only-cf.yaml) \
#   --capabilities CAPABILITY_NAMED_IAM \
#   --parameters \
      # ParameterKey=DeploymentID,ParameterValue=$DEPLOYMENT_ID,
      # ParameterKey=AdminIAMArns,ParameterValue=$ADMIN_ROLE_ARN

EKS_CLUSTER_NAME="EksCluster"

aws eks update-kubeconfig --name "$EKS_CLUSTER_NAME" --region "$AWS_REGION"

# Create Namespace for Kubernetes Pods

kubectl create ns strimzi
kubectl create ns eye4 

# Install Operators

helm repo add cnpg https://cloudnative-pg.github.io/charts 
helm repo update 
helm install cnpg cnpg/cloudnative-pg --namespace cnpg-system --create-namespace --version 0.27.1 

helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx 
helm repo update 
helm install ingress-nginx ingress-nginx/ingress-nginx \
  --namespace ingress-nginx \
  --create-namespace 

helm repo add strimzi https://strimzi.io/charts/ 
helm repo update 
helm install strimzi-operator oci://quay.io/strimzi-helm/strimzi-kafka-operator \
  --version 0.40.0 \
  -n strimzi-system \
  --set 'watchNamespaces={strimzi}' \
  --create-namespace

helm repo add jetstack https://charts.jetstack.io 
helm repo update 
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --version v1.14.4 \
  --set installCRDs=true 

kubectl delete rolebinding strimzi-cluster-operator \
  strimzi-cluster-operator-entity-operator-delegation \
  strimzi-cluster-operator-watched -n strimzi 

secret="$(mktemp)"

# Create ECR Pull Secret
kubectl create secret docker-registry ecr-pull-secret \
  --docker-server=709825985650.dkr.ecr.us-east-1.amazonaws.com \
  --docker-username=AWS \
  --docker-password="$(aws ecr get-login-password --region us-east-1)" \
  --namespace=eye4 \
  --dry-run=client -o yaml > "$secret"

kubectl apply -f "$secret"

rm -f "$secret"

# Login into AWS ECR Repo

aws ecr get-login-password --region us-east-1 | helm registry login --username AWS --password-stdin 709825985650.dkr.ecr.us-east-1.amazonaws.com 

read -p "Enter the S3 bucket name for Volume Mount: " BUCKET_NAME
read -p "Enter the EFS ID for Volume Mount: " EFS_ID
read -p "Enter the domain name: " DOMAIN_NAME
read -p "Enter the S3 backup bucket name for CNPG PostgreSQL: " BACKUP_BUCKET_NAME

# AWS Cognito Registration 
read -p "Enter Pool name for Cognito: " COGNITO_POOL_NAME

aws cognito-idp create-user-pool \
    --pool-name "$COGNITO_POOL_NAME" \
    --policies '{"PasswordPolicy":{"MinimumLength":8,"RequireUppercase":true,"RequireLowercase":true,"RequireNumbers":true,"RequireSymbols":true}}' \
    --auto-verified-attributes email \
    --no-cli-pager

COGNITO_POOL_ID=$(aws cognito-idp list-user-pools --max-results 10 --query "UserPools[?Name=='$COGNITO_POOL_NAME'].Id" --output text --no-cli-pager)

read -p "Enter the Cognito client name: " COGNITO_CLIENT_NAME

aws cognito-idp create-user-pool-client \
    --user-pool-id $COGNITO_POOL_ID \
    --client-name "$COGNITO_CLIENT_NAME" \
    --generate-secret \
    --callback-urls "https://$DOMAIN_NAME/api/auth/callback/cognito" \
    --logout-urls "https://$DOMAIN_NAME" \
    --default-redirect-uri "https://$DOMAIN_NAME/api/auth/callback/cognito" \
    --allowed-o-auth-flows "code" \
    --allowed-o-auth-scopes "email" "openid" "profile" \
    --supported-identity-providers "COGNITO" \
    --no-cli-pager

read -r -p "Enter the username for the Cognito user: " COGNITO_USERNAME
read -r -p "Enter your email for the Cognito user: " COGNITO_EMAIL

# Sanitize inputs: remove CR/LF, trim surrounding whitespace.
COGNITO_USERNAME=$(printf '%s' "$COGNITO_USERNAME" | tr -d '\r\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
# lower-case the email and trim
COGNITO_EMAIL=$(printf '%s' "$COGNITO_EMAIL" | tr -d '\r\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | tr '[:upper:]' '[:lower:]')

# Basic validation
if [ -z "${COGNITO_USERNAME}" ] || [ -z "${COGNITO_EMAIL}" ]; then
  echo "ERROR: Cognito username and email must not be empty" >&2
  exit 1
fi

aws cognito-idp admin-create-user \
    --user-pool-id "$COGNITO_POOL_ID" \
    --username "$COGNITO_USERNAME" \
    --user-attributes Name=email,Value="$COGNITO_EMAIL" \
    --temporary-password 'TempPass@123' \
    --message-action SUPPRESS

# Create Cognito groups for RBAC (admin & allowed users)
COGNITO_DEV_GROUP="dev"
COGNITO_SUPPORT_GROUP="support"
COGNITO_ADMIN_GROUP="admin"

aws cognito-idp create-group \
    --user-pool-id "$COGNITO_POOL_ID" \
    --group-name "$COGNITO_SUPPORT_GROUP" \
    --description "Allowed users for Eye4 portal" \
    --no-cli-pager

aws cognito-idp create-group \
    --user-pool-id "$COGNITO_POOL_ID" \
    --group-name "$COGNITO_DEV_GROUP" \
    --description "Allowed users for Eye4 portal" \
    --no-cli-pager

aws cognito-idp create-group \
    --user-pool-id "$COGNITO_POOL_ID" \
    --group-name "$COGNITO_ADMIN_GROUP" \
    --description "Admin users for Eye4 portal" \
    --no-cli-pager

# Add the created user to both groups (admin user by default)
aws cognito-idp admin-add-user-to-group \
    --user-pool-id "$COGNITO_POOL_ID" \
    --username "$COGNITO_USERNAME" \
    --group-name "$COGNITO_ADMIN_GROUP" \
    --no-cli-pager

echo "Cognito groups created: $COGNITO_ALLOWED_GROUP, $COGNITO_ADMIN_GROUP"
echo "User '$COGNITO_USERNAME' added to both groups."

echo "Login into Cognito using the username and temporary password to set a new password for the user."

echo 
echo "Cognito email ID: $COGNITO_EMAIL"
echo
echo "Cognito Username: $COGNITO_USERNAME"
echo "Cognito Password: TempPass@123"

read -p "Enter the domain prefix for Cognito: " DOMAIN_PREFIX

aws cognito-idp create-user-pool-domain \
    --user-pool-id "$COGNITO_POOL_ID" \
    --domain "$DOMAIN_PREFIX"
COGNITO_DOMAIN_PREFIX=$(aws cognito-idp describe-user-pool --user-pool-id "$COGNITO_POOL_ID" --query "UserPool.Domain" --output text --no-cli-pager)
# Construct the full Cognito hosted UI domain (used by the frontend for OAuth token refresh)
COGNITO_DOMAIN="${COGNITO_DOMAIN_PREFIX}.auth.${AWS_REGION}.amazoncognito.com"
COGNITO_CLIENT_ID=$(aws cognito-idp list-user-pool-clients --user-pool-id "$COGNITO_POOL_ID" --query "UserPoolClients[?ClientName=='$COGNITO_CLIENT_NAME'].ClientId" --output text --no-cli-pager)
COGNITO_CLIENT_SECRET=$(aws cognito-idp describe-user-pool-client --user-pool-id "$COGNITO_POOL_ID" --client-id "$COGNITO_CLIENT_ID" --query "UserPoolClient.ClientSecret" --output text --no-cli-pager)

echo "Cognito Domain: $COGNITO_DOMAIN"

# aws cognito-idp update-user-pool-client \
#     --user-pool-id "$COGNITO_POOL_ID" \
#     --client-id "$COGNITO_CLIENT_ID" \
#     --allowed-o-auth-flows "code" \
#     --allowed-o-auth-scopes "openid" "email" "profile" \
#     --allowed-o-auth-flows-user-pool-client \
#     --supported-identity-providers "COGNITO" \
#     --callback-urls "https://$DOMAIN_NAME/api/auth/callback/cognito" \
#     --logout-urls "https://$DOMAIN_NAME"

NEXT_AUTH_SECRET=$(openssl rand -base64 32)

# Web-API environment defaults
AWS_SECRET_NAME="psql-connectionstring"
MONITORING_PATH="/dummy/monitor/path"
PLAYBACK_PATH="/dummy/playback/path"
DATABASE_URL="Host=pg-eks-rw.cnpg-postgresql.svc.cluster.local;Port=5432;Username=postgres;Password=admin@12345;Database=app"

# Frontend environment defaults
FASTAPI_URL="http://eye4-api-service:5000"
COGNITO_ADMIN_GROUP_NAME="admin"
TEST_BUILD="false"
TEST_USER_TYPE=""

helm install eye4-release oci://709825985650.dkr.ecr.us-east-1.amazonaws.com/bi3-technologies/eye4 \
  --namespace eye4 \
  --version 1.0.0 \
  --set eye4-storage.s3.accountId=$AWS_ACCOUNT_ID \
  --set eye4-storage.s3.volumeHandle=$BUCKET_NAME \
  --set eye4-storage.efs.volumeHandle=$EFS_ID \
  --set global.domain=$DOMAIN_NAME \
  --set cnpg-postgresql.postgresql.cluster.backup.barmanObjectStore.s3Bucket="$BACKUP_BUCKET_NAME" \
  --set cnpg-postgresql.postgresql.cluster.backup.barmanObjectStore.destinationPath="s3://${BACKUP_BUCKET_NAME}/eye4" \
  --set eye4-frontend.env.NEXT_PUBLIC_COGNITO_CLIENT_ID="$COGNITO_CLIENT_ID" \
  --set eye4-frontend.env.NEXT_PUBLIC_COGNITO_CLIENT_SECRET="$COGNITO_CLIENT_SECRET" \
  --set eye4-frontend.env.NEXT_PUBLIC_COGNITO_DOMAIN="$COGNITO_DOMAIN" \
  --set eye4-frontend.env.NEXT_PUBLIC_COGNITO_REGION="$AWS_REGION" \
  --set eye4-frontend.env.NEXT_PUBLIC_COGNITO_USER_POOL_ID="$COGNITO_POOL_ID" \
  --set eye4-frontend.env.NEXTAUTH_SECRET="$NEXT_AUTH_SECRET" \
  --set eye4-frontend.env.NEXT_PUBLIC_FASTAPI_URL="$FASTAPI_URL" \
  --set eye4-frontend.env.NEXT_PUBLIC_COGNITO_ADMIN_GROUP_NAME="$COGNITO_ADMIN_GROUP_NAME" \
  --set eye4-frontend.env.NEXT_PUBLIC_TEST_BUILD="$TEST_BUILD" \
  --set eye4-frontend.env.NEXT_PUBLIC_TEST_USER_TYPE="$TEST_USER_TYPE" \
  --set eye4-webapi.env.AWS_REGION="$AWS_REGION" \
  --set eye4-webapi.env.AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY" \
  --set eye4-webapi.env.AWS_SECRET_ACCESS_KEY="$AWS_SECRET_KEY" \
  --set eye4-webapi.env.AWS_SECRET_NAME="$AWS_SECRET_NAME" \
  --set eye4-webapi.env.MONITORING_PATH="$MONITORING_PATH" \
  --set eye4-webapi.env.PLAYBACK_PATH="$PLAYBACK_PATH" \
  --set eye4-webapi.env.DATABASE_URL="$DATABASE_URL"; echo "Eye4 Helm Chart deployed successfully!"
  
pg_config="$(mktemp)"
trap 'rm -f "$pg_config"' EXIT

cat <<EOF > "$pg_config"
apiVersion: v1
kind: Secret
metadata:
  name: aws-s3-credentials
  namespace: cnpg-postgresql
type: Opaque
stringData:
  access-key-id: $AWS_ACCESS_KEY
  secret-access-key: $AWS_SECRET_KEY
EOF

kubectl apply -f "$pg_config"

NLB=$(kubectl get svc ingress-nginx-controller -n ingress-nginx -o jsonpath="{.status.loadBalancer.ingress[0].hostname}")

echo "Update the url to the domain as A record pointing to the NLB: $NLB"
