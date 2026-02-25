cat <<'EOF'
 m    m        ""#                  mmmmmm                  mm
 #    #  mmm     #    mmmmm         #      m   m   mmm     m"#
 #mmmm# #"  #    #    # # #         #mmmmm "m m"  #"  #   #" #
 #    # #""""    #    # # #         #       #m#   #""""  #mmm#m
 #    # "#mm"    "mm  # # #         #mmmmm  "#    "#mm"      #
                                            m"
                                           ""
EOF

# Get AWS Account Credentials and OIDC info

aws configure 

AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query 'Account' --output text)
AWS_ACCESS_KEY=$(aws configure get aws_access_key_id)
AWS_SECRET_KEY=$(aws configure get aws_secret_access_key)
AWS_REGION=$(aws configure get region)

echo "AWS Account ID: $AWS_ACCOUNT_ID"
echo "AWS Region: $AWS_REGION"

# Kubectl Connection

read -p "Enter stack Name to be created: " STACK_NAME

DEPLOYMENT_ID=$(LC_ALL=C tr -dc a-z0-9 </dev/urandom | head -c 16 ; echo)

aws cloudformation create-stack --stack-name eye4-infra-only-stack \
  --stack-name $STACK_NAME \
  --template-body raw.githubusercontent.com/JoshanSam-Bi3/eye4-cloudformation/refs/heads/main/eks-infra-only-cf.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameters ParameterKey=DeploymentID,ParameterValue=$DEPLOYMENT_ID

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

echo "Login into Cognito using the username and temporary password to set a new password for the user."

echo 
echo "Cognito email ID: $COGNITO_EMAIL"
echo "Cognito Password: TempPass@123"

read -p "Enter the domain prefix for Cognito: " DOMAIN_PREFIX

aws cognito-idp create-user-pool-domain \
    --user-pool-id "$COGNITO_POOL_ID" \
    --domain "$DOMAIN_PREFIX"
COGNITO_DOMAIN=$(aws cognito-idp describe-user-pool --user-pool-id "$COGNITO_POOL_ID" --query "UserPool.Domain" --output text --no-cli-pager)
COGNITO_CLIENT_ID=$(aws cognito-idp list-user-pool-clients --user-pool-id "$COGNITO_POOL_ID" --query "UserPoolClients[?ClientName=='$COGNITO_CLIENT_NAME'].ClientId" --output text --no-cli-pager)
COGNITO_CLIENT_SECRET=$(aws cognito-idp describe-user-pool-client --user-pool-id "$COGNITO_POOL_ID" --client-id "$COGNITO_CLIENT_ID" --query "UserPoolClient.ClientSecret" --output text --no-cli-pager)
# demo.eye4.ai.auth.ap-southeast-2.amazoncognito.com

NEXT_AUTH_SECRET=$(openssl rand -base64 32)

helm install eye4-release oci://709825985650.dkr.ecr.us-east-1.amazonaws.com/bi3-technologies/eye4 \
  --version 0.4.0 \
  --namespace eye4 \
  --set eye4-storage.s3.accountId=$AWS_ACCOUNT_ID \
  --set eye4-storage.s3.volumeHandle=$BUCKET_NAME \
  --set eye4-storage.efs.volumeHandle=$EFS_ID \
  --set global.domain=$DOMAIN_NAME \
  --set cnpg-postgresql.postgresql.cluster.backup.barmanObjectStore.s3Bucket="$BACKUP_BUCKET_NAME" \
  --set cnpg-postgresql.postgresql.cluster.backup.barmanObjectStore.destinationPath="s3://${BACKUP_BUCKET_NAME}/eye4" \
  --set eye4-frontend.env.NEXT_PUBLIC_COGNITO_CLIENT_ID="$COGNITO_CLIENT_ID" \
  --set eye4-frontend.env.NEXT_PUBLIC_COGNITO_USER_POOL_ID="$COGNITO_POOL_ID" \
  --set eye4-frontend.env.NEXT_PUBLIC_COGNITO_REGION="$AWS_REGION" \
  --set eye4-frontend.env.NEXT_PUBLIC_COGNITO_DOMAIN="$COGNITO_DOMAIN" \
  --set eye4-frontend.env.NEXT_PUBLIC_COGNITO_CLIENT_SECRET="$COGNITO_CLIENT_SECRET" \
  --set eye4-frontend.env.NEXTAUTH_SECRET="$NEXT_AUTH_SECRET"; echo "Eye4 Helm Chart deployed successfully!"
  
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
