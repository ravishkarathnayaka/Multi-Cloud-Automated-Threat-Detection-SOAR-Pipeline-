#!/usr/bin/env bash
# ==============================================================================
# Multi-Cloud Threat Detection & SOAR Pipeline: Attack Simulation Suite
# Emulates MITRE ATT&CK techniques against LocalStack or live AWS environments.
# ==============================================================================

set -eo pipefail

# ANSI Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Defaults
MODE="localstack"
ENDPOINT="http://localhost:4566"
REGION="us-east-1"
TARGET_ATTACK="all"

print_header() {
    echo -e "${PURPLE}====================================================================${NC}"
    echo -e "${CYAN}  Multi-Cloud Threat Detection & SOAR Pipeline: Attack Simulator  ${NC}"
    echo -e "${PURPLE}====================================================================${NC}"
}

usage() {
    echo -e "Usage: $0 [options]"
    echo -e "Options:"
    echo -e "  --mode <localstack|live-aws>  Target execution environment (default: localstack)"
    echo -e "  --endpoint <url>              Custom endpoint URL (default: http://localhost:4566)"
    echo -e "  --region <region>             AWS Region (default: us-east-1)"
    echo -e "  --attack <all|iam|s3|ec2|trail> Specific attack technique to emulate (default: all)"
    echo -e "  --help                        Display this help message"
    exit 1
}

# Parse CLI flags
while [[ $# -gt 0 ]]; do
    case $1 in
        --mode)
            MODE="$2"
            shift 2
            ;;
        --endpoint)
            ENDPOINT="$2"
            shift 2
            ;;
        --region)
            REGION="$2"
            shift 2
            ;;
        --attack)
            TARGET_ATTACK="$2"
            shift 2
            ;;
        --help)
            usage
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            usage
            ;;
    esac
done

# Configure AWS CLI invocation wrapper
if [ "$MODE" == "localstack" ]; then
    export AWS_ACCESS_KEY_ID="mock_access_key"
    export AWS_SECRET_ACCESS_KEY="mock_secret_key"
    export AWS_DEFAULT_REGION="$REGION"
    AWS_CMD="aws --endpoint-url $ENDPOINT --region $REGION"
    echo -e "${BLUE}[INFO] Running in LOCALSTACK mode targeting ${ENDPOINT}${NC}"
else
    AWS_CMD="aws --region $REGION"
    echo -e "${YELLOW}[WARNING] Running in LIVE AWS mode in region ${REGION}${NC}"
fi

# ==============================================================================
# Simulation 1: IAM Privilege Escalation (MITRE T1098)
# ==============================================================================
simulate_iam_escalation() {
    local USER_NAME="attacker-sim-user"
    echo -e "\n${YELLOW}[ATTACK 1: MITRE T1098] Simulating IAM Privilege Escalation...${NC}"

    echo -e "${CYAN}1. Creating rogue IAM user: ${USER_NAME}${NC}"
    $AWS_CMD iam create-user --user-name "$USER_NAME" > /dev/null 2>&1 || true

    echo -e "${CYAN}2. Generating active access key for compromised user${NC}"
    $AWS_CMD iam create-access-key --user-name "$USER_NAME" > /dev/null 2>&1 || true

    echo -e "${RED}3. Attaching AdministratorAccess policy to user (Trigger Event)${NC}"
    $AWS_CMD iam attach-user-policy \
        --user-name "$USER_NAME" \
        --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess"

    echo -e "${GREEN}[SUCCESS] Attack event dispatched. EventBridge will trigger 'revoke_iam_session.py'.${NC}"
}

# ==============================================================================
# Simulation 2: Defense Evasion - Disable CloudTrail (MITRE T1562.001)
# ==============================================================================
simulate_cloudtrail_tampering() {
    local TRAIL_NAME="soar-threat-detection-trail-dev"
    echo -e "\n${YELLOW}[ATTACK 2: MITRE T1562.001] Simulating CloudTrail Logging Tampering...${NC}"

    echo -e "${RED}1. Stopping CloudTrail logging on: ${TRAIL_NAME}${NC}"
    $AWS_CMD cloudtrail stop-logging --name "$TRAIL_NAME" > /dev/null 2>&1 || {
        echo -e "${YELLOW}[NOTE] Trail '${TRAIL_NAME}' not found or already stopped.${NC}"
    }

    echo -e "${GREEN}[SUCCESS] StopLogging triggered. EventBridge will dispatch incident alert.${NC}"
}

# ==============================================================================
# Simulation 3: S3 Data Exposure & Public Block Removal (MITRE T1530)
# ==============================================================================
simulate_s3_exposure() {
    local BUCKET_NAME="soar-sim-exposed-$RANDOM"
    echo -e "\n${YELLOW}[ATTACK 3: MITRE T1530] Simulating S3 Bucket Public Exposure...${NC}"

    echo -e "${CYAN}1. Provisioning private simulation bucket: ${BUCKET_NAME}${NC}"
    $AWS_CMD s3 mb "s3://${BUCKET_NAME}" > /dev/null 2>&1

    echo -e "${RED}2. Deleting Public Access Block (Trigger Event)${NC}"
    $AWS_CMD s3api delete-public-access-block --bucket "$BUCKET_NAME" > /dev/null 2>&1 || true

    echo -e "${RED}3. Applying public wildcard bucket policy (Allow Principal: *)${NC}"
    local PUBLIC_POLICY="{
        \"Version\": \"2012-10-17\",
        \"Statement\": [
            {
                \"Sid\": \"PublicReadGetObject\",
                \"Effect\": \"Allow\",
                \"Principal\": \"*\",
                \"Action\": \"s3:GetObject\",
                \"Resource\": \"arn:aws:s3:::${BUCKET_NAME}/*\"
            }
        ]
    }"
    $AWS_CMD s3api put-bucket-policy --bucket "$BUCKET_NAME" --policy "$PUBLIC_POLICY" > /dev/null 2>&1 || true

    echo -e "${GREEN}[SUCCESS] Public exposure triggered. EventBridge will trigger 'remediate_s3.py'.${NC}"
}

# ==============================================================================
# Simulation 4: Unauthorized Security Group Open Ingress (MITRE T1071 / T1190)
# ==============================================================================
simulate_ec2_ingress() {
    echo -e "\n${YELLOW}[ATTACK 4: MITRE T1071/T1190] Simulating EC2 Ingress Exposure (0.0.0.0/0)...${NC}"

    echo -e "${CYAN}1. Identifying available default Security Group${NC}"
    local SG_ID
    SG_ID=$($AWS_CMD ec2 describe-security-groups --query "SecurityGroups[0].GroupId" --output text 2>/dev/null || echo "")

    if [ -n "$SG_ID" ] && [ "$SG_ID" != "None" ]; then
        echo -e "${RED}2. Authorizing open ingress (0.0.0.0/0) on port 22 on SG: ${SG_ID}${NC}"
        $AWS_CMD ec2 authorize-security-group-ingress \
            --group-id "$SG_ID" \
            --protocol tcp \
            --port 22 \
            --cidr 0.0.0.0/0 > /dev/null 2>&1 || true
        echo -e "${GREEN}[SUCCESS] Unauthorized ingress opened. EventBridge will trigger 'isolate_ec2.py'.${NC}"
    else
        echo -e "${YELLOW}[NOTE] No EC2 Security Group found to modify. Launch or create an SG first.${NC}"
    fi
}

# Execution Controller
print_header

case "$TARGET_ATTACK" in
    iam)
        simulate_iam_escalation
        ;;
    trail)
        simulate_cloudtrail_tampering
        ;;
    s3)
        simulate_s3_exposure
        ;;
    ec2)
        simulate_ec2_ingress
        ;;
    all)
        simulate_iam_escalation
        simulate_cloudtrail_tampering
        simulate_s3_exposure
        simulate_ec2_ingress
        ;;
    *)
        echo -e "${RED}Unknown attack technique: $TARGET_ATTACK${NC}"
        usage
        ;;
esac

echo -e "\n${PURPLE}====================================================================${NC}"
echo -e "${GREEN}  All selected simulation events executed successfully!           ${NC}"
echo -e "${CYAN}  Inspect alert output via:                                        ${NC}"
echo -e "  - Docker logs: docker logs -f soar_webhook_receiver"
echo -e "  - CloudWatch:  aws --endpoint-url $ENDPOINT logs tail /aws/lambda/..."
echo -e "${PURPLE}====================================================================${NC}"
