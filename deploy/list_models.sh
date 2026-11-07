#!/usr/bin/env bash
# Print the model ids your Vultr Serverless Inference key can use; set one as VULTR_INFERENCE_MODEL.
set -euo pipefail
: "${VULTR_INFERENCE_API_KEY:?export VULTR_INFERENCE_API_KEY first}"
curl -sS https://api.vultrinference.com/v1/models -H "Authorization: Bearer $VULTR_INFERENCE_API_KEY" | python3 -m json.tool
