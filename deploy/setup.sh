#!/usr/bin/env bash
# Provision a fresh Ubuntu 22.04/24.04 Vultr Cloud Compute instance and run Traceback behind Caddy (auto-HTTPS).
# usage (as root):  DOMAIN=traceback.example.com VULTR_INFERENCE_API_KEY=... bash deploy/setup.sh
# No domain? Omit DOMAIN: Traceback is served over plain HTTP on :80 for the hackathon demo.
set -euo pipefail

APP_DIR=/opt/traceback
apt-get update -y
apt-get install -y python3 python3-venv python3-pip docker.io caddy unzip rsync
systemctl enable --now docker

mkdir -p "$APP_DIR"
rsync -a --exclude .git --exclude __pycache__ "$(dirname "$0")/../" "$APP_DIR/"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt"

# Pre-pull the sandbox image so the first investigation is fast and the worker never needs network.
docker pull "${SANDBOX_IMAGE:-python:3.12-slim}"

# Dedicated unprivileged service user that may talk to docker (the worker itself runs as uid 1000 with no caps/network).
id -u traceback &>/dev/null || useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin traceback
usermod -aG docker traceback
chown -R traceback:traceback "$APP_DIR"

cat > /etc/traceback.env <<EOF
SANDBOX_DRIVER=docker
SANDBOX_IMAGE=${SANDBOX_IMAGE:-python:3.12-slim}
VULTR_INFERENCE_API_KEY=${VULTR_INFERENCE_API_KEY:-}
VULTR_INFERENCE_MODEL=${VULTR_INFERENCE_MODEL:-llama-3.3-70b-instruct-fp8}
HOST=127.0.0.1
PORT=8080
EOF
chmod 600 /etc/traceback.env   # key lives with the control plane only; never passed into a worker

install -m 644 "$APP_DIR/deploy/traceback.service" /etc/systemd/system/traceback.service
systemctl daemon-reload
systemctl enable --now traceback

if [ -n "${DOMAIN:-}" ]; then SITE="$DOMAIN"; else SITE=":80"; fi
cat > /etc/caddy/Caddyfile <<EOF
$SITE {
    request_body { max_size 60MB }
    reverse_proxy 127.0.0.1:8080
}
EOF
systemctl restart caddy
echo "Traceback is up: ${DOMAIN:+https://$DOMAIN}${DOMAIN:-http://$(curl -s ifconfig.me)}"
echo "Verify: curl -s localhost:8080/api/health   (driver should be 'docker')"
