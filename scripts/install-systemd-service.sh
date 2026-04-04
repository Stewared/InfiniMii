#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="infinimii"
APP_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE_PATH="${APP_DIR}/deploy/systemd/${SERVICE_NAME}.service.template"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
ENV_PATH="/etc/default/${SERVICE_NAME}"
NODE_BIN="$(command -v node)"

if [[ ! -f "${TEMPLATE_PATH}" ]]; then
    echo "Missing systemd template at ${TEMPLATE_PATH}" >&2
    exit 1
fi

if [[ ! -f "${APP_DIR}/package.json" ]]; then
    echo "Missing package.json in ${APP_DIR}" >&2
    exit 1
fi

if [[ ! -f "${APP_DIR}/env.json" ]]; then
    echo "Missing env.json in ${APP_DIR}. Create it before installing the service." >&2
    exit 1
fi

if [[ ! -d "${APP_DIR}/node_modules" ]]; then
    echo "Missing node_modules in ${APP_DIR}. Run npm install before installing the service." >&2
    exit 1
fi

if [[ -z "${NODE_BIN}" ]]; then
    echo "node is not installed or not on PATH." >&2
    exit 1
fi

install -d -m 0755 /etc/default

if [[ ! -f "${ENV_PATH}" ]]; then
    install -m 0644 /dev/null "${ENV_PATH}"
fi

sed \
    -e "s|__APP_DIR__|${APP_DIR}|g" \
    -e "s|__NODE_BIN__|${NODE_BIN}|g" \
    "${TEMPLATE_PATH}" > "${UNIT_PATH}"

chmod 0644 "${UNIT_PATH}"
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}.service" >/dev/null

if systemctl is-active --quiet "${SERVICE_NAME}.service"; then
    systemctl restart "${SERVICE_NAME}.service"
else
    systemctl start "${SERVICE_NAME}.service"
fi

echo "Installed and started ${SERVICE_NAME}.service"
systemctl --no-pager --full status "${SERVICE_NAME}.service"
