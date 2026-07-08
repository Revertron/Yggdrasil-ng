#!/bin/sh

set -e

CONF_DIR="/data"

if [ ! -f "${CONF_DIR}/config.toml" ]; then
  echo "generate ${CONF_DIR}/config.toml"
  (umask 037 && yggdrasil --genconf > "${CONF_DIR}/config.toml")
fi

exec yggdrasil --config "${CONF_DIR}/config.toml"
