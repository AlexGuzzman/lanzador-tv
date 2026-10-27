#!/bin/sh
# Junta tweetnacl y el puente en un solo archivo, que es lo que TizenBrew descarga y ejecuta.
cd "$(dirname "$0")"
{
  echo "// Generado por build.sh. Incluye tweetnacl 1.0.3 (dominio público, ver service/vendor/tweetnacl-LICENSE)."
  echo "var nacl = (function () { var module = { exports: {} };"
  cat service/vendor/nacl-fast.js
  echo "return module.exports; })();"
  cat service/bridge.js
} > service.js
echo "service.js: $(wc -c < service.js) bytes"
