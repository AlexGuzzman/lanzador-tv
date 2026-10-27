#!/bin/sh
# Junta tweetnacl y el puente en un solo archivo, que es lo que TizenBrew descarga y ejecuta.
cd "$(dirname "$0")"
VERSION=$(sed -n 's/.*"version": *"\([0-9.]*\)".*/\1/p' package.json)
[ -n "$VERSION" ] || { echo "package.json no tiene versión"; exit 1; }
{
  echo "// Generado por build.sh. Incluye tweetnacl 1.0.3 (dominio público, ver service/vendor/tweetnacl-LICENSE)."
  echo "var nacl = (function () { var module = { exports: {} };"
  cat service/vendor/nacl-fast.js
  echo "return module.exports; })();"
  # La versión del puente sale de package.json (la que muestra TizenBrew), así no se separan
  sed "s/^var VERSION = .*/var VERSION = '$VERSION';/" service/bridge.js
} > service.js
echo "service.js: $(wc -c < service.js) bytes, versión $VERSION"
