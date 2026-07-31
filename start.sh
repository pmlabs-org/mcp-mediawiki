#!/bin/sh
set -e

BACKEND_PORT="${BACKEND_PORT:-8081}"

echo "Starting MediaWiki MCP backend on port ${BACKEND_PORT}..."
PORT="${BACKEND_PORT}" node dist/index.js &

echo "Waiting for backend to be ready..."
i=0
while [ "$i" -lt 30 ]; do
  node -e "require('http').get('http://localhost:${BACKEND_PORT}/health', function(r){process.exit(r.statusCode===200?0:1)}).on('error',function(){process.exit(1)})" 2>/dev/null && break
  sleep 1
  i=$((i+1))
done

echo "Starting OAuth proxy on port ${PORT:-8080}..."
exec node oauth-proxy.cjs
