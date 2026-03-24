#!/bin/bash
set -e

cd /home/deployer/deploy

COMMIT_HASH=$(curl -s https://api.github.com/repos/latonis/content-server/commits/main | grep '"sha"' | head -1 | cut -d'"' -f4 | cut -c1-7)

# Deploy with commit hash
COMMIT_HASH=$COMMIT_HASH docker compose up -d
