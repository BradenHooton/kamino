#!/bin/bash
# scripts/init-template.sh
OLD_NAME="kamino"
NEW_NAME=$1

if [ -z "$NEW_NAME" ]; then
  echo "Usage: ./scripts/init-template.sh <new-app-name>"
  exit 1
fi

# Replace in all relevant files
find . -type f \( -name "*.go" -o -name "*.md" -o -name "docker-compose.yml" -o -name "Dockerfile" \) \
  -exec sed -i '' "s/$OLD_NAME/$NEW_NAME/g" {} +

echo "Renamed $OLD_NAME to $NEW_NAME"