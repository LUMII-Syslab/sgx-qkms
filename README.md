# sgx-qkms

## Generating ETSI GS QKD 014 API handlers

```bash
# 0) Prereqs
sudo apt-get update
sudo apt-get install -y curl default-jre

# 1) Install nvm (if you don't already have it)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.4/install.sh | bash

export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"

# 2) Install Node (LTS) via nvm
nvm install --lts
nvm use --lts
node -v
npm -v

# 3) Install OpenAPI Generator CLI
npm install -g @openapitools/openapi-generator-cli

# 4) Sanity check
openapi-generator-cli version
openapi-generator-cli help

# 5) Generate API handlers
openapi-generator-cli generate \
  -i api/etsigsqkd014.yaml \
  -g rust-server \
  -o api/qkd014-server-gen \
  --additional-properties=packageName=qkd014_server_gen
```
