# HashiCorp Vault Certificate Authentication Guide

This guide demonstrates how to authenticate to HashiCorp Vault using client certificates and retrieve secrets using curl commands.

## Prerequisites

- HashiCorp Vault server running and accessible
- Client certificate (`client.crt`)
- Private key for the certificate (`client.key`)
- Certificate Authority certificate (`ca.crt`)
- `curl` and `jq` installed on your system
- Certificate authentication method enabled in Vault
- A certificate role configured in Vault

## File Structure

Ensure your certificates are organized as follows:
```
certs/
├── client.crt    # Your client certificate
├── client.key    # Private key for the client certificate
└── ca.crt        # Certificate Authority certificate
```

## Step 1: Authenticate with Certificate

First, authenticate to Vault using your certificate:

```bash
curl --cert certs/client.crt \
     --key certs/client.key \
     --cacert certs/ca.crt \
     -X POST \
     -d '{"name": "web-cert"}' \
     https://vault.local:8200/v1/auth/cert/login
```

**Response example:**
```json
{
  "auth": {
    "client_token": "hvs.CAESIJ...",
    "accessor": "accessor_id",
    "policies": ["default", "web-policy"],
    "token_policies": ["default", "web-policy"],
    "lease_duration": 2764800,
    "renewable": true
  }
}
```

## Step 2: Extract Token for Manual Use

To extract just the token for subsequent requests:

```bash
TOKEN=$(curl -s --cert certs/client.crt \
             --key certs/client.key \
             --cacert certs/ca.crt \
             -X POST \
             -d '{"name": "web-cert"}' \
             https://vault.local:8200/v1/auth/cert/login | jq -r '.auth.client_token')
```

## Step 3: Retrieve Secrets

### Method 1: Using Extracted Token

```bash
curl --cert certs/client.crt \
     --key certs/client.key \
     --cacert certs/ca.crt \
     -H "X-Vault-Token: $TOKEN" \
     https://vault.local:8200/v1/secret/data/your-secret-path
```

### Method 2: One-Liner Command (Recommended)

This combines authentication and secret retrieval in a single command:

```bash
curl --cert certs/client.crt \
     --key certs/client.key \
     --cacert certs/ca.crt \
     -H "X-Vault-Token: $(curl -s --cert certs/client.crt --key certs/client.key --cacert certs/ca.crt -X POST -d '{\"name\": \"web-cert\"}' https://vault.local:8200/v1/auth/cert/login | jq -r '.auth.client_token')" \
     https://vault.local:8200/v1/secret/data/your-secret-path
```

## Command Breakdown

### Certificate Parameters
- `--cert certs/client.crt`: Your client certificate for authentication
- `--key certs/client.key`: Private key corresponding to your client certificate
- `--cacert certs/ca.crt`: CA certificate to verify Vault server's identity

### Authentication Payload
- `{"name": "web-cert"}`: Specifies the certificate role name configured in Vault
- Replace `"web-cert"` with your actual role name

### Secret Path Examples
- **KV v2 engine**: `/v1/secret/data/myapp/database`
- **KV v1 engine**: `/v1/secret/myapp/database`
- **Custom mount**: `/v1/custom-secrets/data/path`

## Practical Examples

### Example 1: Database Credentials
```bash
curl --cert certs/client.crt \
     --key certs/client.key \
     --cacert certs/ca.crt \
     -H "X-Vault-Token: $(curl -s --cert certs/client.crt --key certs/client.key --cacert certs/ca.crt -X POST -d '{\"name\": \"web-cert\"}' https://vault.local:8200/v1/auth/cert/login | jq -r '.auth.client_token')" \
     https://vault.local:8200/v1/secret/data/myapp/database
```

### Example 2: API Keys
```bash
curl --cert certs/client.crt \
     --key certs/client.key \
     --cacert certs/ca.crt \
     -H "X-Vault-Token: $(curl -s --cert certs/client.crt --key certs/client.key --cacert certs/ca.crt -X POST -d '{\"name\": \"web-cert\"}' https://vault.local:8200/v1/auth/cert/login | jq -r '.auth.client_token')" \
     https://vault.local:8200/v1/secret/data/api-keys/external-service
```

## Response Format

Successful secret retrieval returns JSON like this:

```json
{
  "data": {
    "data": {
      "username": "myuser",
      "password": "mypassword"
    },
    "metadata": {
      "created_time": "2024-01-01T12:00:00Z",
      "version": 1
    }
  }
}
```

## Extracting Specific Values

### Get specific secret values:
```bash
# Get username
curl --cert certs/client.crt \
     --key certs/client.key \
     --cacert certs/ca.crt \
     -H "X-Vault-Token: $(curl -s --cert certs/client.crt --key certs/client.key --cacert certs/ca.crt -X POST -d '{\"name\": \"web-cert\"}' https://vault.local:8200/v1/auth/cert/login | jq -r '.auth.client_token')" \
     https://vault.local:8200/v1/secret/data/myapp/database | jq -r '.data.data.username'
```

## Troubleshooting

### Common Issues

1. **Certificate not found**
   ```
   curl: (58) could not load client certificate from certs/client.crt
   ```
   - Verify certificate files exist and have proper permissions
   - Check file paths are correct

2. **Authentication failed**
   ```
   {"errors":["invalid certificate or no client certificate supplied"]}
   ```
   - Ensure certificate role exists in Vault
   - Verify certificate is not expired
   - Check CA certificate matches Vault configuration

3. **Permission denied**
   ```
   {"errors":["1 error occurred: * permission denied"]}
   ```
   - Verify certificate role has required policies
   - Check secret path permissions

4. **jq command not found**
   ```
   bash: jq: command not found
   ```
   - Install jq: `sudo apt-get install jq` (Ubuntu/Debian) or `brew install jq` (macOS)

### Debug Commands

Test authentication only:
```bash
curl -s --cert certs/client.crt --key certs/client.key --cacert certs/ca.crt -X POST -d '{"name": "web-cert"}' https://vault.local:8200/v1/auth/cert/login
```

Check certificate details:
```bash
openssl x509 -in certs/client.crt -text -noout
```

Verify certificate expiration:
```bash
openssl x509 -in certs/client.crt -enddate -noout
```

## Security Best Practices

1. **File Permissions**: Protect private keys with restrictive permissions
   ```bash
   chmod 600 certs/client.key
   chmod 644 certs/client.crt
   chmod 644 certs/ca.crt
   ```

2. **Certificate Rotation**: Regularly rotate certificates before expiration

3. **Least Privilege**: Configure certificate roles with minimal required permissions

4. **Token Handling**: Don't log or expose tokens in scripts or command history

5. **Network Security**: Use TLS and verify Vault server certificates

## Alternative Approaches

### Vault Agent
For production use, consider using Vault Agent for automatic token management:

```hcl
# vault-agent.hcl
auto_auth {
  method "cert" {
    config = {
      name = "web-cert"
      ca_cert = "certs/ca.crt"
      client_cert = "certs/client.crt"
      client_key = "certs/client.key"
    }
  }
  sink "file" {
    config = {
      path = "/tmp/vault-token"
    }
  }
}
```

### Shell Function
Create a reusable shell function:

```bash
vault_get_secret() {
    local secret_path=$1
    curl --cert certs/client.crt \
         --key certs/client.key \
         --cacert certs/ca.crt \
         -H "X-Vault-Token: $(curl -s --cert certs/client.crt --key certs/client.key --cacert certs/ca.crt -X POST -d '{\"name\": \"web-cert\"}' https://vault.local:8200/v1/auth/cert/login | jq -r '.auth.client_token')" \
         "https://vault.local:8200/v1/secret/data/$secret_path"
}

# Usage
vault_get_secret "myapp/database"
```

This guide provides a complete workflow for using certificate authentication with HashiCorp Vault via curl commands.