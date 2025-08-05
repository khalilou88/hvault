# HashiCorp Vault Authentication with JKS Keystore Guide

This guide demonstrates how to authenticate to HashiCorp Vault using certificates stored in a Java KeyStore (JKS) file and retrieve secrets using curl commands.

## Prerequisites

- HashiCorp Vault server running and accessible
- JKS keystore file containing client certificate and private key
- Java KeyStore password
- Certificate Authority certificate (may be in JKS or separate file)
- `keytool`, `openssl`, `curl`, and `jq` installed on your system
- Certificate authentication method enabled in Vault
- A certificate role configured in Vault

## Step 1: Extract Certificates from JKS

### Convert JKS to PKCS12 Format

First, convert your JKS file to PKCS12 format (easier to work with):

```bash
keytool -importkeystore \
        -srckeystore client.jks \
        -srcstoretype JKS \
        -srcstorepass YOUR_JKS_PASSWORD \
        -destkeystore client.p12 \
        -deststoretype PKCS12 \
        -deststorepass YOUR_P12_PASSWORD \
        -srcalias YOUR_CERT_ALIAS
```

### Extract Client Certificate

```bash
# Extract client certificate from PKCS12
openssl pkcs12 -in client.p12 -out client.crt -clcerts -nokeys -passin pass:YOUR_P12_PASSWORD

# Or directly from JKS (alternative method)
keytool -export -alias YOUR_CERT_ALIAS -file client.crt -keystore client.jks -storepass YOUR_JKS_PASSWORD -rfc
```

### Extract Private Key

```bash
# Extract private key from PKCS12
openssl pkcs12 -in client.p12 -out client.key -nocerts -nodes -passin pass:YOUR_P12_PASSWORD
```

### Extract CA Certificate (if in JKS)

```bash
# List aliases to find CA certificate
keytool -list -keystore client.jks -storepass YOUR_JKS_PASSWORD

# Export CA certificate
keytool -export -alias CA_CERT_ALIAS -file ca.crt -keystore client.jks -storepass YOUR_JKS_PASSWORD -rfc
```

## Step 2: One-Time Setup Script

Create a script to automate the certificate extraction:

```bash
#!/bin/bash

# extract-certs.sh
JKS_FILE="client.jks"
JKS_PASSWORD="your_jks_password"
P12_PASSWORD="temp_p12_password"
CERT_ALIAS="your_cert_alias"
CA_ALIAS="your_ca_alias"

# Create certs directory
mkdir -p certs

echo "Converting JKS to PKCS12..."
keytool -importkeystore \
        -srckeystore "$JKS_FILE" \
        -srcstoretype JKS \
        -srcstorepass "$JKS_PASSWORD" \
        -destkeystore certs/client.p12 \
        -deststoretype PKCS12 \
        -deststorepass "$P12_PASSWORD" \
        -srcalias "$CERT_ALIAS"

echo "Extracting client certificate..."
openssl pkcs12 -in certs/client.p12 -out certs/client.crt -clcerts -nokeys -passin pass:"$P12_PASSWORD"

echo "Extracting private key..."
openssl pkcs12 -in certs/client.p12 -out certs/client.key -nocerts -nodes -passin pass:"$P12_PASSWORD"

echo "Extracting CA certificate..."
keytool -export -alias "$CA_ALIAS" -file certs/ca.crt -keystore "$JKS_FILE" -storepass "$JKS_PASSWORD" -rfc

# Set proper permissions
chmod 600 certs/client.key
chmod 644 certs/client.crt certs/ca.crt

# Clean up temporary file
rm certs/client.p12

echo "Certificate extraction complete!"
echo "Files created:"
echo "  - certs/client.crt (Client certificate)"
echo "  - certs/client.key (Private key)"
echo "  - certs/ca.crt (CA certificate)"
```

Run the script:
```bash
chmod +x extract-certs.sh
./extract-certs.sh
```

## Step 3: Authenticate and Retrieve Secrets

Once certificates are extracted, use the same commands as the PEM certificate guide:

### One-Liner Command
```bash
curl --cert certs/client.crt \
     --key certs/client.key \
     --cacert certs/ca.crt \
     -H "X-Vault-Token: $(curl -s --cert certs/client.crt --key certs/client.key --cacert certs/ca.crt -X POST -d '{\"name\": \"web-cert\"}' https://vault.local:8200/v1/auth/cert/login | jq -r '.auth.client_token')" \
     https://vault.local:8200/v1/secret/data/your-secret-path
```

## Alternative: Direct JKS Usage (Advanced)

For systems where you cannot extract certificates, you can use Java-based tools or create a wrapper.

### Using Java HttpsURLConnection

Create a Java utility to handle JKS authentication:

```bash
# java-vault-client.java
import java.io.*;
import java.net.URL;
import java.security.KeyStore;
import javax.net.ssl.*;
import java.nio.charset.StandardCharsets;

public class VaultJKSClient {
    public static void main(String[] args) throws Exception {
        String jksPath = args[0];
        String jksPassword = args[1];
        String vaultUrl = args[2];
        String roleName = args[3];
        String secretPath = args[4];
        
        // Load JKS keystore
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(new FileInputStream(jksPath), jksPassword.toCharArray());
        
        // Initialize SSL context
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keyStore, jksPassword.toCharArray());
        
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(keyStore);
        
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        
        // Authenticate
        String token = authenticate(sslContext, vaultUrl, roleName);
        
        // Get secret
        String secret = getSecret(sslContext, vaultUrl, token, secretPath);
        System.out.println(secret);
    }
    
    private static String authenticate(SSLContext sslContext, String vaultUrl, String roleName) throws Exception {
        URL url = new URL(vaultUrl + "/v1/auth/cert/login");
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setSSLSocketFactory(sslContext.getSocketFactory());
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/json");
        
        String payload = "{\"name\":\"" + roleName + "\"}";
        conn.getOutputStream().write(payload.getBytes(StandardCharsets.UTF_8));
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        
        // Extract token (simple JSON parsing)
        String responseStr = response.toString();
        int tokenStart = responseStr.indexOf("\"client_token\":\"") + 16;
        int tokenEnd = responseStr.indexOf("\"", tokenStart);
        return responseStr.substring(tokenStart, tokenEnd);
    }
    
    private static String getSecret(SSLContext sslContext, String vaultUrl, String token, String secretPath) throws Exception {
        URL url = new URL(vaultUrl + "/v1/secret/data/" + secretPath);
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setSSLSocketFactory(sslContext.getSocketFactory());
        conn.setRequestProperty("X-Vault-Token", token);
        
        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        
        return response.toString();
    }
}
```

Compile and use:
```bash
javac VaultJKSClient.java
java VaultJKSClient client.jks password https://vault.local:8200 web-cert myapp/database
```

## Practical Examples

### Example 1: Complete Workflow with JKS

```bash
#!/bin/bash

# Configuration
JKS_FILE="client.jks"
JKS_PASSWORD="mypassword"
CERT_ALIAS="mycert"
CA_ALIAS="myca"
VAULT_URL="https://vault.local:8200"
ROLE_NAME="web-cert"
SECRET_PATH="myapp/database"

# Extract certificates (one-time setup)
if [ ! -d "certs" ]; then
    echo "Extracting certificates from JKS..."
    mkdir -p certs
    
    # Convert to PKCS12
    keytool -importkeystore \
            -srckeystore "$JKS_FILE" \
            -srcstoretype JKS \
            -srcstorepass "$JKS_PASSWORD" \
            -destkeystore certs/temp.p12 \
            -deststoretype PKCS12 \
            -deststorepass temppass \
            -srcalias "$CERT_ALIAS"
    
    # Extract certificates
    openssl pkcs12 -in certs/temp.p12 -out certs/client.crt -clcerts -nokeys -passin pass:temppass
    openssl pkcs12 -in certs/temp.p12 -out certs/client.key -nocerts -nodes -passin pass:temppass
    keytool -export -alias "$CA_ALIAS" -file certs/ca.crt -keystore "$JKS_FILE" -storepass "$JKS_PASSWORD" -rfc
    
    # Set permissions and cleanup
    chmod 600 certs/client.key
    chmod 644 certs/client.crt certs/ca.crt
    rm certs/temp.p12
    
    echo "Certificate extraction complete!"
fi

# Retrieve secret
echo "Retrieving secret from Vault..."
RESULT=$(curl -s --cert certs/client.crt \
              --key certs/client.key \
              --cacert certs/ca.crt \
              -H "X-Vault-Token: $(curl -s --cert certs/client.crt --key certs/client.key --cacert certs/ca.crt -X POST -d "{\"name\": \"$ROLE_NAME\"}" $VAULT_URL/v1/auth/cert/login | jq -r '.auth.client_token')" \
              "$VAULT_URL/v1/secret/data/$SECRET_PATH")

echo "Secret retrieved:"
echo "$RESULT" | jq '.'
```

### Example 2: Extract Specific Values

```bash
# Get database username from JKS-based authentication
DB_USERNAME=$(curl -s --cert certs/client.crt \
                   --key certs/client.key \
                   --cacert certs/ca.crt \
                   -H "X-Vault-Token: $(curl -s --cert certs/client.crt --key certs/client.key --cacert certs/ca.crt -X POST -d '{\"name\": \"web-cert\"}' https://vault.local:8200/v1/auth/cert/login | jq -r '.auth.client_token')" \
                   https://vault.local:8200/v1/secret/data/myapp/database | jq -r '.data.data.username')

echo "Database Username: $DB_USERNAME"
```

## Troubleshooting JKS-Specific Issues

### Common JKS Problems

1. **Incorrect alias name**
   ```bash
   # List all aliases in JKS
   keytool -list -keystore client.jks -storepass YOUR_PASSWORD
   ```

2. **Wrong keystore password**
   ```
   keytool error: java.io.IOException: Keystore was tampered with, or password was incorrect
   ```
   - Verify the JKS password is correct

3. **Certificate extraction fails**
   ```bash
   # Verify JKS contents
   keytool -list -v -keystore client.jks -storepass YOUR_PASSWORD
   ```

4. **Missing private key in JKS**
   ```
   keytool error: Cannot recover key
   ```
   - Ensure the JKS contains both certificate and private key
   - Use `-keypass` if key password differs from store password

### Debugging Commands

Check JKS contents:
```bash
keytool -list -v -keystore client.jks -storepass YOUR_PASSWORD
```

Verify extracted certificate:
```bash
openssl x509 -in certs/client.crt -text -noout
```

Test certificate and key match:
```bash
openssl x509 -noout -modulus -in certs/client.crt | openssl md5
openssl rsa -noout -modulus -in certs/client.key | openssl md5
```

## Security Considerations

1. **JKS Password Security**: Store JKS passwords securely, consider using environment variables
   ```bash
   export JKS_PASSWORD="your_password"
   ```

2. **Temporary Files**: Clean up temporary PKCS12 files after extraction

3. **File Permissions**: Ensure extracted private keys have restricted permissions (600)

4. **Certificate Rotation**: Plan for certificate renewal in JKS files

5. **Backup**: Keep secure backups of your JKS files

## Shell Functions for Reuse

```bash
# Add to ~/.bashrc or ~/.zshrc

extract_jks_certs() {
    local jks_file=$1
    local jks_password=$2
    local cert_alias=$3
    local ca_alias=$4
    
    mkdir -p certs
    
    # Convert and extract
    keytool -importkeystore -srckeystore "$jks_file" -srcstoretype JKS -srcstorepass "$jks_password" \
            -destkeystore certs/temp.p12 -deststoretype PKCS12 -deststorepass temppass -srcalias "$cert_alias"
    
    openssl pkcs12 -in certs/temp.p12 -out certs/client.crt -clcerts -nokeys -passin pass:temppass
    openssl pkcs12 -in certs/temp.p12 -out certs/client.key -nocerts -nodes -passin pass:temppass
    keytool -export -alias "$ca_alias" -file certs/ca.crt -keystore "$jks_file" -storepass "$jks_password" -rfc
    
    chmod 600 certs/client.key
    chmod 644 certs/client.crt certs/ca.crt
    rm certs/temp.p12
}

vault_get_secret_jks() {
    local secret_path=$1
    local role_name=${2:-"web-cert"}
    local vault_url=${3:-"https://vault.local:8200"}
    
    curl -s --cert certs/client.crt \
         --key certs/client.key \
         --cacert certs/ca.crt \
         -H "X-Vault-Token: $(curl -s --cert certs/client.crt --key certs/client.key --cacert certs/ca.crt -X POST -d "{\"name\": \"$role_name\"}" $vault_url/v1/auth/cert/login | jq -r '.auth.client_token')" \
         "$vault_url/v1/secret/data/$secret_path"
}

# Usage:
# extract_jks_certs client.jks mypassword mycert myca
# vault_get_secret_jks myapp/database
```

This guide provides a complete workflow for using JKS keystores with HashiCorp Vault certificate authentication, including certificate extraction, troubleshooting, and practical examples.