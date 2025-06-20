#!/bin/bash
echo "Starting SSL certificate generation..."

# --- Load .env file (if it exists) ---
ENV_FILE=".env"
if [ -f "$ENV_FILE" ]; then
  echo "loading environment variables from $ENV_FILE..."
  set -a
  source "$ENV_FILE"
  set +a
else
  echo "No .env file found at $ENV_FILE. Using default values."
fi

# --- Time Synchronization Check ---
echo "Performing time synchronization check..."
HOST_TIME=$(date +%s)
NTP_SERVER="time.cloudflare.com" # Using Cloudflare's NTP server

# Attempt to get external time using curl, preferring HTTPS for 'Date' header
EXTERNAL_TIME_STR=$(curl -s --head -m 5 --retry 3 --retry-max-time 10 https://"$NTP_SERVER" | grep -i Date: | awk '{print $NF,$5,$6,$7,$8,$9}')
EXTERNAL_TIME=$(date -d "$EXTERNAL_TIME_STR" +%s 2>/dev/null)

if [ -z "$EXTERNAL_TIME" ]; then
  echo "WARNING: Could not fetch external time using curl. Please ensure 'curl' is installed and you have internet access."
  echo "Proceeding with local system time. Ensure your host machine's clock is accurate!"
else
  TIME_DIFF=$((HOST_TIME - EXTERNAL_TIME))
  ABS_TIME_DIFF=$(TIME_DIFF#-) #Absolute value

  # Allow for a small difference (e.g., 5 seconds)
  if [ "$ABS_TIME_DIFF" -gt 5 ]; then
    echo "WARNING: Significant time difference detected!"
    echo "  Your host system time: $(date -d @$HOST_TIME)"
    echo "  External NTP time ($NTP_SERVER): $(date -d @$EXTERNAL_TIME)"
    echo "  Difference: $TIME_DIFF seconds. This can cause certificate validation issues."
    echo "  Please synchronize your host machine's clock (e.g., 'sudo ntpdate -s time.nist.gov' or system settings)."
  else
    echo "Host system time appears to be synchronized with external NTP server."
  fi
fi
echo "--- End Time Synchronization Check ---"

# Create the certs directory if it doesn't exist
mkdir -p "$SSL_CERT_DIR"

# Navigate into the certs directory
cd "$SSL_CERT_DIR" || { echo "Failed to change to directory $CERT_DIR. Exiting."; exit 1; }


echo "using certificate details:"
echo "  Common Name: $SERVER_DOMAIN_NAME"
echo "  Subject Alt Name IP: $SERVER_STATIC_IP"
echo "  Days Valid: $SSL_CERT_DAYS_VALID"
echo "  Location: $SSL_CERT_LOCALITY, $SSL_CERT_STATE, $SSL_CERT_COUNTRY"
echo "  Organization: $SSL_CERT_ORGANIZATION"

# Create a temporary OpenSSL configuration file for SANs
OPENSSL_CONF="openssl.cnf"
cat > "$OPENSSL_CONF" <<-EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no
[req_distinguished_name]
C = $SSL_CERT_COUNTRY
ST = $SSL_CERT_STATE
L = $SSL_CERT_LOCALITY
O = $SSL_CERT_ORGANIZATION
CN = $SERVER_DOMAIN_NAME

[v3_req]
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $SERVER_DOMAIN_NAME
IP.1 = $SERVER_IP_ADDRESS
EOF

# 1. Generate a Private Key for your server
# Using 2048-bit RSA key
echo "Generating server private key (server.key)..."
openssl genrsa -out server.key 2048

# Check if key generation was successful
if [ $? -ne 0 ]; then
  echo "ERROR: Failed to generate server.key. Exiting."
  exit 1
fi
echo "server.key generated."

# 2. Generate a Self-Signed Certificate for your server
# -x509: Creates a self-signed certificate.
# -days: Number of days the certificate is valid for.
# -nodes: No DES encryption (no passphrase for the eky). This is simpler for dev, but less secure.
# -config: Use the custom OpenSSL configuration file for SANs.
echo "Generating self-signed server certificate (server.crt)..."
openssl req -new -x509 -key server.key -out server.crt -days "$SSL_CERT_DAYS_VALID" -nodes -config "$OPENSSL_CONF"

# Check if certificate generation was successful
if [ $? -ne 0 ]; then
  echo "ERROR: Failed to generate server.crt. Exiting."
  exit 1
fi
echo "server.crt generated."

# Verify the certificate's Common Name (CN) and Subject Alternative Names (SANs)
echo "Verifying certificate details:"
openssl x509 -in server.crt -noout -subject | grep "CN="
openssl x509 -in server.crt -noout -ext subjectAltName
openssl x509 -in server.crt -noout -dates

# Clean up the temporary OpenSSL config file
rm "$OPENSSL_CONF"

# Return to the project root directory
cd ..

echo "SSL certificate generation complete."
echo "Certificates are located in the '$SSL_CERT_DIR' directory."