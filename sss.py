# Python3.12.3

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from secretsharing import SecretSharer

# Generate Ed25519 private key
private_key = Ed25519PrivateKey.generate()

# Print private key
# print(private_key.private_bytes_raw())

# Serialize private key to PEM format
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Convert private key PEM to hex string
private_key_hex = pem.hex()

# Print private key pem hex
print("\nPrivate key hex: ", private_key_hex, '\n')

# Define SSS parameters
total_shares = 5
threshold = 3

# Split the private key into shares
shares = SecretSharer.split_secret(private_key_hex, threshold, total_shares)

# Display all shares
for i, share in enumerate(shares):
    print(f"Share {i+1}: {share}\n")

# Reconstruct the private key from shares (using threshold number of shares)
# This uses the first threshold number of shares 
reconstructed_key_hex = SecretSharer.recover_secret(shares[:threshold])

# Print reconstructed key hex
print("Reconstucted key hex: ", reconstructed_key_hex)

# Convert hex string back to PEM format
reconstructed_pem = bytes.fromhex(reconstructed_key_hex)

# Deserialize PEM back to private key object
reconstructed_private_key = serialization.load_pem_private_key(
    reconstructed_pem,
    password=None
)

# Check if the original and reconstructed private keys are the same
assert pem == reconstructed_pem, "The reconstructed key does not match the original key."

print("\nOriginal and reconstructed keys match.")
