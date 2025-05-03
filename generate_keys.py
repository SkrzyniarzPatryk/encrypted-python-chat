# generate_keys.py
import getpass
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Wygeneruj klucz prywatny
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Poproś o hasło do zaszyfrowania klucza prywatnego
password = getpass.getpass("Podaj hasło do ochrony klucza prywatnego serwera: ").encode('utf-8')

# Zapisz klucz prywatny (zaszyfrowany PEM)
pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(password)
)
with open("server_private_key.pem", "wb") as f:
    f.write(pem_private)

print("Zapisano zaszyfrowany klucz prywatny do: server_private_key.pem")

# Zapisz klucz publiczny (PEM)
pem_public = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
with open("server_public_key.pem", "wb") as f:
    f.write(pem_public)

print("Zapisano klucz publiczny do: server_public_key.pem")
