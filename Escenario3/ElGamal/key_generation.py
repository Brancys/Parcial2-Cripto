from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes

# Generar llaves ElGamal
key = ElGamal.generate(1024, get_random_bytes)

# Guardar la llave privada en un archivo
with open("private_elgamal.pem", "wb") as f:
    f.write(key.export_key())

# Guardar la llave pública en un archivo
with open("public_elgamal.pem", "wb") as f:
    f.write(key.publickey().export_key())

print("Llaves ElGamal generadas y guardadas (1024 bits).")
