from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
import json

# Generar llaves ElGamal
key = ElGamal.generate(1024, get_random_bytes)

public_key = key.publickey()

private_key_data = {
    'p': hex(key.p),  
    'g': hex(key.g),
    'y': hex(key.y),
    'x': hex(key.x)   # 'x' es la clave privada
}

public_key_data = {
    'p': hex(public_key.p), 
    'g': hex(public_key.g),
    'y': hex(public_key.y)   # 'y' es la clave pública
}

# Guardar la clave privada
with open("Escenario3/ElGamal/keys/sk.json", "w") as f:
    json.dump(private_key_data, f)

# Guardar la clave pública
with open("Escenario3/ElGamal/keys/pk.json", "w") as f:
    json.dump(public_key_data, f)

print(f"Llaves ElGamal generadas y guardadas en {current_directory} (1024 bits).")
