# Implementación del Parcial 2 de Criptografía

Este proyecto contiene la implementación de tres escenarios de criptografía utilizando Python y varias bibliotecas criptográficas como **PyCryptodome**. Cada escenario explora diferentes algoritmos de cifrado y conceptos fundamentales de criptografía, como el intercambio de llaves y el cifrado asimétrico y simétrico.

## Escenario 1: Intercambio de Llaves Diffie-Hellman

### Descripción
Se implementa el protocolo de **intercambio de llaves Diffie-Hellman** sobre el grupo cíclico multiplicativo \(\mathbb{F}_p^*\). Los parámetros del grupo se leen desde un archivo JSON llamado `parameters.json`, que contiene los valores de \( p \), \( q \) y \( g \).

### Proceso
1. **Cliente y servidor** acuerdan los parámetros \( p \), \( g \), y \( q \) y ejecutan el protocolo Diffie-Hellman.
2. **Generación del secreto compartido**: Ambos calculan el secreto compartido y lo convierten en una llave simétrica utilizando una función KDF (SHA-256).
3. **Cifrado y descifrado**: Una vez que ambos tienen el mismo secreto compartido, lo usan para cifrar la comunicación mediante el cifrador **Salsa20**.

### Archivos
- `client.py`: Código del cliente que ejecuta el protocolo Diffie-Hellman.
- `server.py`: Código del servidor que ejecuta el protocolo Diffie-Hellman.
- `parameters.json`: Archivo con los parámetros \( p \), \( q \) y \( g \).

## Orden de ejecución
1. `server.py`
2. `client.py`

### Objetivo
Explorar cómo funciona el intercambio de llaves Diffie-Hellman sobre un grupo cíclico y cómo se puede usar una KDF para generar llaves simétricas a partir del secreto compartido.

## Escenario 2: Intercambio de Llaves con Curva Elíptica P256 y Ataque MitM

### Descripción
Se implementa el protocolo de **intercambio de llaves Diffie-Hellman** utilizando la curva elíptica **P256**. Luego, se simula un ataque de hombre en el medio (MitM), donde el atacante intercepta el intercambio de llaves y genera llaves distintas con el cliente y el servidor.

### Proceso
1. **Cliente y servidor** acuerdan las llaves usando la curva elíptica P256.
2. **Cifrado y descifrado**: El cliente y el servidor cifran y descifran los mensajes con **AES-256 en modo CBC**.
3. **Ataque MitM**: Un atacante se coloca entre el cliente y el servidor, interceptando y modificando el intercambio de llaves para engañarlos y establecer llaves distintas con cada parte.

### Archivos
- `client.py`: Código del cliente que ejecuta el protocolo Diffie-Hellman con curva elíptica P256.
- `server.py`: Código del servidor que ejecuta el protocolo Diffie-Hellman con curva elíptica P256.
- `attacker.py`: Código del atacante que ejecuta el ataque MitM.

## Orden de ejecución
1. `attacker.py`
2. `server.py`
3. `client.py`

### Objetivo
Explorar cómo se implementa el intercambio de llaves con curvas elípticas y demostrar la vulnerabilidad ante un ataque MitM.

## Escenario 3: Comparación entre Criptografía Simétrica y Asimétrica

### Descripción
Se implementan y comparan los siguientes esquemas de criptografía:
- **Criptografía Asimétrica**: RSA OAEP y ElGamal.
- **Criptografía Simétrica**: Salsa20 y AES-256.

Se mide la eficiencia de cada algoritmo en términos de la cantidad de datos transmitidos sobre la red y el tiempo que toma cifrar y descifrar los mensajes.

### Proceso
1. **Cifrado y descifrado**: Se cifran y descifran mensajes usando los algoritmos asimétricos (RSA OAEP y ElGamal) y los simétricos (Salsa20 y AES-256).
2. **Medición de tiempos**: Se mide el tiempo de cifrado y descifrado de cada algoritmo.
3. **Medición de tamaño**: Se mide el tamaño del mensaje cifrado.
4. **Almacenamiento de resultados**: Los resultados se guardan en un archivo `encryption_results.json`.

### Objetivo
Comparar la eficiencia de la criptografía simétrica y asimétrica, tanto en términos de rendimiento como en la cantidad de datos transmitidos sobre la red.

## Requisitos

Instalar las dependencias de Python necesarias ejecutando el siguiente comando:

```bash
pip install pycryptodome
```
## Notas Adicionales
- Las claves utilizadas en ElGamal se almacenan en formato JSON en el directorio ElGamal/keys.
- Asegúrese de ejecutar cada script en el orden correcto para evitar conflictos entre los clientes y servidores.
