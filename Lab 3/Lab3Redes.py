from Crypto.Cipher import AES
import numpy as np
import time
import matplotlib.pyplot as plt


def read_test(filename):
    """
    Lee un archivo de entrada en modo binario

    :param filename: Nombre del archivo a leer

    :return: Bytes con el contenido del archivo filename
    """
    f = open(filename, "a")
    f.close()
    f = open(filename, "rb")
    content = f.read()
    f.close()
    return content


def write_test(filename, content):
    """
    Escribe un archivo en modo binario

    :param filename: Nombre del archivo a escribir
    :param content: Contenido a escribir (en formato bytes)

    :return: Nada
    """
    f = open(filename, "wb")
    f.write(content)
    f.close()


def getBlocks(byteText, blockSize):
    """
    Divide un texto (en formato bytes) en bloques de tamaño blockSize.

    Si el tamaño del último bloque es menor a blockSize, se agregan espacios para rellenar
    lo que falta.

    :param byteText: Texto en formato bytes
    :param blockSize: Tamaño de cada bloques

    :return: Arreglo con el byteText divido en bloques
    """
    blocks = []
    while len(byteText) >= blockSize:
        blocks.append(byteText[:blockSize])
        byteText = byteText[blockSize:]
    if len(byteText) > 0:
        blocks.append(byteText + b" " * (blockSize - len(byteText)))
    return blocks


def bitstring_to_bytes(s):
    """
    Transforma una string de bits a un byte

    :param s: String con el binario

    :return: Byte con la transformación del binario
    """
    v = int(s, 2)
    b = bytearray()
    while v:
        b.append(v & 0xff)
        v >>= 8
    return bytes(b[::-1])


def cycleLeftKey(key, times):
    """
    Realiza un shift circular hacia la izquierda de la llave times veces

    :param key: Llave (en formato bytes)
    :param times: Cantidad de shifts hacia la izquierda

    :return: Llave shifteada (formato bytes)
    """
    key_bin = ""
    for byte in key:
        binary = bin(byte)[2:]
        key_bin += "0" * (8 - len(binary)) + binary
    key_bin = bitstring_to_bytes(key_bin[times::] + key_bin[:times:])
    return key_bin


def cycleRightKey(key, times):
    """
        Realiza un shift circular hacia la derecha de la llave times veces

        :param key: Llave (en formato bytes)
        :param times: Cantidad de shifts hacia la izquierda

        :return: Llave shifteada (formato bytes)
        """
    times %= len(key)
    key_bin = ""
    for byte in key:
        binary = bin(byte)[2:]
        key_bin += "0" * (8 - len(binary)) + binary
    key_bin = bitstring_to_bytes(key_bin[-times:] + key_bin[:-times])
    return key_bin


def feistel(blocks, blockSize, rounds, key, decryption):
    """
    Engargada de realizar la encriptación Feistel.

    Utiliza como función F una encriptación AES implementada en la librería PyCrypto (Crypto.Cipher)
    con el objetivo de alcanzar la mayor seguridad posible utilizando el modelo de cifrador Feistel.

    :param blocks: Arreglo con los bloques (en formato byte) a encriptar
    :param blockSize: Tamaño de bloques
    :param rounds: Cantidad de rondas
    :param key: Llave (en formato bytes)
    :param decryption: Flag booleana (True: Desencriptar, False: Encriptar)

    :return: Texto cifrado (formato bytes)
    """
    throughput = []
    result = b""
    half = int(blockSize / 2)
    for block in blocks:
        start_time = time.time()
        key_i = key
        for _ in range(rounds):
            cipher = AES.new(key=key_i)
            L = block[:half]
            R = block[half:]
            encrypted = cipher.encrypt(R)
            L = bytes([a ^ b for a, b in zip(L, encrypted)])  # realiza xor entre L y encrypted
            block = R + L
            if decryption:
                key_i = cycleRightKey(key_i, 1)
            else:
                key_i = cycleLeftKey(key_i, 1)
        # Al final de Feistel se dan vuelta las mitades de bloque
        result += L + R
        throughput.append(blockSize / (time.time() - start_time) * 0.001)
    return result, throughput


def clean_spaces(plainText):
    """
    Limpia los espacios que fueron agregados durante la función getBlocks

    :param plainText: Texto (formato bytes)
    :return: Texto sin espacios al final (formato bytes)
    """
    while plainText[-1] == b" "[0]:
        plainText = plainText[:-1]
    return bytes(plainText)


def get_different_bits(x, y):
    """
    Calcula la cantidad de bits diferentes entre dos bytes

    :param x: Primer byte a comparar
    :param y: Segundo byte a comprar

    :return: Cantidad de bits diferentes
    """
    x = bin(x)[2:]
    y = bin(y)[2:]
    x = list((8 - len(x)) * str(0) + x)
    y = list((8 - len(y)) * str(0) + y)
    different = 0
    for i in range(0, 8):
        if x[i] != y[i]:
            different += 1
    return different


def modify_first_byte(byte):
    """
    Cambia el último bit de un byte (si es 0 cambia a 1 y de 1 a 0)

    :param byte: Byte a modificar

    :return: Byte modificado
    """
    first = [byte[0]]
    firstBinary = bin(first[0]).format(6)
    if firstBinary[-1] == 1:
        first[0] -= 1
    else:
        first[0] += 1
    return bytes(first) + byte[1:]


def plot_throughput(text, rounds, key):
    """
    Genera un gráfico de througput al encriptar y desencriptar

    :param text: Texto plano (en formato bytes) a encriptar
    :param rounds: Cantidad de rondas
    :param key: Llave (formato bytes)

    :return: Un gráfico utilizando matplotlib
    """
    blockSizes = []
    throghputs = []
    encrypts = []
    times = 100
    for blockSize in range(32, 32 * (times + 1), 32):
        blockSizes.append(blockSize)
        blocks = getBlocks(text, blockSize)
        encrypt, throghput = feistel(blocks, blockSize, rounds, key, False)
        encrypts.append(encrypt)
        throghputs.append(np.mean(throghput))
    plt.plot(blockSizes, throghputs)

    blockSizes = []
    throghputs = []
    i = 0
    for blockSize in range(32, 32 * (times + 1), 32):
        blockSizes.append(blockSize)
        blocks = getBlocks(encrypts[i], blockSize)
        decrypt, throghput = feistel(blocks, blockSize, rounds, cycleLeftKey(key, (rounds - 1) % len(key)), True)
        throghputs.append(np.mean(throghput))
        i += 1
    plt.plot(blockSizes, throghputs)
    plt.title("Throughput promedio v/s Tamaño de bloque")
    plt.legend(["Al encriptar", "Al desencriptar"])
    plt.xlabel("Tamaño de bloque")
    plt.ylabel("Throughput promedio")
    plt.show()


def avalanche_test(key, rounds, blockSize):
    """
    Test que prueba el efecto avalancha en un bloque

    :param key: Llave (formato bytes)
    :param rounds: Cantidad de rondas
    :param blockSize: Tamaño de bloque

    :return: Imprime los resultados
    """
    block = b"1" * blockSize
    modifiedBlock = modify_first_byte(block)

    originalBlocks = getBlocks(block, blockSize)
    modifiedBlocks = getBlocks(modifiedBlock, blockSize)

    originalEncrypt, throughput = feistel(originalBlocks, blockSize, rounds, key, False)
    modifiedEncrypt, throughput = feistel(modifiedBlocks, blockSize, rounds, key, False)

    differentBits = 0
    differentBytes = 0
    for i in range(len(originalEncrypt)):
        if originalEncrypt[i] != modifiedEncrypt[i]:
            differentBits += get_different_bits(originalEncrypt[i], modifiedEncrypt[i])
            differentBytes += 1

    avalanche_bits = differentBits / (len(originalEncrypt) * 8) * 100
    avalanche_bytes = differentBytes / len(originalEncrypt) * 100

    print("El cambio por el efecto avalancha según la cantidad de bits diferentes (con", rounds, "rondas) es de:",
          avalanche_bits, "%")
    print("El cambio por el efecto avalancha según la cantidad de bytes diferentes (con", rounds, "rondas) es de:",
          avalanche_bytes, "%")


def change_key_test(encrypted, key, rounds, blockSize):
    """
    Test que cambia un bit de la llave para comprobar que se obtiene al desencriptar con
    una llave erronea

    :param encrypted: Texto encriptado (formato bytes)
    :param key: Llave (formato bytes)
    :param rounds: Cantidad de rondas
    :param blockSize: Tamaño de bloque

    :return: Escribe el resultado en "Salida.txt"
    """
    key = modify_first_byte(key)

    blocks = getBlocks(encrypted, blockSize)
#   El cycleLeftKey es para comenzar la desencriptación con la última llave utilizada en la encriptación
    decrypted, throughput = feistel(blocks, blockSize, rounds, cycleLeftKey(key, (rounds - 1) % (len(key) * 8)), True)
    decrypted = clean_spaces(decrypted)
    write_test("CambioDeLlave.txt", decrypted)


def main():
    blockSize = 32
    rounds = 54

#   Archivo a encriptar
    bitText = read_test("TextoPlano.txt")

#   Llave a utilizar
    key = b"Llave de 16bytes"

    blocks = getBlocks(bitText, blockSize)
    encrypted, throughput = feistel(blocks, blockSize, rounds, key, False)
    print("Throughput promedio al encriptar: ", np.mean(throughput))

    blocks = getBlocks(encrypted, blockSize)
#   El cycleLeftKey es para comenzar la desencriptación con la última llave utilizada en la encriptación
    decrypted, throughput = feistel(blocks, blockSize, rounds, cycleLeftKey(key, (rounds - 1) % (len(key) * 8)), True)
    decrypted = clean_spaces(decrypted)
    write_test("Salida.txt", decrypted)

#   Tests a realizar
    avalanche_test(key, rounds, blockSize)
    plot_throughput(bitText, rounds, key)
    change_key_test(encrypted, key, rounds, blockSize)


main()


