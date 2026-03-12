from algorithms.hill_cipher import HillCipher
import numpy as np
import math


ALPHABET = "abcdefghijklmnopqrstuvwxyz "
SECRET_CHAR = "x"

# Пример для ключа 2x2
KEY_MATRIX = np.array([
    [3, 5],
    [2, 7]
])

KNOWN_PLAINTEXT = "abba"

TARGET_TEXT = "hill cipher falls to known plaintext attack"


def pad_text(text: str, block_size: int, secret_char: str):
    remainder = len(text) % block_size
    if remainder != 0:
        text += secret_char * (block_size - remainder)
    return text


def split_blocks(text: str, block_size: int):
    return [text[i:i + block_size] for i in range(0, len(text), block_size)]


def blocks_to_matrix(blocks, index_map):
    vectors = [np.array([index_map[ch] for ch in block]) for block in blocks]
    return np.column_stack(vectors)


def is_invertible_mod(matrix, modulus: int):
    det = int(np.round(np.linalg.det(matrix)))
    return math.gcd(det % modulus, modulus) == 1


def main():
    cipher = HillCipher()
    block_size = KEY_MATRIX.shape[0]
    modulus = len(ALPHABET)
    index_map = {ch: i for i, ch in enumerate(ALPHABET)}

    known_plaintext = pad_text(KNOWN_PLAINTEXT, block_size, SECRET_CHAR)
    known_ciphertext = cipher.encrypt(ALPHABET, known_plaintext, KEY_MATRIX, SECRET_CHAR)

    plain_blocks = split_blocks(known_plaintext, block_size)
    cipher_blocks = split_blocks(known_ciphertext, block_size)

    if len(plain_blocks) < block_size:
        raise ValueError(
            f"Для Hill {block_size}x{block_size} нужно минимум {block_size} известных блоков."
        )

    used_plain_blocks = plain_blocks[:block_size]
    used_cipher_blocks = cipher_blocks[:block_size]

    X = blocks_to_matrix(used_plain_blocks, index_map) % modulus
    Y = blocks_to_matrix(used_cipher_blocks, index_map) % modulus

    if not is_invertible_mod(X, modulus):
        raise ValueError(
            "Известные блоки открытого текста линейно зависимы по модулю алфавита. "
            "Нужно выбрать другие блоки."
        )

    X_inv = cipher.get_inv_mod_matrix(X, modulus)
    recovered_key = (Y @ X_inv) % modulus

    encrypted_target = cipher.encrypt(ALPHABET, TARGET_TEXT, KEY_MATRIX, SECRET_CHAR)
    decrypted_target = cipher.decrypt(ALPHABET, encrypted_target, recovered_key, SECRET_CHAR)
    padded_target = pad_text(TARGET_TEXT, block_size, SECRET_CHAR)

    print("Атака на шифр Хилла по известному открытому тексту")
    print(f"Алфавит: {ALPHABET}")
    print(f"Известный открытый текст: {known_plaintext}")
    print(f"Известный шифртекст:      {known_ciphertext}")
    print(f"Использованные блоки:     {used_plain_blocks}")

    print("\nИсходная ключ-матрица:")
    print(KEY_MATRIX)

    print("\nВосстановленная ключ-матрица:")
    print(recovered_key.astype(int))

    print("\nТест на другом сообщении:")
    print(f"Открытый текст: {padded_target}")
    print(f"Шифртекст:      {encrypted_target}")
    print(f"Расшифровано:   {decrypted_target}")


main()