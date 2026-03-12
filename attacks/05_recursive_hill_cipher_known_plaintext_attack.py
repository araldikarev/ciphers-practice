from algorithms.recursive_hill_cipher import RecursiveHillCipher
import numpy as np
import math


ALPHABET = "abcdefghijklmnopqrstuvwxyz "
SECRET_CHAR = "x"

K1_MATRIX = np.array([
    [3, 5],
    [2, 7]
])

K2_MATRIX = np.array([
    [9, 4],
    [5, 7]
])

KNOWN_MESSAGES = [
    "abba",
    "baab"
]

TARGET_TEXT = "recursive hill also breaks with known plaintext"


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
    cipher = RecursiveHillCipher()
    block_size = K1_MATRIX.shape[0]
    modulus = len(ALPHABET)
    index_map = {ch: i for i, ch in enumerate(ALPHABET)}

    if len(KNOWN_MESSAGES) < block_size:
        raise ValueError(
            f"Для рекуррентного шифра Хилла {block_size}x{block_size} нужно минимум {block_size} известных сообщений."
        )

    padded_known_messages = [
        pad_text(message, block_size, SECRET_CHAR) for message in KNOWN_MESSAGES
    ]

    known_ciphertexts = [
        cipher.encrypt(ALPHABET, message, K1_MATRIX, K2_MATRIX, SECRET_CHAR)
        for message in padded_known_messages
    ]

    plain_blocks_by_message = [
        split_blocks(message, block_size) for message in padded_known_messages
    ]
    cipher_blocks_by_message = [
        split_blocks(cipher_text, block_size) for cipher_text in known_ciphertexts
    ]

    for i, blocks in enumerate(plain_blocks_by_message):
        if len(blocks) < 2:
            raise ValueError(
                f"Сообщение {i + 1} должно содержать минимум 2 блока для восстановления K1 и K2."
            )

    first_plain_blocks = [blocks[0] for blocks in plain_blocks_by_message[:block_size]]
    first_cipher_blocks = [blocks[0] for blocks in cipher_blocks_by_message[:block_size]]

    X1 = blocks_to_matrix(first_plain_blocks, index_map) % modulus
    Y1 = blocks_to_matrix(first_cipher_blocks, index_map) % modulus

    if not is_invertible_mod(X1, modulus):
        raise ValueError(
            "Первые известные блоки линейно зависимы по модулю алфавита. "
            "Нужно выбрать другие сообщения."
        )

    X1_inv = cipher.get_inv_mod_matrix(X1, modulus)
    recovered_k1 = (Y1 @ X1_inv) % modulus

    second_plain_blocks = [blocks[1] for blocks in plain_blocks_by_message[:block_size]]
    second_cipher_blocks = [blocks[1] for blocks in cipher_blocks_by_message[:block_size]]

    X2 = blocks_to_matrix(second_plain_blocks, index_map) % modulus
    Y2 = blocks_to_matrix(second_cipher_blocks, index_map) % modulus

    if not is_invertible_mod(X2, modulus):
        raise ValueError(
            "Вторые известные блоки линейно зависимы по модулю алфавита. "
            "Нужно выбрать другие сообщения."
        )

    X2_inv = cipher.get_inv_mod_matrix(X2, modulus)
    recovered_k2 = (Y2 @ X2_inv) % modulus

    encrypted_target = cipher.encrypt(ALPHABET, TARGET_TEXT, K1_MATRIX, K2_MATRIX, SECRET_CHAR)
    decrypted_target = cipher.decrypt(ALPHABET, encrypted_target, recovered_k1, recovered_k2, SECRET_CHAR)
    padded_target = pad_text(TARGET_TEXT, block_size, SECRET_CHAR)

    print("Атака на рекуррентный шифр Хилла по известному открытому тексту")
    print(f"Алфавит: {ALPHABET}")

    print("\nИзвестные сообщения:")
    for i in range(len(padded_known_messages)):
        print(f"{i + 1}) P: {padded_known_messages[i]} | C: {known_ciphertexts[i]}")

    print("\nИсходная K1:")
    print(K1_MATRIX)
    print("\nВосстановленная K1:")
    print(recovered_k1.astype(int))

    print("\nИсходная K2:")
    print(K2_MATRIX)
    print("\nВосстановленная K2:")
    print(recovered_k2.astype(int))

    print("\nТест на другом сообщении:")
    print(f"Открытый текст:   {padded_target}")
    print(f"Шифртекст:        {encrypted_target}")
    print(f"Расшифровано:     {decrypted_target}")


main()