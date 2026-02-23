from algorithms.base_algorithm import AlgorithmBase
import numpy as np
from numpy import ndarray
import ast
import math

class RecursiveHillCipher(AlgorithmBase):
    # region Реализация AlgorithmBase
    def get_name(self):
        return "Рекурсивный Шифр Хилла"

    def get_description(self):
        return "Зашифровывает и расшифровывает строку через Рекурсивный Шифр Хилла."

    def get_arguments_to_setup(self):
        return {
            "Алфавит M": self.set_alphabet,
            "Строка": self.validate_text,
            "Ключ-матрица K1 (в формате \"[[a11, a12], [a21, a22]]\")": self.validate_key_matrix,
            "Ключ-матрица K2 (в формате \"[[a11, a12], [a21, a22]]\")": self.validate_key_matrix,
            "Пустой символ": self.validate_char
        }

    def encrypt(self, alphabet: str, plain_text: str, k1_matrix: ndarray, k2_matrix: ndarray, secret_char: str):
        return self.encrypt_via_recursive_hill_cipher(
            alphabet, plain_text, k1_matrix, k2_matrix, secret_char
        )

    def decrypt(self, alphabet: str, cipher_text: str, k1_matrix: ndarray, k2_matrix: ndarray, secret_char: str ):
        return self.decrypt_via_recursive_hill_cipher(
            alphabet, cipher_text, k1_matrix, k2_matrix, secret_char 
        )

    # endregion

    # region Валидация

    def __init__(self):
        self.alphabet = ""
        self.previous_k_matrix: ndarray = None

    def set_alphabet(self, alphabet):
        if not alphabet:
            raise ValueError("Алфавит не может быть пустым")
        if len(set(alphabet)) != len(alphabet):
            raise ValueError("Алфавит не должен иметь повторяющиеся символы.")
        if len(alphabet) < 2:
            raise ValueError("Алфавит должен содержать минимум 2 разных символа.")
        self.alphabet = alphabet
        return alphabet

    def validate_text(self, text):
        validation = any(a not in self.alphabet for a in text)
        if validation:
            raise ValueError(
                "Строка не должна содержать символы не из заданного алфавита."
            )
        return str(text)
    
    def validate_char(self, char):
        if len(char) != 1:
            raise ValueError("Введите один символ из алфавита.")
        validation = any(a not in self.alphabet for a in char)
        if validation:
            raise ValueError(
                "Символ должен быть из заданного алфавита."
            )
        return str(char)

    def validate_key_matrix(self, k_matrix_str):
        k_matrix = None
        try:
            matrix_list = ast.literal_eval(k_matrix_str)
            k_matrix = np.array(matrix_list) % len(self.alphabet)
        except Exception as ex:
            raise ValueError("Ключ-матрица неверного формата. Используйте следующий формат записи: \"[[a11, a12], [a21, a22]]\"")
        
        if k_matrix.shape[0] != k_matrix.shape[1]:
            raise ValueError("Ключ-матрица неверного размера: используйте квадратную матрицу для ключа-матрицы.")
        
        
        if self.previous_k_matrix is not None:
            if self.previous_k_matrix.shape != k_matrix.shape:
                self.previous_k_matrix = None 
                raise ValueError("Ключ-матрица неверного размера: используйте квадратную матрицу того же размера, что и для первого ключа-матрицы.")
            
            self.previous_k_matrix = None
        else:
            self.previous_k_matrix = k_matrix


        matrix_det = int(np.round(np.linalg.det(k_matrix)))

        if matrix_det == 0:
            raise ValueError("Неверная ключ-матрица: Определитель матрицы не должен быть равен нулю.")

        if math.gcd(matrix_det % len(self.alphabet), len(self.alphabet)) != 1:
            raise ValueError("Неверная ключ-матрица: НОД определителя матрицы ключа и мощность алфавита должна быть равна единице.")

        return k_matrix
    # endregion

    # region Реализация Шифра
    def encrypt_via_recursive_hill_cipher(
        self, alphabet: str, plain_text: str, k1_matrix: ndarray, k2_matrix: ndarray, secret_char: str 
    ):
        """
        Зашифровывает строку Рекурсивным Шифром Хилла.
        """
        len_of_alphabet = len(alphabet)
        key_size = k1_matrix.shape[0]
        remainder = len(plain_text) % key_size
        if remainder != 0:
            plain_text += secret_char*(key_size - remainder)

        k_matrices = [k1_matrix, k2_matrix]

        index_map = {ch: i for i, ch in enumerate(alphabet)}
        result = []
        
        for i in range(len(plain_text) // key_size):
            if i >= len(k_matrices):
                k_new_matrix = (k_matrices[-1] @ k_matrices[-2]) % len_of_alphabet
                k_matrices.append(k_new_matrix)
            
            k_matrix = k_matrices[i]
            block = [index_map[x] for x in plain_text[i*key_size:(i+1)*key_size]]
            X_matrix = np.array(block).T 
            res_vector = (k_matrix @ X_matrix) % len_of_alphabet
            result.extend([alphabet[int(round(res)) % len_of_alphabet] for res in res_vector])

        return "".join(result)


    def decrypt_via_recursive_hill_cipher(
        self, alphabet: str, cipher_text: str, k1_matrix: ndarray, k2_matrix: ndarray, secret_char: str 
    ):
        """
        Расшифровывает строку, зашифрованную Рекурсивным Шифром Хилла.
        """
        len_of_alphabet = len(alphabet)
        key_size = k1_matrix.shape[0]

        if len(cipher_text)%key_size != 0:
            raise ValueError("Ошибка - длина шифртекста должна быть кратна рангу ключа матрицы.")
        
        k_matrices = [k1_matrix, k2_matrix]
        index_map = {ch: i for i, ch in enumerate(alphabet)}
        result = []

        for i in range(len(cipher_text) // key_size):
            
            if i >= len(k_matrices):
                k_new_matrix = (k_matrices[-1] @ k_matrices[-2]) % len_of_alphabet
                k_matrices.append(k_new_matrix)
            k_matrix = k_matrices[i]
            k_matrix_inv = self.get_inv_mod_matrix(k_matrix, len_of_alphabet)

            block = [index_map[x] for x in cipher_text[i*key_size:(i+1)*key_size]]
            X_matrix = np.array(block).T
            res_vector = (k_matrix_inv @ X_matrix) % len_of_alphabet
            result.extend([alphabet[int(round(res)) % len_of_alphabet] for res in res_vector])
        
        return "".join(result)
    # endregion

    #region Helpers
    def get_inv_mod_matrix(self, k_matrix, m) -> ndarray:
        k_matrix_det = int(np.round(np.linalg.det(k_matrix)))
        k_matrix_det_mod = k_matrix_det % m
        
        try:
            det_inv = pow(k_matrix_det_mod, -1, m)
        except ValueError:
            raise ValueError("Матрица не имеет обратной по этому модулю (НОД(k_matrix_det_mod, m) != 1)")
        
        k_adj = np.round(k_matrix_det * np.linalg.inv(k_matrix)).astype(int)
        k_matrix_inv_mod = (det_inv  * k_adj) % m
        return k_matrix_inv_mod
    #endregion
