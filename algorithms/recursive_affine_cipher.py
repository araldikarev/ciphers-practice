import math
from algorithms.base_algorithm import AlgorithmBase

class RecursiveAffineCipher(AlgorithmBase):

    #region Реализация AlgorithmBase
    def get_name(self):
        return "Рекурсивный Аффинный шифр"
    
    def get_description(self):
        return "Зашифровывает и расшифровывает строку через Рекурсивный Аффинный шифр."

    def get_arguments_to_setup(self):
        return {
            "Алфавит M": self.set_alphabet,
            "Строка": self.validate_text,
            "Параметр A_1 первого ключа": self.validate_a,
            "Параметр B_1 первого ключа": int,
            "Параметр A_2 второго ключа": self.validate_a,
            "Параметр B_2 второго ключа": int,
        }

    def encrypt(self, alphabet: str, plain_text: str, ak1: int, bk1: int, ak2: int, bk2: int):
        return self.encrypt_via_recursive_affine_cipher(alphabet, plain_text, ak1, bk1, ak2, bk2)
    
    def decrypt(self, alphabet: str, cipher_text: str, ak1: int, bk1: int, ak2: int, bk2: int):
        return self.decrypt_via_recursive_affine_cipher(alphabet, cipher_text, ak1, bk1, ak2, bk2)
    #endregion

    #region Валидация
    def __init__(self):
        self.alphabet = ""

    def set_alphabet(self, alphabet):
        if not alphabet: 
            raise ValueError("Алфавит не может быть пустым")
        if len(set(alphabet)) != len(alphabet):
            raise ValueError("Алфавит не должен иметь повторяющиеся символы.")
        if len(alphabet) < 2:
            raise ValueError("Алфавит должен содержать минимум 2 разных символа.")
        self.alphabet = alphabet
        return alphabet

    def validate_a(self, a_key):
        a_parsed = int(a_key)
        validation = math.gcd(a_parsed, len(self.alphabet)) == 1
        if not validation:
            raise ValueError(f"Параметр \"A\" должен иметь НОД(A, длина алфавита ({len(self.alphabet)})) равный единице.")
        return a_parsed
    
    def validate_text(self, text):
        validation = any(a not in self.alphabet for a in text)
        if validation:
            raise ValueError("Строка не должна содержать символы не из заданного алфавита.")
        return str(text)
    #endregion
    
    #region Реализация Шифра
    def encrypt_via_recursive_affine_cipher(self, alphabet: str, plain_text: str, ak1: int, bk1: int, ak2: int, bk2: int):
        """
        Зашифровывает строку рекурсивным аффинным шифром, где ключи для каждого символа 
        вычисляются на основе двух предыдущих: a[i] = a[i-1]*a[i-2], b[i] = b[i-1]+b[i-2].
        
        :param alphabet: Алфавит, используемый для шифрования
        :type alphabet: str
        :param plain_text: Исходная строка для зашифрования
        :type plain_text: str
        :param ak1: Параметр A первого ключа
        :type ak1: int
        :param bk1: Параметр B первого ключа
        :type bk1: int
        :param ak2: Параметр A второго ключа
        :type ak2: int
        :param bk2: Параметр B второго ключа
        :type bk2: int
        :return: Зашифрованная строка
        :rtype: str
        """
        len_of_alphabet = len(alphabet)

        if math.gcd(ak1, len(alphabet)) != 1:
            raise ValueError("Параметр `ak1` должен иметь НОД(ak1, длина алфавита) равный единице.")
        
        if math.gcd(ak2, len(alphabet)) != 1:
            raise ValueError("Параметр `ak2` должен иметь НОД(ak2, длина алфавита) равный единице.")
        
        index_map = {ch: i for i, ch in enumerate(alphabet)}

        a_array = [ak1, ak2]
        b_array = [bk1, bk2]

        result = []
        
        for i in range(len(plain_text)):
            if i>=len(a_array):
                a_array.append((a_array[-1] * a_array[-2]) % len_of_alphabet)
                b_array.append((b_array[-1] + b_array[-2]) % len_of_alphabet)
            result.append(alphabet[(a_array[i] * index_map[plain_text[i]] + b_array[i]) % len_of_alphabet])

        return "".join(result)

    def decrypt_via_recursive_affine_cipher(self, alphabet: str, cipher_text: str, ak1: int, bk1: int, ak2: int, bk2: int):
        """
        Расшифровывает строку, зашифрованную рекурсивным аффинным шифром.
        
        :param alphabet: Алфавит, используемый для расшифрования
        :type alphabet: str
        :param cipher_text: Зашифрованная строка
        :type cipher_text: str
        :param ak1: Параметр A первого ключа
        :type ak1: int
        :param bk1: Параметр B первого ключа
        :type bk1: int
        :param ak2: Параметр A второго ключа
        :type ak2: int
        :param bk2: Параметр B второго ключа
        :type bk2: int
        :return: Расшифрованная строка
        :rtype: str
        """
        len_of_alphabet = len(alphabet)

        if math.gcd(ak1, len_of_alphabet) != 1:
            raise ValueError("Параметр `ak1` должен иметь НОД(ak1, длина алфавита) равный единице.")
        
        if math.gcd(ak2, len_of_alphabet) != 1:
            raise ValueError("Параметр `ak2` должен иметь НОД(ak2, длина алфавита) равный единице.")

        index_map = {ch: i for i, ch in enumerate(alphabet)}

        a_array = [ak1, ak2]
        b_array = [bk1, bk2]

        result = []

        for i in range(len(cipher_text)):
            if i>=len(a_array):
                a_array.append((a_array[-1] * a_array[-2]) % len_of_alphabet)
                b_array.append((b_array[-1] + b_array[-2]) % len_of_alphabet)
            result.append(alphabet[(pow(a_array[i], -1, len_of_alphabet)*(index_map[cipher_text[i]] - b_array[i])) % len_of_alphabet])
        return "".join(result)
    #endregion