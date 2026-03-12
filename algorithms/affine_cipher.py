import math

from algorithms.base_algorithm import AlgorithmBase


class AffineCipher(AlgorithmBase):
    # region Реализация AlgorithmBase
    def get_name(self):
        return "Аффинный шифр"

    def get_description(self):
        return "Зашифровывает и расшифровывает строку через Аффинный шифр."

    def get_arguments_to_setup(self):
        return {
            "Алфавит M": self.set_alphabet,
            "Строка": self.validate_text,
            "Параметр A ключа": self.validate_a,
            "Параметр B ключа": int,
        }

    def encrypt(self, alphabet: str, plain_text: str, a: int, b: int):
        return self.encrypt_via_affine_cipher(alphabet, plain_text, a, b)

    def decrypt(self, alphabet: str, cipher_text: str, a: int, b: int):
        return self.decrypt_via_affine_cipher(alphabet, cipher_text, a, b)

    # endregion

    # region Валидация
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
            raise ValueError(
                f'Параметр "A" должен иметь НОД(A, длина алфавита ({len(self.alphabet)})) равный единице.'
            )
        return a_parsed

    def validate_text(self, text):
        validation = any(a not in self.alphabet for a in text)
        if validation:
            raise ValueError(
                "Строка не должна содержать символы не из заданного алфавита."
            )
        return str(text)

    # endregion

    # region Реализация Шифра
    def encrypt_via_affine_cipher(self, alphabet, plain_text: str, a: int, b: int):
        """
        Зашифровывает строку с использованием аффинного шифра по формуле: y_i = (a * x + b) mod n.

        :param alphabet: Алфавит, используемый для шифрования
        :type alphabet: str
        :param plain_text: Исходная строка для зашифрования
        :type plain_text: str
        :param a: Множитель ключа (должен быть взаимно прост с длиной алфавита)
        :type a: int
        :param b: Сдвиг ключа
        :type b: int
        :return: Зашифрованная строка
        :rtype: str
        """
        len_of_alphabet = len(alphabet)

        if math.gcd(a, len_of_alphabet) != 1:
            raise ValueError(
                "Параметр `a` должен иметь НОД(a, длина алфавита) равный единице."
            )

        index_map = {ch: i for i, ch in enumerate(alphabet)}

        result = []

        for symbol in plain_text:
            result.append(alphabet[(a * index_map[symbol] + b) % len_of_alphabet])

        return "".join(result)

    def decrypt_via_affine_cipher(self, alphabet, cipher_text: str, a: int, b: int):
        """
        Расшифровывает строку, зашифрованную аффинным шифром, по формуле: x_i = (y - b)*a^(-1) mod n.

        :param alphabet: Алфавит, используемый для расшифрования
        :type alphabet: str
        :param cipher_text: Зашифрованная строка
        :type cipher_text: str
        :param a: Множитель ключа, использованный при зашифровании
        :type a: int
        :param b: Сдвиг ключа, использованный при зашифровании
        :type b: int
        :return: Расшифрованная строка
        :rtype: str
        """
        len_of_alphabet = len(alphabet)

        if math.gcd(a, len_of_alphabet) != 1:
            raise ValueError(
                "Параметр `a` должен иметь НОД(a, длина алфавита) равный единице."
            )

        index_map = {ch: i for i, ch in enumerate(alphabet)}

        result = []

        a_inv = pow(a, -1, len_of_alphabet)
        for symbol in cipher_text:
            result.append(alphabet[(a_inv * (index_map[symbol] - b)) % len_of_alphabet])

        return "".join(result)

    # endregion
