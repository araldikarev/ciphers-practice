from algorithms.base_algorithm import AlgorithmBase


class VigenereCipherWithRepeatingKeyCipher(AlgorithmBase):
    # region Реализация AlgorithmBase
    def get_name(self):
        return "Шифр Виженера с циклическим повторением лозунга"

    def get_description(self):
        return "Зашифровывает и расшифровывает строку через Шифр Виженера с циклическим повторением лозунга."

    def get_arguments_to_setup(self):
        return {
            "Алфавит M": self.set_alphabet,
            "Строка": self.validate_text,
            "Лозунг (пароль)": self.validate_key_text,
        }

    def encrypt(self, alphabet: str, plain_text: str, key_text: str):
        return self.encrypt_via_vigenere_cipher_with_repeating_key_cipher(
            alphabet, plain_text, key_text
        )

    def decrypt(self, alphabet: str, cipher_text: str, key_text: str):
        return self.decrypt_via_vigenere_cipher_with_repeating_key_cipher(
            alphabet, cipher_text, key_text
        )

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

    def validate_text(self, text):
        validation = any(a not in self.alphabet for a in text)
        if validation:
            raise ValueError(
                "Строка не должна содержать символы не из заданного алфавита."
            )
        return str(text)

    def validate_key_text(self, key_text):
        if not key_text:
            raise ValueError("Лозунг (пароль) не может быть пустым")
        validation = any(a not in self.alphabet for a in key_text)
        if validation:
            raise ValueError(
                "Лозунг (пароль) не должен содержать символы не из заданного алфавита."
            )
        return str(key_text)

    # endregion

    # region Реализация Шифра
    def encrypt_via_vigenere_cipher_with_repeating_key_cipher(
        self, alphabet: str, plain_text: str, key_text: str
    ):
        """
        Зашифровывает строку шифром Виженера с циклическим повторением лозунга.

        :param alphabet: Алфавит, используемый для шифрования
        :type alphabet: str
        :param plain_text: Исходная строка для зашифрования
        :type plain_text: str
        :param key_text: Лозунг (пароль)
        :type key_text: str
        :return: Зашифрованная строка
        :rtype: str
        """
        len_of_alphabet = len(alphabet)

        index_map = {ch: i for i, ch in enumerate(alphabet)}

        result = []

        for i in range(len(plain_text)):
            result.append(alphabet[(index_map[plain_text[i]] + index_map[key_text[i % len(key_text)]]) % len_of_alphabet])

        return "".join(result)

    def decrypt_via_vigenere_cipher_with_repeating_key_cipher(
        self, alphabet: str, cipher_text: str, key_text: str
    ):
        """
        Расшифровывает строку, зашифрованную шифром Виженера с циклическим повторением лозунга.

        :param alphabet: Алфавит, используемый для расшифрования
        :type alphabet: str
        :param cipher_text: Зашифрованная строка
        :type cipher_text: str
        :param key_text: Лозунг (пароль), использованный при зашифровании
        :type key_text: str
        :return: Расшифрованная строка
        :rtype: str
        """
        len_of_alphabet = len(alphabet)

        index_map = {ch: i for i, ch in enumerate(alphabet)}

        result = []

        for i in range(len(cipher_text)):
            result.append(alphabet[(index_map[cipher_text[i]] - index_map[key_text[i % len(key_text)]]) % len_of_alphabet])

        return "".join(result)

    # endregion