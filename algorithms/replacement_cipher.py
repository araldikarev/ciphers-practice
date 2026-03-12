from algorithms.base_algorithm import AlgorithmBase


class SimpleReplacementCipher(AlgorithmBase):
    # region Реализация AlgorithmBase
    def get_name(self):
        return "Шифр простой замены"

    def get_description(self):
        return "Зашифровывает и расшифровывает строку через Шифр простой замены."

    def get_arguments_to_setup(self):
        return {
            "Алфавит M": self.set_alphabet,
            "Строка": self.validate_text,
            "Ключ Алфавит": self.validate_key_alphabet,
        }

    def encrypt(self, alphabet: str, plain_text: str, key_alphabet: str):
        return self.encrypt_via_simple_replacement_cipher(
            alphabet, plain_text, key_alphabet
        )

    def decrypt(self, alphabet: str, cipher_text: str, key_alphabet: str):
        return self.decrypt_via_simple_replacement_cipher(
            alphabet, cipher_text, key_alphabet
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

    def validate_key_alphabet(self, key_alphabet):
        if len(key_alphabet) != len(self.alphabet):
            raise ValueError(
                f"Ключ-алфавит и сам алфавит должны совпадать ({len(key_alphabet)} vs {len(self.alphabet)})"
            )
        if len(set(key_alphabet)) != len(key_alphabet):
            raise ValueError("Ключ-алфавит не должен иметь повторяющиеся символы.")
        if set(key_alphabet) != set(self.alphabet):
            raise ValueError(
                "Ключ-алфавит должен быть перестановкой исходного алфавита (те же символы)."
            )
        return str(key_alphabet)

    # endregion

    # region Реализация Шифра
    def encrypt_via_simple_replacement_cipher(
        self, alphabet: str, plain_text: str, key_alphabet: str
    ):
        """
        Зашифровывает строку методом простой замены, заменяя каждый символ
        алфавита на соответствующий символ из ключ-алфавита.

        :param alphabet: Исходный алфавит (M)
        :type alphabet: str
        :param plain_text: Строка для зашифрования
        :type plain_text: str
        :param key_alphabet: Алфавит-заменитель (ключ). Если None, используется сдвиг на 3.
        :type key_alphabet: str
        :return: Зашифрованная строка
        :rtype: str
        """
        len_of_alphabet = len(alphabet)

        if len(key_alphabet) != len_of_alphabet:
            raise Exception("Алфавиты должны совпадать по длине.")

        forward_map = {alphabet[i]: key_alphabet[i] for i in range(len_of_alphabet)}

        result = []
        for symbol in plain_text:
            result.append(forward_map[symbol])

        return "".join(result)

    def decrypt_via_simple_replacement_cipher(
        self, alphabet: str, cipher_text: str, key_alphabet: str = None
    ):
        """
        Расшифровывает строку, зашифрованную методом простой замены.

        :param alphabet: Исходный алфавит (M)
        :type alphabet: str
        :param cipher_text: Зашифрованная строка
        :type cipher_text: str
        :param key_alphabet: Алфавит-заменитель (ключ), использованный при зашифровании
        :type key_alphabet: str
        :return: Расшифрованная строка
        :rtype: str
        """
        len_of_alphabet = len(alphabet)

        if key_alphabet is not None:
            if len(key_alphabet) != len_of_alphabet:
                raise ValueError("Алфавиты должны совпадать по длине.")
        else:
            key_alphabet = "".join(
                [(alphabet * 2)[i + 3] for i in range(len_of_alphabet)]
            )

        reverse_map = {key_alphabet[i]: alphabet[i] for i in range(len_of_alphabet)}

        result = []
        for symbol in cipher_text:
            result.append(reverse_map[symbol])

        return "".join(result)

    # endregion
