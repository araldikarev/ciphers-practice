from algorithms.vigenere_cipher_with_repeating_key_cipher import VigenereCipherWithRepeatingKeyCipher

LONG_TEXT = """
when i started to study ciphers i believed that secrecy was only a matter of hiding symbols
but soon i learned that structure leaks through repetition even when every letter is replaced
a long message leaves footprints in its own habits certain pairs appear again and again
and a patient analyst can use those habits to guess what the hidden sentence was trying to say
this does not require magic it requires statistics careful comparison and many small corrections
first you count how often each sign occurs then you compare that list with a known language profile
the most frequent letter in english is usually e and the next ones often include t a o i n and s
after single letters you examine pairs because th he in er an re and on are stubbornly common
then you search for short words because the and and are everywhere and they act like anchors
each guess unlocks more context and context allows better guesses until the text becomes readable
the method is not perfect but it is practical and it teaches an important lesson about patterns
if two different messages are encrypted with the same substitution the attacker improves faster
and if the message is long the attacker needs less luck because the averages stabilize
a defender can respond by changing keys often mixing alphabets or using stronger constructions
"""

ALPHABET = "abcdefghijklmnopqrstuvwxyz "
KEY_TEXT = "cipher"

MAX_KEY_LENGTH = 12

TRIGRAM_W = {
    "the": 12, "and": 10, "ing": 9, "her": 7, "ere": 7, "ent": 7, "tha": 7, "nth": 6,
    "was": 5, "eth": 5, "for": 5, "his": 5, "hat": 5, "ion": 6, "tio": 6,
}

letter_frequencies = {
    ' ': 15.00,
    'e': 12.70, 't': 9.06,  'a': 8.17, 'o': 7.51, 'i': 6.97, 'n': 6.75, 's': 6.33,
    'r': 5.99,  'h': 6.09,  'l': 4.03, 'd': 4.25, 'c': 2.78, 'u': 2.76, 'm': 2.41,
    'w': 2.36,  'f': 2.23,  'g': 2.02, 'y': 1.97, 'p': 1.93, 'b': 1.49, 'v': 0.98,
    'k': 0.77,  'x': 0.15,  'j': 0.15, 'q': 0.10, 'z': 0.07
}


def split_text_by_key_length(text: str, key_length: int):
    groups = ["" for _ in range(key_length)]

    for i in range(len(text)):
        groups[i % key_length] += text[i]

    return groups


def get_index_of_coincidence(text: str):
    if len(text) < 2:
        return 0

    score = 0

    for symbol in ALPHABET:
        frequency = text.count(symbol)
        score += frequency * (frequency - 1)

    return score / (len(text) * (len(text) - 1))


def get_normalized_letter_frequencies():
    total = sum(letter_frequencies.values())
    return {symbol: letter_frequencies[symbol] / total for symbol in ALPHABET}


def decrypt_group_by_shift(group_text: str, shift: int):
    index_map = {ch: i for i, ch in enumerate(ALPHABET)}

    result = []

    for symbol in group_text:
        result.append(ALPHABET[(index_map[symbol] - shift) % len(ALPHABET)])

    return "".join(result)


def get_chi_squared_score(text: str, normalized_frequencies: dict):
    score = 0

    for symbol in ALPHABET:
        observed = text.count(symbol)
        expected = normalized_frequencies[symbol] * len(text)

        if expected > 0:
            score += ((observed - expected) ** 2) / expected

    return score


def main():
    cipher = VigenereCipherWithRepeatingKeyCipher()

    encrypted_text = cipher.encrypt(ALPHABET, LONG_TEXT.replace("\n", " "), KEY_TEXT)

    ic_scores = []

    for key_length in range(1, MAX_KEY_LENGTH + 1):
        groups = split_text_by_key_length(encrypted_text, key_length)
        avg_ic = sum([get_index_of_coincidence(group) for group in groups]) / len(groups)
        ic_scores.append((key_length, avg_ic))

    ic_scores.sort(key=lambda x: x[1], reverse=True)

    print("Наиболее вероятные длины ключа:")
    for key_length, ic_score in ic_scores[:5]:
        print(f"Длина={key_length} | Индекс совпадений={ic_score:.6f}")

    normalized_frequencies = get_normalized_letter_frequencies()
    results = []

    for key_length, ic_score in ic_scores[:5]:
        groups = split_text_by_key_length(encrypted_text, key_length)

        got_key_text = ""
        total_chi_score = 0

        for group in groups:
            group_scores = []

            for shift in range(len(ALPHABET)):
                decrypted_group = decrypt_group_by_shift(group, shift)
                chi_score = get_chi_squared_score(decrypted_group, normalized_frequencies)
                group_scores.append((shift, chi_score))

            group_scores.sort(key=lambda x: x[1])

            best_shift, best_chi_score = group_scores[0]
            got_key_text += ALPHABET[best_shift]
            total_chi_score += best_chi_score

        decrypted_text = cipher.decrypt(ALPHABET, encrypted_text, got_key_text)

        trigram_score = sum([
            s.count(trigram) * weight
            for trigram, weight in TRIGRAM_W.items()
            for s in decrypted_text.split(" ")
        ])

        results.append({
            "key_length": key_length,
            "key_text": got_key_text,
            "ic_score": ic_score,
            "chi_score": total_chi_score,
            "trigram_score": trigram_score,
            "decrypted_text": decrypted_text
        })

    results.sort(key=lambda x: (-x["trigram_score"], x["chi_score"]))

    print("\nНаиболее вероятные ключи:")
    for best in results[:3]:
        print(
            f"Длина ключа={best['key_length']}\n"
            f"Найденный ключ={best['key_text']}\n"
            f"Индекс совпадений={best['ic_score']:.6f}\n"
            f"Chi-Squared={best['chi_score']:.6f}\n"
            f"Trigram-скоринг={best['trigram_score']}\n"
            f"Дешифрованный текст:\n{'-' * 20}\n{best['decrypted_text'][:300]}"
        )
        print("-" * 30)


main()