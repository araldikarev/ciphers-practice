from itertools import product

from algorithms.vigenere_cipher_with_plain_text_autokey_cipher import VigenereCipherWithPlainTextAutokeyCipher

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
KEY_TEXT = "sun"

TRIGRAM_W = {
    "the": 12, "and": 10, "ing": 9, "her": 7, "ere": 7, "ent": 7, "tha": 7, "nth": 6,
    "was": 5, "eth": 5, "for": 5, "his": 5, "hat": 5, "ion": 6, "tio": 6,
}


def main():
    cipher = VigenereCipherWithPlainTextAutokeyCipher()

    encrypted_text = cipher.encrypt(ALPHABET, LONG_TEXT.replace("\n", " "), KEY_TEXT)

    prefix_text = encrypted_text[:150]
    results = []

    for key_tuple in product(ALPHABET, repeat=len(KEY_TEXT)):
        got_key_text = "".join(key_tuple)
        decrypted_prefix = cipher.decrypt(ALPHABET, prefix_text, got_key_text)

        score = sum([
            s.count(trigram) * weight
            for trigram, weight in TRIGRAM_W.items()
            for s in decrypted_prefix.split(" ")
        ])

        results.append({
            "key_text": got_key_text,
            "score": score
        })

    results.sort(key=lambda x: x["score"], reverse=True)

    print(f"\nПроверено комбинаций: {len(results)}")

    for best in results[:5]:
        got_key_text = best["key_text"]
        full_decrypted = cipher.decrypt(ALPHABET, encrypted_text, got_key_text)

        print(
            f"Найденный начальный ключ={got_key_text}\n"
            f"Скоринг: {best['score']}\n"
            f"Дешифрованный текст:\n{'-' * 20}\n{full_decrypted[:300]}"
        )
        print("-" * 30)


main()