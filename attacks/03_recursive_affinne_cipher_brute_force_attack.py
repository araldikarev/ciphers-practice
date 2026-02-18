from algorithms.recursive_affine_cipher import RecursiveAffineCipher
import math

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

ALPHABET = "abcdefghijklmnopqrstuvwxyz \n"

TRIGRAM_W = {
    "the": 12, "and": 10, "ing": 9, "her": 7, "ere": 7, "ent": 7, "tha": 7, "nth": 6,
    "was": 5, "eth": 5, "for": 5, "his": 5, "hat": 5, "ion": 6, "tio": 6,
}

def main():
    cipher = RecursiveAffineCipher()
    
    encrypted_a1 = 3
    encrypted_b1 = 16
    encrypted_a2 = 17
    encrypted_b2 = 11

    encrypted_text = cipher.encrypt(ALPHABET, LONG_TEXT, encrypted_a1, encrypted_b1, encrypted_a2, encrypted_b2)

    n = len(ALPHABET)
    valid_a = [a for a in range(n) if math.gcd(a, n) == 1]

    results = []

    for a1 in valid_a:
        for b1 in range(n):
            for a2 in valid_a:
                for b2 in range(n):
                    prefix_text = encrypted_text[:100]
                    decrypted_prefix = cipher.decrypt(ALPHABET, prefix_text, a1, b1, a2, b2)
                    
                    score = 0
                    for trigram, weight in TRIGRAM_W.items():
                        score += decrypted_prefix.count(trigram) * weight
                    
                    if score > 20: 
                        results.append({
                            "keys": (a1, b1, a2, b2),
                            "score": score
                        })
    
    results.sort(key=lambda x: x["score"], reverse=True)

    print(f"\nНайдено подозрительных комбинаций: {len(results)}")

    for best in results[:3]:
        a1, b1, a2, b2 = best["keys"]
        full_decrypted = cipher.decrypt(ALPHABET, encrypted_text, a1, b1, a2, b2)
        print(f"Найденные значения: A_1={a1} B_1={b1} | A_2={a2} B_2={b2}\nСкоринг: {best['score']}\nДешифрованный текст:\n{'-'*20}\n{full_decrypted[:150]}")
        print("-" * 30)

main()