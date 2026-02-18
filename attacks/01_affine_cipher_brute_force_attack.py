from algorithms.affine_cipher import AffineCipher
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
    cipher = AffineCipher()
    
    encrypted_a = 3
    encrypted_b = 16

    encrypted_text = cipher.encrypt(ALPHABET, LONG_TEXT, encrypted_a, encrypted_b)

    texts = {}

    for a in range(len(ALPHABET)):
        if math.gcd(a, len(ALPHABET)) != 1:
            continue
        
        for b in range(len(ALPHABET)-1):
            decrypted = cipher.decrypt(ALPHABET, encrypted_text, a, b)
            texts[(a, b)] = decrypted
    
    probability_map = []

    print(len(texts))

    for (a,b), text in texts.items():
        probability_map.append((a, b, sum([s.count(trigram)*weight for trigram, weight in TRIGRAM_W.items() for s in text.split(' ')])))

    probability_map.sort(key=lambda x: x[2])

    bests = probability_map[::-1][:5]

    for best in bests:
        print(f"Найденные значения: A={best[0]} B={best[1]}\nСкоринг: {best[2]}\nДешифрованный текст:\n{"-"*20}\n{texts[best[0],best[1]]}")
main()