from algorithms.replacement_cipher import SimpleReplacementCipher

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

ALPHABET =     "abcdefghijklmnopqrstuvwxyz "
KEY_ALPHABET = "vjzxwrpufmqtyosnigekbadlch "

letter_frequencies = {
    ' ': 15.00,
    'E': 12.70, 'T': 9.06,  'A': 8.17, 'O': 7.51, 'I': 6.97, 'N': 6.75, 'S': 6.33, 
    'R': 5.99,  'H': 6.09,  'L': 4.03, 'D': 4.25, 'C': 2.78, 'U': 2.76, 'M': 2.41,
    'W': 2.36,  'F': 2.23,  'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.49, 'V': 0.98, 
    'K': 0.77,  'X': 0.15,  'J': 0.15, 'Q': 0.10, 'Z': 0.07
}

def main():
    cipher = SimpleReplacementCipher()

    encrypted_text = cipher.encrypt(ALPHABET, LONG_TEXT.replace("\n"," "), KEY_ALPHABET)

    frequency_symbols = []
    for symbol in ALPHABET:
        frequency_symbols.append((symbol, encrypted_text.count(symbol)/(len(encrypted_text))*100))

    frequency_symbols.sort(key=lambda x: x[1], reverse=True)

    #Вывод
    for rows in range((len(ALPHABET)+3)//4):
        result_string = ""

        for i in range(4):
            if i+4*rows < len(ALPHABET):
                element = frequency_symbols[i+4*rows]
                result = f"\"{element[0]}\": {element[1]:f}%"
                result_string += result + "    "
        print(result_string)

    #Попытка сопоставления:
    predicted_key_alphabet = []
    letter_keys = sorted(letter_frequencies.keys(), key=lambda k: letter_frequencies[k], reverse=True)

    for i in range(len(frequency_symbols)):
        predicted_key_alphabet.append((frequency_symbols[i][0], letter_keys[i].lower()))
    
    plain_to_cipher = {plain: cipher_sym for (cipher_sym, plain) in predicted_key_alphabet}

    got_key_alphabet = ""
    for ch in ALPHABET:
        got_key_alphabet += plain_to_cipher[ch]
    
    print("\nУгаданный ключ-алфавит:")
    print(got_key_alphabet)

    #Вывод дешифрованного текста:
    decrypted_text = cipher.decrypt(ALPHABET, encrypted_text, got_key_alphabet)
    print("\nДешифрованный текст:")
    print(decrypted_text)

main()