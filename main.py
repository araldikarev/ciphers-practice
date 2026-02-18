from algorithms.base_algorithm import AlgorithmBase
from algorithms.replacement_cipher import SimpleReplacementCipher
from algorithms.affine_cipher import AffineCipher
from algorithms.recursive_affine_cipher import RecursiveAffineCipher

from InquirerPy import inquirer
from prompt_toolkit.validation import Validator, ValidationError

alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

print(f"Стандартный алфавит: {alphabet}\n")


def main():
    ciphers = [SimpleReplacementCipher, AffineCipher, RecursiveAffineCipher]

    dict_parameters = {}

    for cipher in ciphers:
        instance: AlgorithmBase = cipher()
        name_of_cipher = instance.get_name()

        dict_parameters[name_of_cipher] = instance

    while True:
        action_choice = inquirer.select(
            message="Выберите действие:",
            choices=["Зашифровать", "Расшифровать", "Выход"],
            default="Зашифровать",
        ).execute()

        match action_choice:
            case "Выход":
                break
            case _:
                pass

        cipher_choice = inquirer.select(
            message="Выберите шифр:", choices=dict_parameters.keys()
        ).execute()

        cipher: AlgorithmBase = dict_parameters[cipher_choice]
        arguments: dict = cipher.get_arguments_to_setup()

        args_values = []

        def ask_parsed_after_validation(argument_name: str, parse):
            cached_parsed_value = {}

            class V(Validator):
                def validate(self, document):
                    if document.text == "":
                        raise ValidationError(
                            message="Значение не может быть пустым", cursor_position=0
                        )
                    try:
                        cached_parsed_value["value"] = parse(document.text)
                    except Exception as ex:
                        raise ValidationError(
                            message=str(ex), cursor_position=len(document.text)
                        )

            inquirer.text(
                message=f'Введите значения для "{argument_name}": ', validate=V()
            ).execute()

            return cached_parsed_value["value"]

        for argument, parse in arguments.items():
            parsed_value = ask_parsed_after_validation(argument, parse)
            args_values.append(parsed_value)

        try:
            match action_choice:
                case "Зашифровать":
                    print(f"\nРезультат зашифрования: {cipher.encrypt(*args_values)}\n")
                case "Расшифровать":
                    print(
                        f"\nРезультат расшифрования: {cipher.decrypt(*args_values)}\n"
                    )
                case _:
                    pass
        except Exception as ex:
            print(f"\nПроизошла ошибка при выполнении: {ex}\n")

    print("Завершение программы.")


if __name__ == "__main__":
    main()
