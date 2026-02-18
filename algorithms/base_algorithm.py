from abc import ABC, abstractmethod


class AlgorithmBase(ABC):
    """
    Интерфейс для выбора алгоритма.
    """

    @abstractmethod
    def get_name(self):
        pass

    @abstractmethod
    def get_description(self):
        pass

    @abstractmethod
    def get_arguments_to_setup(self):
        pass

    @abstractmethod
    def encrypt(self, *args):
        pass

    @abstractmethod
    def decrypt(self, *args):
        pass
