# Документация по запуску

1) Клонирование репозитория:
```
git clone https://github.com/araldikarev/ciphers-practice.git
```

2) Установка зависимостей:
```
pip install -r requirements.txt
```

3) Запуск программы:
```
python main.py
```

## Вариант через uv:
Запуск основной программы:
```
uv run main.py
```

Запуск алгоритма атаки на шифр на примере 01:
```
uv run -m attacks.01_affine_cipher_brute_force_attack
```