from os import environ, system
from sys import stdin

test = environ.get("Test")
print(f"test_enfant2.py: {test}")
assert test is not None
print(len(input("first input:")))
# Affiche la première ligne, n'est pas limité en caractètres
# input("End test_enfant2.py...")

print(stdin.read())  # Récupère tous les inputs jusqu'a la fin

# system('test_enfant.py')
# le stdin du process est un PIPE mais n'est pas le même que celui de ce process
# il faut donc capturer l'input est faire un comunicate dans ce script
