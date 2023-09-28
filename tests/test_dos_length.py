from os import system, name

if name == "nt":
    system("echo " + "a" * 8155)  # OK
    system("echo " + "a" * 8156)  # NOK
    # Documentation say: La longueur maximale de la chaîne que vous pouvez utiliser à l’invite de commandes est de 8 191 caractères
else:
    system("getconf ARG_MAX")
    system("xargs --show-limits </dev/null")

exit(0)

for a in range(1000, 8191):
    b = system("echo " + "a" * a)
    if b:
        print(a)
        break
