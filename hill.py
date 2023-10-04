import random

from egcd import egcd
from sympy.physics.continuum_mechanics.beam import numpy

alphabet = {'a': 0, 'b': 1, 'c': 2, 'd': 3, 'e': 4, 'f': 5, 'g': 6, 'h': 7, 'i': 8, 'j': 9, 'k': 10, 'l': 11,
            'm': 12, 'n': 13, 'o': 14, 'p': 15, 'q': 16, 'r': 17, 's': 18, 't': 19, 'u': 20, 'v': 21, 'w': 22,
            'x': 23, 'y': 24, 'z': 25}


def encode_hill(message, key):
    """
    Cette fonction chiffre un message selon la technique de Hill
    param message: message à chiffrer
    param key: matrice de chiffrement 2x2
    return: cryptogramme
    """
    letter_value = []
    lst = 0
    it = 0
    message_mod = message.lower()
    for i in message_mod:
        if i in alphabet:
            if it == 0:
                letter_value.append([])
                letter_value[lst].append(alphabet[i])
            elif len(letter_value[lst]) < 2:
                letter_value[lst].append(alphabet[i])
            elif len(letter_value[lst]) == 2:
                letter_value.append([])
                lst += 1
                letter_value[lst].append(alphabet[i])
        else:
            continue
        it += 1
    print(letter_value)
    new_values = []
    for x in letter_value:
        if len(x) == 2:
            nums = numpy.matmul(key, x)
            for a in nums:
                new_values.append(a % 26)
        else:
            new_x = x
            new_x.append(25)
            nums = numpy.matmul(key, new_x)
            for a in nums:
                new_values.append(a % 26)
    print(new_values)
    message_encry = ''
    for n in new_values:
        for k, v in alphabet.items():
            if n == v:
                message_encry += ''.join(k)
            else:
                continue
    return message_encry


def inverse_modulo(number, p):
    """
    Cette fonction implémente l'algorithme d'euclide étendu
    :param p:
    :param number: nombre à inverser
    :return (pgcd, u, v) u*number+v*p = pgcd relation de bézout
    """
    if number == 0:
        return p, 0, 1
    else:
        gcd, u, v = inverse_modulo(p % number, number)
        return gcd, v - (p // number) * u, u


def gcd_euclid(number1, number2):
    """
    Cette fonction implémente l'algorithme d'euclide tel que décrit
    ![ici](https://upload.wikimedia.org/wikipedia/commons/3/3a/Algorithme_PGCD.svg)
    :param number1: premier entier dont il faut calculer le pgcd
    :param number2: second entier dont il faut calculer le pgcd
    :return: le pgcd des deux entiers donnés en argument
    """
    if number2 == 0:
        return number1
    else:
        r = number1 % number2
        return gcd_euclid(number2, r)


def inverse(key):
    """
    Cette fonction calcul la clé de déchiffrement sur base de la clé.
    Pour ce faire, elle calcul la matrice inverse dans l'esapce modulo 26.
    param key: matrice de chiffrement de Hill
    return: matrice de déchiffrement de Hill
    """
    key_inv = []
    det = int(numpy.round(numpy.linalg.det(key)))
    det_inv = egcd(det, 26)[1] % 26
    calc = (det_inv * numpy.round(det * numpy.linalg.inv(key)).astype(int) % 26)
    key_inv.append(list(calc[0]))
    key_inv.append(list(calc[1]))
    return key_inv


def build_key_hill():
    """
    Cette fonction construit une matrice inversible modulo 26 qui peut servir de clé pour le chiffrement de Hill.
    return: matrice inversible dans l'espace modulo 26
    """
    key = []
    lst = 0
    for i in range(4):
        random_nb = random.randint(0, 25)
        if i == 0:
            key.append([])
            key[lst].append(random_nb)
        elif len(key[lst]) < 2:
            key[lst].append(random_nb)
        elif len(key[lst]) >= 2:
            key.append([])
            lst += 1
            key[lst].append(random_nb)
    det = key[0][0] * key[1][1] - key[1][0] * key[0][1]
    if det != 0 and gcd_euclid(det, 26) == 1:
        return key
    else:
        return build_key_hill()


def decode_hill(cryptogramme, key):
    """
    Cette fonction déchiffre un message selon la technique de Hill.
    Elle calcul la clé de déchiffrement et puis l'utilisé pour déchiffrer le cryptogramme.
    param cryptogramme: cryptogramme à déchiffrer
    param key: clé de chiffrement
    return: message en clair
    """
    letter_value = []
    lst = 0
    it = 0
    cryptogramme_mod = cryptogramme.lower()
    for i in cryptogramme_mod:
        if i in alphabet:
            if it == 0:
                letter_value.append([])
                letter_value[lst].append(alphabet[i])
            elif len(letter_value[lst]) < 2:
                letter_value[lst].append(alphabet[i])
            elif len(letter_value[lst]) >= 2:
                letter_value.append([])
                lst += 1
                letter_value[lst].append(alphabet[i])
        else:
            continue
        it += 1

    key_inv = inverse(key)
    new_values = []
    for x in letter_value:
        if len(x) == 2:
            for a in numpy.matmul(key_inv, x) % 26:
                new_values.append(a % 26)
        else:
            continue
    message_clair = ''
    for n in new_values:
        for k, v in alphabet.items():
            if n == v:
                message_clair += ''.join(k)
            else:
                continue

    return message_clair


def cryptanalyse_hill(cryptogramme, mot):
    """
    Cette fonction effectue une cryptanalyse par force brute d'un cryptogramme chiffrer selon Hill.
    Afin de choisir le message décrypté, elle utilise le mot probable.
    param cryptogramme: cryptogramme à cryptanalyser
    param mot: le mot que le message en clair contient
    return: message en clair.
    """
    used_matrix = []
    while True:
        key = build_key_hill()
        message_clair = decode_hill(cryptogramme, key)

        if mot in message_clair and key not in used_matrix:
            print(message_clair)
            used_matrix.append(key)
        else:
            used_matrix.append(key)