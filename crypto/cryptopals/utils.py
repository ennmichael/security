#!/usr/bin/env python3.7


from __future__ import annotations
from typing import (Iterable, List, DefaultDict, Any, Union, NamedTuple, Dict,
                    Mapping, TypeVar, Optional, Callable, Deque)
import statistics
import functools
import itertools
import importlib
import operator
import secrets
import string
import codecs
import random
import sys
import re
import io

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from run_mypy import run_mypy


# These make the REPL experience easier
r = functools.partial(importlib.reload, sys.modules[__name__])
mypy = functools.partial(run_mypy, 'utils.py')


concat: Any = functools.partial(functools.reduce, operator.add)


T = TypeVar('T')


BYTE_MAX = 255
BYTE_BITS = 8


MOST_COMMON_WORDS = [
    b'a', b'and', b'away', b'big', b'blue', b'can', b'come', b'down', b'find',
    b'for', b'funny', b'go', b'help', b'here', b'I', b'in', b'is', b'it',
    b'jump', b'little', b'look', b'make', b'me', b'my', b'not', b'one', b'play',
    b'red', b'run', b'said', b'see', b'the', b'three', b'to', b'two', b'up',
    b'we', b'where', b'yellow', b'you', b'all', b'am', b'are', b'at', b'ate',
    b'be', b'black', b'brown', b'but', b'came', b'did', b'do', b'eat', b'four',
    b'get', b'good', b'have', b'he', b'into', b'like', b'must', b'new', b'no',
    b'now', b'on', b'our', b'out', b'please', b'pretty', b'ran', b'ride',
    b'saw', b'say', b'she', b'so', b'soon', b'that', b'there', b'they', b'this',
    b'too', b'under', b'want', b'was', b'well', b'went', b'what', b'white',
    b'who', b'will', b'with', b'yes', b'after', b'again', b'an', b'any', b'as',
    b'ask', b'by', b'could', b'every', b'fly', b'from', b'give', b'giving',
    b'had', b'has', b'her', b'him', b'his', b'how', b'just', b'know', b'let',
    b'live', b'may', b'of', b'old', b'once', b'open', b'over', b'put', b'round',
    b'some', b'stop', b'take', b'thank', b'them', b'then', b'think', b'walk',
    b'were', b'when', b'always', b'around', b'because', b'been', b'before',
    b'best', b'both', b'buy', b'call', b'cold', b'does', b"don't", b'fast',
    b'first', b'five', b'found', b'gave', b'goes', b'green', b'its', b'made',
    b'many', b'off', b'or', b'pull', b'read', b'right', b'sing', b'sit',
    b'sleep', b'tell', b'their', b'these', b'those', b'upon', b'us', b'use',
    b'very', b'wash', b'which', b'why', b'wish', b'work', b'would', b'write',
    b'your', b'about', b'better', b'bring', b'carry', b'clean', b'cut', b'done',
    b'draw', b'drink', b'eight', b'fall', b'far', b'full', b'got', b'grow',
    b'hold', b'hot', b'hurt', b'if', b'keep', b'kind', b'laugh', b'light',
    b'long', b'much', b'myself', b'never', b'nine', b'only', b'own', b'pick',
    b'seven', b'shall', b'show', b'six', b'small', b'start', b'ten', b'today',
    b'together', b'try', b'warm', b'apple', b'baby', b'back', b'ball', b'bear',
    b'bed', b'bell', b'bird', b'birthday', b'boat', b'box', b'boy', b'bread',
    b'brother', b'cake', b'car', b'cat', b'chair', b'chicken', b'children',
    b'christmas', b'coat', b'corn', b'cow', b'day', b'dog', b'doll', b'door',
    b'duck', b'egg', b'eye', b'farm', b'farmer', b'father', b'feet', b'fire',
    b'fish', b'floor', b'flower', b'game', b'garden', b'girl', b'good-bye',
    b'grass', b'ground', b'hand', b'head', b'hill', b'home', b'horse', b'house',
    b'kitty', b'leg', b'letter', b'man', b'men', b'milk', b'money', b'morning',
    b'mother', b'name', b'nest', b'night', b'paper', b'party', b'picture',
    b'pig', b'rabbit', b'rain', b'ring', b'robin', b'school',
    b'seed', b'sheep', b'shoe', b'sister', b'snow', b'song', b'squirrel',
    b'stick', b'street', b'sun', b'table', b'thing', b'time', b'top', b'toy'
]


PUNCTUATION_REGEX = '\\' + '|\\'.join(string.punctuation)

# More useful would be to look at the frequencies of all possible characters.
# Maybe crypto/Character-frequency-statistics.html would be better.
ENGLISH_LETTER_FREQUENCIES = {
    ord('e'): 12.702,
    ord('t'): 9.056,
    ord('a'): 8.167,
    ord('o'): 7.507,
    ord('i'): 6.966,
    ord('n'): 6.749,
    ord('s'): 6.327,
    ord('h'): 6.094,
    ord('r'): 5.987,
    ord('d'): 4.253,
    ord('l'): 4.025,
    ord('c'): 2.782,
    ord('u'): 2.758,
    ord('m'): 2.406,
    ord('w'): 2.360,
    ord('f'): 2.228,
    ord('g'): 2.015,
    ord('y'): 1.974,
    ord('p'): 1.929,
    ord('b'): 1.492,
    ord('v'): 0.978,
    ord('k'): 0.772,
    ord('j'): 0.153,
    ord('x'): 0.150,
    ord('q'): 0.095,
    ord('z'): 0.074
}


def transpose(i: Iterable[Iterable[T]]) -> Iterable[Iterable[T]]:
    return zip(*i)


def ascii_letters_and_digits() -> Iterable[int]:
    yield from itertools.chain(
        string.ascii_letters.encode(), string.digits.encode()
    )


class InvalidBase64Input(Exception):

    pass


def remove_punctuation(b: bytes) -> bytes:
    return re.sub(PUNCTUATION_REGEX.encode(), b'', b)


def groups(i: Iterable[T], group_length: int) -> Iterable[List[T]]:
    l = list(i)
    while l:
        yield l[:group_length]
        l = l[group_length:]


def xor(b: Iterable[int], key: Iterable[int]) -> Iterable[int]:
    yield from (a ^ b for a, b in zip(b, key))


def single_character_xor(b: Iterable[int], key: int) -> Iterable[int]:
    return xor(b, itertools.repeat(key))


def repeating_key_xor(b: Iterable[int], key: Iterable[int]) -> Iterable[int]:
    return xor(b, itertools.cycle(key))


ScoringMethod = Callable[[bytes], float]


def english_words_score(text: bytes) -> int:
    return sum(1 for w in text.split() if w in MOST_COMMON_WORDS)


def english_letters_score(text: bytes) -> float:
    return histogram_similarity(
        letter_frequencies(text), ENGLISH_LETTER_FREQUENCIES
    )


def break_single_character_xor(
    ciphertext: bytes,
    scoring_method: Optional[ScoringMethod]=None
) -> List[int]:
    def score(key: int) -> float:
        plaintext = bytes(single_character_xor(ciphertext, key))
        if scoring_method is None:
            return english_letters_score(plaintext)
        else:
            return scoring_method(plaintext)
    return sorted(ascii_letters_and_digits(), key=score)


def letter_frequencies(text: bytes) -> Dict[int, int]:
    text = text.lower()
    return {c: text.count(c) for c in string.ascii_lowercase.encode()}


def histogram_similarity(
    hist1: Mapping[int, float],
    hist2: Mapping[int, float]
) -> float:
    assert set(hist1.keys()) == set(hist2.keys())
    differences = (abs(v - hist2[k]) for k, v in hist1.items())
    return 1 / (sum(differences) or 1)


def guess_repeating_xor_key_size(
    ciphertext: Iterable[int],
    num_estimations: int=1,
    min_key_size: int=2,
    max_key_size: int=40
) -> List[int]:
    def estimations(key_size: int) -> Iterable[float]:
        key_sized_blocks = groups(ciphertext, group_length=key_size)
        chunks = groups(key_sized_blocks, group_length=2)
        for a, b in itertools.islice(chunks, num_estimations):
            yield edit_difference(a, b) / key_size

    return sorted(
        range(min_key_size, max_key_size + 1),
        key=lambda key_size: statistics.mean(estimations(key_size))
    )


OneOrManyInts = TypeVar('OneOrManyInts', int, Iterable[int])


def edit_difference(a: OneOrManyInts, b: OneOrManyInts) -> int:
    if isinstance(a, int):
        return true_bits(a ^ b, bit_count=BYTE_BITS)
    else:
        return sum(edit_difference(i, j) for i, j in zip(a, b))


def true_bits(x: int, bit_count: int) -> int:
    return sum(1 for i in range(bit_count) if x & (2 ** i))


def break_repeating_key_xor(
    ciphertext: Iterable[int],
    key_size: int
) -> List[bytes]:
    def score(key: bytes) -> int:
        plaintext = bytes(repeating_key_xor(ciphertext, key))
        return english_words_score(plaintext)

    d: DefaultDict[int, List[int]] = DefaultDict(list)
    for i, char in enumerate(ciphertext):
        d[i % key_size].append(char)
    result = transpose(break_single_character_xor(bytes(v)) for v in d.values())
    return sorted((bytes(x) for x in result), key=score)


def encrypt_ecb_aes(plaintext: bytes, key: bytes) -> bytes:
    e = Cipher(algorithms.AES(key), modes.ECB(), default_backend()).encryptor()
    return e.update(plaintext) + e.finalize()


def decrypt_ecb_aes(ciphertext: bytes, key: bytes) -> bytes:
    d = Cipher(algorithms.AES(key), modes.ECB(), default_backend()).decryptor()
    return d.update(ciphertext) + d.finalize()


def encrypt_cbc_aes(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    def ciphertext_blocks() -> Iterable[bytes]:
        feedback = encrypt_ecb_aes(iv, key)
        plaintext_blocks = (
            bytes(x) for x in groups(plaintext, group_length=len(key))
        )
        for plaintext_block in plaintext_blocks:
            xor_block = xor(plaintext_block, feedback)
            feedback = encrypt_ecb_aes(bytes(xor_block), key)
            yield feedback
    return b''.join(ciphertext_blocks())


def decrypt_cbc_aes(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    def plaintext_blocks() -> Iterable[bytes]:
        feedback = encrypt_ecb_aes(iv, key)
        ciphertext_blocks = iter(
            bytes(x) for x in groups(ciphertext, group_length=len(key))
        )
        for ciphertext_block in ciphertext_blocks:
            xor_block = decrypt_ecb_aes(ciphertext_block, key)
            yield bytes(xor(xor_block, feedback))
            feedback = ciphertext_block
    return b''.join(plaintext_blocks())


def uses_ecb_aes_128(ciphertext: bytes) -> bool:
    return has_duplicates(
        [bytes(g) for g in groups(ciphertext, group_length=16)]
    )


def has_duplicates(l: List[bytes]) -> bool:
    return any(l.count(x) > 1 for x in l)


def pkcs_7_pad(plaintext: bytes, block_size: int) -> bytes:
    offset = len(plaintext) % block_size
    difference = block_size - offset
    padding = itertools.repeat(difference, difference)
    return plaintext + bytes(padding)


class BadPKCS7Padding(Exception):
    
    pass


def pkcs_7_unpad(plaintext: bytes) -> bytes:
    difference = plaintext[-1]
    if not all(x == difference for x in plaintext[-difference:]):
        raise BadPKCS7Padding(plaintext)
    return plaintext[:-difference]


RANDOM_KEY = secrets.token_bytes(16)
RANDOM_PREFIX = secrets.token_bytes(random.randrange(1, 30))
SECRET_STRING = codecs.decode(
    b''.join([
        b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg',
        b'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq',
        b'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg',
        b'YnkK'
    ]),
    'base64'
)


def oracle(message: bytes) -> bytes:
    message = bytes(pkcs_7_pad(message + SECRET_STRING, block_size=16))
    return encrypt_ecb_aes(message, RANDOM_KEY)


def aes_blocks(text: bytes) -> List[bytes]:
    return [bytes(x) for x in groups(text, group_length=16)]


def last_aes_block(text: bytes) -> bytes:
    return aes_blocks(text)[-1]


def first_aes_block(text: bytes) -> bytes:
    return aes_blocks(text)[0]


pad_aes = functools.partial(pkcs_7_pad, block_size=16)


class NoSecretString(Exception):

    pass


# An alternate implementation. Slower compared to the official solution.
def break_secret_string() -> bytes:
    secret_string_ciphertext = oracle(b'')

    def bruteforce_first_byte(
        ciphertext_block: bytes,
        progress: bytes
    ) -> Optional[int]:
        for byte in range(256):
            message = pad_aes(bytes([byte]) + progress)
            ciphertext = oracle(message)
            new_block = first_aes_block(ciphertext)
            if new_block == ciphertext_block:
                return byte
        return None

    def bruteforce_secret_string(padding_size: int) -> Optional[bytes]:
        progress = b''
        while len(progress) < len(secret_string_ciphertext) - padding_size:
            message = bytes(padding_size + 1 + len(progress))
            ciphertext = oracle(message)
            block_start = len(secret_string_ciphertext)
            block_end = block_start + 16
            block = ciphertext[block_start:block_end]
            byte = bruteforce_first_byte(block, progress)
            if byte:
                progress = bytes([byte]) + progress
            else:
                return None
            if verify_secret_string(progress):
                return progress
        raise NoSecretString

    def verify_secret_string(secret_string: bytes) -> bool:
        secret_string = bytes(pad_aes(secret_string))
        ciphertext = oracle(secret_string)
        l = len(ciphertext)
        return ciphertext[:l//2] == ciphertext[l//2:]

    for padding_size in range(16):
        secret_string = bruteforce_secret_string(padding_size)
        if secret_string and verify_secret_string(secret_string):
            return secret_string
    raise NoSecretString


class CantFindBlockSize(Exception):

    pass


def oracle_block_size(max_block_size: int=80) -> int:
    secret_string_ciphertext = oracle(b'')
    for i in range(max_block_size):
        ciphertext = oracle(bytes(i))
        if len(ciphertext) > len(secret_string_ciphertext):
            return len(ciphertext) - len(secret_string_ciphertext)
    raise CantFindBlockSize


def oracle_uses_ecb() -> bool:
    message = bytes(range(16))
    ciphertext = oracle(message * 2)
    blocks = aes_blocks(ciphertext)
    return blocks[0] == blocks[1]


def parse_url_query(query: bytes) -> Dict[bytes, bytes]:
    return dict(x.split(b'=') for x in query.split(b'&'))


class InvalidEmail(Exception):

    pass


def profile_for(email: bytes) -> bytes:
    if email.count(b'&') or email.count(b'='):
        raise InvalidEmail
    return b'email=' + email + b'&uid=10&role=user'


encrypt_profile = functools.partial(encrypt_ecb_aes, key=RANDOM_KEY)
decrypt_profile = functools.partial(decrypt_ecb_aes, key=RANDOM_KEY)


def parse_encoded_profile(profile_ciphertext: bytes) -> Dict[bytes, bytes]:
    profile_plaintext = decrypt_profile(profile_ciphertext)
    profile_plaintext = pkcs_7_unpad(profile_plaintext, block_size=16)
    return parse_url_query(profile_ciphertext)


def encrypt_profile_for(email: bytes) -> bytes:
    profile = profile_for(email)
    profile = pad_aes(profile)
    return encrypt_profile(profile)


def hard_oracle(message: bytes) -> bytes:
    message = bytes(pkcs_7_pad(
        RANDOM_PREFIX + message + SECRET_STRING, block_size=16
    ))
    return encrypt_ecb_aes(message, RANDOM_KEY)


def break_hard_oracle() -> Iterable[bytes]:
    message_size = 0
    base_ciphertext_size = len(hard_oracle(b''))

    while len(hard_oracle(bytes(message_size))) == base_ciphertext_size:
        message_size += 1

    base_message_size = message_size

    def bruteforce_first_byte(
        ciphertext_block: bytes,
        progress: bytes
    ) -> int:
        for byte in range(256):
            message = pad_aes(bytes([byte]) + progress)
            ciphertext = hard_oracle(bytes(message_size))
            new_block = first_aes_block(ciphertext)
            if new_block == ciphertext_block:
                return byte
        raise NoSecretString

    progress = b''
    while len(progress) < base_ciphertext_size:
        message = bytes(base_message_size)
        ciphertext = hard_oracle(message)
        # For the first iteration, we already have the ciphertext,
        # so we don't actually need the extra call to hard_oracle here.
        # In some real-world situation this might be meaningful.
        block_start = base_ciphertext_size
        block_end = block_start + 16
        block = ciphertext[block_start:block_end]
        byte = bruteforce_first_byte(block, progress)
        message_size += 1
        if byte == 0:
            yield progress
        progress = bytes([byte]) + progress


class InvalidUserData(Exception):

    pass


PREFIX = b'comment1=cooking%20MCs;userdata='
SUFFIX = b';comment2=%20like%20a%20pound%20of%20bacon'
IV = b'YELLOW SUBMARINE'


def some_query(userdata: bytes) -> bytes:
    if userdata.count(b'=') or userdata.count(b';'):
        raise InvalidUserData
    message = pad_aes(PREFIX + userdata + SUFFIX)
    return encrypt_cbc_aes(message, RANDOM_KEY, IV)


def is_admin(query_ciphertext: bytes) -> bool:
    query = decrypt_cbc_aes(query_ciphertext, RANDOM_KEY, IV)
    print(query)
    query = pkcs_7_unpad(query)
    pairs = (x.split(b'=') for x in query.split(b';'))
    return any(k == b'admin' and v == b'true' for k, v in pairs)


def break_some_query() -> bool: 
    ciphertext = some_query(bytes(6))
    ciphertext = ciphertext[:-16]

    def new_control_block() -> Iterable[int]:
        control_block = ciphertext[-32:-16]
        plain_target = b'und%20of%20bacon'
        wanted = b';admin=true\x05\x05\x05\x05\x05'
        for byte, wanted_byte, control_byte in zip(plain_target, wanted, control_block):
            difference = byte ^ wanted_byte
            yield ((~control_byte & difference) | (control_byte & ~difference))

    return is_admin(
        ciphertext[:-32] + bytes(new_control_block()) + ciphertext[-16:]
    )

def read_lines(filename: str) -> Iterable[str]:
    with io.open(filename) as f:
        yield from (l.replace('\n', '') for l in f)


if __name__ == '__main__':
    print(list(break_hard_oracle()))

