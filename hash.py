import uuid #импорт модуля uuid (используется для генерации случайного числа)
import hashlib #импорт модуля hashlib

#создание функции hash_pass, которая хеширует пароль и добавляет к нему "соль"
def hash_pass(password):
    salt = uuid.uuid4().hex
    return hashlib.sha256(salt.encode() + password.encode()).hexdigest() + ':' + salt

#создание функции check_pass, которая по хешу паролей проверяет их совпадение
def check_pass(hashed_pass, user_pass):
    password, salt = hashed_pass.split(':')
    return password == hashlib.sha256(salt.encode() + user_pass.encode()).hexdigest()

new_pass = input('Input password: ')
hashed_pass = hash_pass(new_pass)
print('Hash: ' + hashed_pass)
old_pass = input('Input password again: ')

#проверка паролей на совпадение по кешам
if check_pass(hashed_pass, old_pass):
    print('Correct password')
else:
    print('Wrong password')

input()
