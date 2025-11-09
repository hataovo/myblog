+++
title = "MoeCTF 2025 Crypto WP"
date = "2025-10-12"
description = "MoeCTF 2025 Crypto 方向题目解析"
categories = ["WP"]
tags = ["Crypto"]
image="fengmian.png"
+++

**写在前面的一些话**<br >
这是我真正意义上参加的第一场ctf比赛，通过两个月左右的学习，实践，从零开始踏入了这扇门，有乐趣，有坐牢......总之，通过moe，受益匪浅，未来再接再厉<br >
这次moe，其实五个方向题目都去尝试做了做，最后还是觉得crypto最适合，就以此为主要方向吧，至于题目，确实对于新手友好，感觉cry于新手最好的一点就是不需要各种工具，装个python，装个vscode就能开工了，然后边做题边了解密码学知识或是数学知识<br >
总之，这次的crypto一共19道题，大部分难度适中，多花花时间，或是借助ai，都能应付得来，有几道分组密码比较繁琐，个人不是很喜欢 : (<br >

### Crypto入门指北
题目
```python
from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes, random
from Crypto.Util.number import *
from random import *
from secret import flag


def generate_elgamal_keypair(bits=512):
    p = getPrime(bits)

    for _ in range(1000):
        g = getRandomRange(2, 5)
        if pow(g, (p - 1) // 2, p) != 1:
            break

    x = randrange(2, p - 1)
    y = pow(g, x, p)

    return p, g, y, x


key = generate_elgamal_keypair(bits=512)
p, g, y, x = key

print("=== 公钥 (p, g, y) ===")
print("p =", p)
print("g =", g)
print("y =", y)
print()

k = randrange(1, p - 2)
m = bytes_to_long(flag)
c1 = pow(g, k, p)
c2 = (m * pow(y, k, p)) % p

print("=== 密文 (c1, c2) ===")
print("c1 =", c1)
print("c2 =", c2)
#不小心把x输出了()
print("x =", x)
"""
=== 公钥 (p, g, y) ===
p =
115409637159621449517635782553574175289667159048490149855475976576983048910448410
99894993117258279094910424033273299863589407477091830213468539451196239863
g = 2
y =
831342478336601128701462358277352159533328529138054068946707321221293164841558006
5207081449784135835711205324186662482526357834042013400765421925274271853
=== 密文 (c1, c2) ===
c1 =
665205355305564535827536225955485652597693184131825115294046454317510856013294961
0916012490837970851191204144757409335011811874896056430105292534244732863
c2 =
231491356808152642824798171910095233144493885239903182663547597194748466341836253
3363591441216570597417789120470703548843342170567039399830377459228297983
x =
801095707808655428402095966412478447961091359656003501195114326955976122911402773
8791440961864150225798049120582540951874956255115884539333966429021004214
"""
```
由于私钥直接输出出来了，所以直接按正常ElGamal流程解密就好了

exp
```python
from Crypto.Util.number import inverse, long_to_bytes

p = 
g = 
y = 
c1 = 
c2 = 
x = 

c11 = pow(c1, x, p)
c11_1 = inverse(c11, p)
m = (c2 * c11_1) % p
m = long_to_bytes(m)
print(m)
# moectf{th1s_1s_y0ur_f1rst_ElG@m@l}
```
### ez_DES
题目
```python
from Crypto.Cipher import DES
import secrets
import string

flag = 'moectf{???}'
characters = string.ascii_letters + string.digits + string.punctuation
key = 'ezdes'+''.join(secrets.choice(characters) for _ in range(3))
assert key[:5] == 'ezdes'
key = key.encode('utf-8')
l = 8

def encrypt(text, key):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_text = text + (l - len(text) % l) * chr(len(text))
    data = cipher.encrypt(padded_text.encode('utf-8'))
    return data

c = encrypt(flag, key)
print('c =', c)

# c = b'\xe6\x8b0\xc8m\t?\x1d\xf6\x99sA>\xce \rN\x83z\xa0\xdc{\xbc\xb8X\xb2\xe2q\xa4"\xfc\x07'
```
这个加密代码使用的DES就是标准的Crypto.Cipher里面的DES，所以解密的话，只需要知道密钥就能直接调用解密函数了<br >
能清楚地看出密钥key有8位，并且前五位已知，剩余三位来自定义好的characters，那么直接爆破密钥就好了

exp
```python
import string
from Crypto.Cipher import DES

c = b'\xe6\x8b0\xc8m\t?\x1d\xf6\x99sA>\xce \rN\x83z\xa0\xdc{\xbc\xb8X\xb2\xe2q\xa4"\xfc\x07'
characters = string.ascii_letters + string.digits + string.punctuation

for c1 in characters:
    for c2 in characters:
        for c3 in characters:
            key = ('ezdes' + c1 + c2 + c3).encode('utf-8')
            cipher = DES.new(key, DES.MODE_ECB)
            try:
                decrypted = cipher.decrypt(c).decode('utf-8')
                if 'moectf{' in decrypted:
                    print("Key:", key)
                    print("Flag:", decrypted)
                    exit(0)
            except UnicodeDecodeError:
                pass
# moectf{_Ju5t envmEra+e.!}
```
### baby_next
题目
```python
from Crypto.Util.number import *
from gmpy2 import next_prime
from functools import reduce
from secret import flag

assert len(flag) == 38
assert flag[:7] == b'moectf{'
assert flag[-1:] == b'}'

def main():
    p = getPrime(512)
    q = int(reduce(lambda res, _: next_prime(res), range(114514), p))

    n = p * q
    e = 65537

    m = bytes_to_long(flag)

    c = pow(m, e, n)

    print(f'{n = }')
    print(f'{c = }')

if __name__ == '__main__':
    main()

"""
n = 96742777571959902478849172116992100058097986518388851527052638944778038830381328778848540098201307724752598903628039482354215330671373992156290837979842156381411957754907190292238010742130674404082688791216045656050228686469536688900043735264177699512562466087275808541376525564145453954694429605944189276397
c = 17445962474813629559693587749061112782648120738023354591681532173123918523200368390246892643206880043853188835375836941118739796280111891950421612990713883817902247767311707918305107969264361136058458670735307702064189010952773013588328843994478490621886896074511809007736368751211179727573924125553940385967
"""
```
关键代码`q = int(reduce(lambda res, _: next_prime(res), range(114514), p))`<br >
这句代码的意思就是,以p为起点,计算114514次next_prime(),结果赋给q<br >
由于p是512位的素数,114514次next_prime()后,q并不会比p大很多,也就是说q和p很接近,有了这个信息就可以对n进行分解<br >
由于q和p很接近,而n是p和q的乘积,所以q和p和根号n都很接近,而且p小于根号n,q大于根号n
那么我们就可以从根号n开始,寻找q,找到后就按流程解密就好<br >

exp
```python
from gmpy2 import isqrt, next_prime
from Crypto.Util.number import inverse, long_to_bytes

n = 
c = 
e = 
sqrt_n = isqrt(n)
q1 = next_prime(sqrt_n)
for i in range(1000000):
    if n % q1 == 0:
        print(q1)
        q = q1
        break
     else:
        print("wrong")
        q1 = next_prime(q1)
p = n // q # 需要用 // 除法,用 / 的话精度有问题
phi = (p - 1) * (q - 1)
d = inverse(e, phi)
m = pow(c, d, n)
m = long_to_bytes(m)
print(m)
# moectf{vv0W_p_m1nu5_q_i5_r34l1y_sm4lI}
```
### ezBSGS
题目<br >
x是能够满足神秘式子$13^x = 114514 \mod 100000000000099$的最小整数，flag内容即为x<br >

利用bsgs算法求解离散对数问题，放一个链接<br ><a>https://blog.csdn.net/qq_58207591/article/details/123954286</a><br >
这里直接用了现成的bsgs脚本解题了<br >
exp
```python
p = 100000000000099
a = 13
b = 114514
def bsgs(a, b, m):
    from math import isqrt
    a %= m
    b %= m
    if b == 1:
        return 0
    n = isqrt(m) + 1
    value = {}
    an = pow(a, n, m)
    cur = b
    for q in range(n):
        value[cur] = q
        cur = cur * a % m
    cur = an
    for p in range(1, n + 2):
        if cur in value:
            return p * n - value[cur]
        cur = cur * an % m
    return -1

print(bsgs(a, b, p))
# moectf{18272162371285}
```
后来试了试发现a不是p的原根，不过这对bsgs求解似乎不影响
```python
p = 100000000000099
a = 13
b = 114514
phi = p - 1
factors = [2, 3, 11, 19, 26581605529] # sagemath分解

for q in factors:
    print(pow(a, phi // q, p))
    if pow(a, phi // q, p) == 1:
        is_primitive_root = False
    break
else:
    is_primitive_root = False
# a不是p的原根
```
### ez_square
题目
```python
from Crypto.Util.number import *
from secret import flag

assert len(flag) == 35
assert flag[:7] == b'moectf{'
assert flag[-1:] == b'}'

def main():
    p = getPrime(512)
    q = getPrime(512)

    n = p * q
    e = 65537

    m = bytes_to_long(flag)

    c = pow(m, e, n)
    hint = pow(p + q, 2, n)

    print(f'{n = }')
    print(f'{c = }')
    print(f'{hint = }')

if __name__ == '__main__':
    main()

"""
n = 83917281059209836833837824007690691544699901753577294450739161840987816051781770716778159151802639720854808886223999296102766845876403271538287419091422744267873129896312388567406645946985868002735024896571899580581985438021613509956651683237014111116217116870686535030557076307205101926450610365611263289149
c = 69694813399964784535448926320621517155870332267827466101049186858004350675634768405333171732816667487889978017750378262941788713673371418944090831542155613846263236805141090585331932145339718055875857157018510852176248031272419248573911998354239587587157830782446559008393076144761176799690034691298870022190
hint = 5491796378615699391870545352353909903258578093592392113819670099563278086635523482350754035015775218028095468852040957207028066409846581454987397954900268152836625448524886929236711403732984563866312512753483333102094024510204387673875968726154625598491190530093961973354413317757182213887911644502704780304
"""
```
RSA类型题目,给了一个`hint = pow(p + q, 2, n)`额外信息,对此进行一些处理<br >
$$
(p + q)^2 \equiv \text{hint} \pmod{n}
$$

$$
(p + q)^2 = \text{hint}+ k \cdot n
$$
而$(p + q)^2$和n应当相差不是特别大,因此可以从k出发,通过判断$1 + k \cdot n$是否是平方数去寻找$(p + q)^2$的值<br >

exp
```python
from gmpy2 import isqrt
from Crypto.Util.number import inverse, long_to_bytes

n = 
c = 
hint = 
for i in range(1, 100):
    square = i * n + hint   
    if (isqrt(square) ** 2 == square):
        sqrt = isqrt(square)
        break
    else:
        print("wrong") 

# sqrt = p + q
phi = n - sqrt + 1
e = 65537
d = inverse(e, phi)
m = pow(c, d, n)
m = long_to_bytes(m)
print(m)
# moectf{Ma7hm4t1c5_is_@_k1nd_0f_a2t}
```
### ezAES
题目
```python
from secret import flag

rc = [0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef,0xf1]

s_box = [
	[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
	[0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
	[0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
	[0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
	[0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
	[0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
	[0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
	[0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
	[0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
	[0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
	[0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
	[0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
	[0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
	[0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
	[0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
	[0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
]

s_box_inv = [
	[0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
	[0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
	[0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
	[0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
	[0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
	[0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
	[0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
	[0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
	[0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
	[0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
	[0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
	[0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
	[0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
	[0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
	[0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
	[0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]
]

def sub_bytes(grid):
    for i, v in enumerate(grid):
        grid[i] = s_box[v >> 4][v & 0xf]

def shift_rows(grid):
    for i in range(4):
        grid[i::4] = grid[i::4][i:] + grid[i::4][:i]
        grid =grid[0::4]+grid[1::4]+grid[2::4]+grid[3::4]

def mix_columns(grid):
    def mul_by_2(n):
        s = (n << 1) & 0xff
        if n & 128:
            s ^= 0x1b
        return s

    def mul_by_3(n):
        return n ^ mul_by_2(n)

    def mix_column(c):
        return [
            mul_by_2(c[0]) ^ mul_by_3(c[1]) ^ c[2] ^ c[3],  # [2 3 1 1]
	    c[0] ^ mul_by_2(c[1]) ^ mul_by_3(c[2]) ^ c[3],  # [1 2 3 1]
	    c[0] ^ c[1] ^ mul_by_2(c[2]) ^ mul_by_3(c[3]),  # [1 1 2 3]
	    mul_by_3(c[0]) ^ c[1] ^ c[2] ^ mul_by_2(c[3]),  # [3 1 1 2]
	]

    for i in range(0, 16, 4):
        grid[i:i + 4] = mix_column(grid[i:i + 4])

def key_expansion(grid):
    for i in range(10 * 4):
        r = grid[-4:]
        if i % 4 == 0:  # 对上一轮最后4字节自循环、S-box置换、轮常数异或，从而计算出当前新一轮最前4字节
            for j, v in enumerate(r[1:] + r[:1]):
                r[j] = s_box[v >> 4][v & 0xf] ^ (rc[i // 4] if j == 0 else 0)

        for j in range(4):
            grid.append(grid[-16] ^ r[j])

    return grid

def add_round_key(grid, round_key):
    for i in range(16):
        grid[i] ^= round_key[i]

def encrypt(b, expanded_key):
    # First round
    add_round_key(b, expanded_key)

    for i in range(1, 10):
        sub_bytes(b)
        shift_rows(b)
        mix_columns(b)
        add_round_key(b, expanded_key[i * 16:])

    # Final round
    sub_bytes(b)
    shift_rows(b)
    add_round_key(b, expanded_key[-16:])
    return b


def aes(key, msg):
    expanded = key_expansion(bytearray(key))

    # Pad the message to a multiple of 16 bytes
    b = bytearray(msg + b'\x00' * (16 - len(msg) % 16))
    # Encrypt the message
    for i in range(0, len(b), 16):
        b[i:i + 16] = encrypt(b[i:i + 16], expanded)
    return bytes(b)

if __name__ == '__main__':
    key = b'Slightly different from the AES.'
    enc = aes(key, flag)

    print('Encrypted:', enc)
    #Encrypted: b'%\x98\x10\x8b\x93O\xc7\xf02F\xae\xedA\x96\x1b\xf9\x9d\x96\xcb\x8bT\r\xd31P\xe6\x1a\xa1j\x0c\xe6\xc8'

```
分组密码aes题目，需要对aes加密的流程有一个大致的了解才好做<br >
密钥是直接给了，内容也算是一点提示吧，'和标准aes略微有区别'，(具体有啥区别，写wp的时候太久远了，忘记了...qaq)要解密就是要实现字节代换，行移位，列混和这几种操作的逆向操作，字节代换和行移位的逆向都比较好实现，列混合比较麻烦，不过现有的资料挺多的，拿过来改一改就能用
最后就按加密流程反过来解密<br >

exp
```python
key = b'Slightly different from the AES.'
c = b'%\x98\x10\x8b\x93O\xc7\xf02F\xae\xedA\x96\x1b\xf9\x9d\x96\xcb\x8bT\r\xd31P\xe6\x1a\xa1j\x0c\xe6\xc8'
rc = ...
s_box = ...
s_box_inv = ...


def key_expansion(grid): # 复制
    for i in range(10 * 4):
        r = grid[-4:]
        if i % 4 == 0:  # 对上一轮最后4字节自循环、S-box置换、轮常数异或，从而计算出当前新一轮最前4字节
            for j, v in enumerate(r[1:] + r[:1]):
                r[j] = s_box[v >> 4][v & 0xf] ^ (rc[i // 4] if j == 0 else 0)

        for j in range(4):
            grid.append(grid[-16] ^ r[j])

    return grid


expanded = key_expansion(bytearray(key))

def inv_shift_rows(grid):
    for i in range(4):
        grid[i::4] = grid[i::4][-i:] + grid[i::4][:-i]
        grid = grid[0::4] + grid[1::4] + grid[2::4] + grid[3::4]


def inv_sub_bytes(grid):
    for i, v in enumerate(grid):
        grid[i] = s_box_inv[v >> 4][v & 0xf]


def add_round_key(grid, round_key):
    for i in range(16):
        grid[i] ^= round_key[i]


def mul(a, b):
    """GF(2^8) 乘法"""
    p = 0
    for i in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit_set:
            a ^= 0x1b
        b >>= 1
    return p


def inv_mix_column(col):
    # 逆列混合矩阵
    # [14 11 13  9]
    # [ 9 14 11 13]
    # [13  9 14 11]
    # [11 13  9 14]
    return [
        mul(col[0], 14) ^ mul(col[1], 11) ^ mul(col[2], 13) ^ mul(col[3], 9),
        mul(col[0], 9) ^ mul(col[1], 14) ^ mul(col[2], 11) ^ mul(col[3], 13),
        mul(col[0], 13) ^ mul(col[1], 9) ^ mul(col[2], 14) ^ mul(col[3], 11),
        mul(col[0], 11) ^ mul(col[1], 13) ^ mul(col[2], 9) ^ mul(col[3], 14),
    ]


def inv_mix_columns(grid):
    for i in range(0, 16, 4):
        grid[i:i + 4] = inv_mix_column(grid[i:i + 4])


def decrypt_block(b, expanded_key):
    add_round_key(b, expanded[-16:])
    inv_shift_rows(b)
    inv_sub_bytes(b)
    for i in range(9, 0, -1):
        add_round_key(b, expanded[i * 16:(i + 1) * 16])
        inv_mix_columns(b)
        inv_shift_rows(b)
        inv_sub_bytes(b)
    add_round_key(b, expanded[:16])
    return b


c = bytearray(c)
for i in range(0, len(c), 16):
    c[i:i + 16] = decrypt_block(c[i:i + 16], expanded)

print(c)
# moectf{Th1s_1s_4n_E4ZY_AE5_!@#}
```
### ezlegendre
题目(输出太长了,就不放出来了)
```python
from Crypto.Util.number import getPrime, bytes_to_long
from secret import flag

p = 258669765135238783146000574794031096183
a = 144901483389896508632771215712413815934

def encrypt_flag(flag):
    ciphertext = []
    plaintext = ''.join([bin(i)[2:].zfill(8) for i in flag])
    for b in plaintext:
        e = getPrime(16)
        d = randint(1,10)
        n = pow(a+int(b)*d, e, p)
        ciphertext.append(n)
    return ciphertext

print(encrypt_flag(flag))
```
由plaintext的生成方式可以看出,这应该是一个01串,所以b要么是0,要么是1<br >
所以n只有两种取值`n = pow(a, e, p)`和`n = pow(a + d, e, p)`,生成的ciphertext是有一个许多整数组成的列表<br >
注意到e和d的取值范围都不大,所以我们可以尝试给出所有的第一种取值方式的n,得到一个list1,然后去遍历ciphertext中的数c,如果c在list1中,那么意味着这一位的b是0,反之则是1<br >
不过,有一个问题要注意,是否存在一种可能,使得n在两种不同取值方式下得到的最终值相等呢?这样就无法通过c来判断这一位到底是0还是1了,这种碰撞的可能性应该是极小的,我们暂时不考虑,如果能正确恢复flag那就没什么事情了<br >

exp
```python
import sympy

p = 258669765135238783146000574794031096183
a = 144901483389896508632771215712413815934
primes16 = list(sympy.primerange(2**15, 2**16))
list1 = []
for e in primes16:
    n = pow(a, e, p)
    list1.append(n)
path = 'ezlegendre_output.txt'
with open(path) as f:
    ciphertext = eval(f.read())
ans = ''
for c in ciphertext:
    if c in list1:
        ans = ans + '0'
    else:
        ans = ans + '1'

bytes_list = [int(ans[i:i + 8], 2) for i in range(0, len(ans), 8)]
flag = bytes(bytes_list)
print(flag)
# moectf{Y0u_h@v3_ju5t_s01v3d_7h1s_pr0b13m!}
```
### ez_det
题目(输出太长了,就不放出来了)
```python
from random import randrange
from Crypto.Util.number import *
from sage.all import*
from secret import flag


m_blocks = [bytes_to_long(flag), 0, 0, 0, 0]
p = getPrime(128)

def make_mask(n, p):
    upper = identity_matrix(n)
    low   = identity_matrix(n)
    for i in range(n-1):
        for j in range(i+1, n):
            upper[i, j] = randrange(1, p)
            low[j, i]   = randrange(1, p)
    result = upper * low
    assert det(result) == 1
    return result

def matrix_to_list(mat):
    return [list(row) for row in mat]

Noise = [[randrange(1, p) for _ in range(5)] for _ in range(4)]
Noise.append(m_blocks)

M = matrix(Noise)
A = make_mask(5, p)
C = A * M

print(f"Noise1={Noise[:4]}")
print(f"C={matrix_to_list(C)}")
```
分析make_mask函数，可以看出upper是一个上三角矩阵，low是一个下三角矩阵，且两个矩阵的主对角线都是1，返回的result，也就是A矩阵，是一个阶为5的方阵，A矩阵的内容没什么特别的，特殊之处是A的行列式为1<br >
M矩阵，由Noise得来，也是一个5阶方阵，分析代码可以看出，上面的4行5列都是一些随机的数，第五行是flag和4个0<br >
C矩阵，由A和M相乘得到，也是5阶方阵<br >
现在，M矩阵只有左下角一个flag是未知的，其余全知道，C矩阵已知，由性质：两个矩阵的积的行列式等于两个矩阵的行列式的积,我们可以得出矩阵M的行列式<br >
$$
M =\begin{pmatrix}
a_{11} & a_{12} & a_{13} & a_{14} & a_{15} \\
a_{21} & a_{22} & a_{23} & a_{24} & a_{25} \\
a_{31} & a_{32} & a_{33} & a_{34} & a_{35} \\
a_{41} & a_{42} & a_{43} & a_{44} & a_{45} \\
flag & 0 & 0 & 0 & 0
\end{pmatrix}
$$
现以第五行展开计算M的行列式，由公式，a51即为所求<br >
$$
\det(M) = a_{51}A_{51} + a_{52}A_{52} + a_{53}A_{53} + a_{54}A_{54} + a_{55}A_{55} = a_{51}A_{51}
$$
$$
A_{51} = (-1)^{5+1} \cdot M_{51}
$$
$$
\det(M) = a_{51}M_{51}
$$

exp
```python
from Crypto.Util.number import long_to_bytes

Noise1 = ... 
C = ...

C = matrix(C)
M51 = matrix([row[1:5] for row in Noise1])
det_m51 = det(M51)
det_m = det(C) // 1
flag = det_m // det_m51
print(long_to_bytes(flag))
# moectf{D0_Y0u_kn0w_wh@7_4_de7erm1n@n7_1s!}
```
### 杂交随机数
题目
```python
from Crypto.Util.number import bytes_to_long

def lfsr(data, mask):
    mask = mask.zfill(len(data))
    res_int = int(data, base=2)^int(mask, base=2)
    bit = 0
    while res_int > 0:
        bit ^= res_int % 2
        res_int >>= 1

    res = data[1:]+str(bit)
    return res

def lcg(x, a, b, m):
    return (a*x+b)%m

flag = b'moectf{???}'

x = bin(bytes_to_long(flag))[2:].zfill(len(flag)*8)
l = len(x)//2
L, R = x[:l], x[l:]
b = -233
m = 1<<l

for _ in range(2025):
    mask = R
    seed = int(L, base=2)
    L = lfsr(L, mask)
    R = bin(lcg(int(R, base=2), b, seed, m))[2:].zfill(l)
    L, R = R, L

en_flag = L+R
print(int(en_flag, base=2))
# en_flag = 4567941593066862873653209393990031966807270114415459425382356207107640
```
这道题的加密过程比较清晰，将字符串分为左右两半，用lfsr和lcg两个函数对左右两半进行2025轮处理后得到密文<br >
lfsr中的bit相当于一个校验位，用于标志data和mask异或后的结果中1的个数的奇偶性<br >
解密思路就是把加密流程倒过来，从最后一轮开始逆着往回推<br >
需要特别注意的是，在利用校验位的性质时，可能构造的两个结果都能通过校验而并非唯一，因此需要一个回溯机制才能找到正确解<br >
exp
```python
from Crypto.Util.number import long_to_bytes

en_flag_val = 4567941593066862873653209393990031966807270114415459425382356207107640
en_flag_bin = bin(en_flag_val)[2:]
l = len(en_flag_bin) // 2
L = en_flag_bin[:l]
R = en_flag_bin[l:]
m = 1 << l
b = -233
b_ = pow(b, -1, m)


def decrypt_step(l1, r1):
    x = l1[:-1]
    bit = l1[-1]
    possible = []
    for a in ['0', '1']:
        l0 = a + x
        L_int = int(l0, 2)
        R_int = (int(r1, 2) - L_int) * b_ % m
        r0 = bin(R_int)[2:].zfill(l)
        xor_val = L_int ^ int(r0, 2)
        parity_bit = bin(xor_val).count('1') % 2
        if parity_bit == int(bit):
            possible.append((l0, r0))
    return possible


stack = []
stack.append((L, R, 0))

while stack:
    L_cur, R_cur, step = stack.pop()
    if step == 2025:
        flag_bin = L_cur + R_cur
        flag_int = int(flag_bin, 2)
        flag = long_to_bytes(flag_int)
        if flag.startswith(b'moectf{') and flag.endswith(b'}'):
            print(flag.decode())
            break
        else:
            continue
    L_prev, R_prev = R_cur, L_cur
    pairs = decrypt_step(L_prev, R_prev)
    for pair in pairs:
        stack.append((pair[0], pair[1], step + 1))
# moectf{I5_1t_Stream0rBlock.?}
```
### 沙茶姐姐的Fufu
题目
现在有 $N$ $(1 \leq N \leq 10^3)$ 只 Fufu 在沙茶姐姐的购物清单上，每只 Fufu 能且仅能购买一次，其中第 $i$ 只 Fufu 的可爱程度为 $w_i$ $(1 \leq w_i \leq 10^9)$，每只 Fufu 还有一个“保养难度” $c_i$ $(1 \leq c_i \leq 10^4)$。沙茶姐姐的精力 $M$ $(1 \leq M \leq 10^4)$ 有限，也就是沙茶姐姐持有的所有 Fufu 的保养难度的总和不能大于 $M$，但她又想买入总可爱度尽可能多的 Fufu。现在，她把这个问题交给了你，请你帮她算算总可爱度最多可以是多少。<br >
形式化地，你需要求出给定的 $N$ 只 Fufu 的一个子集 $S$ 在满足 $\sum_{i \in S} c_i \leq M$ 的前提下，$\sum_{i \in S} w_i$ 的最大值。<br >
由于沙茶姐姐是一种多维生物，所以你需要为所有 $T$ 个平行宇宙中的沙茶姐姐解决问题，在解决所有沙茶姐姐的问题后，所有问题答案的异或和就是沙茶姐姐给你的报酬——本题Flag的内容。<br >
输入格式<br >
第一行一个整数 $T$。<br >
接下来 $T$ 组数据表示每一个子问题，每组数据第一行两个整数 $N$ 和$M$，接下来 $N$ 行每行两个整数 $c_i$和$w_i$描述一个 Fufu。<br >

抽象一下，就是一个背包问题，M是背包的容量，ci代表装的东西的大小，wi代表装的东西的价值，目的就是求出不超过总容量的情况下，装的东西的价值的最大值，且每个物品只能装一次
这个经典的01背包问题需要用动态规划算法来求解<br >

exp
```python
def solve(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()

    idx = 0
    T = int(lines[idx].strip())
    idx += 1
    results = []
    for _ in range(T):
        N, M = map(int, lines[idx].strip().split())
        idx += 1
        items = []
        for _ in range(N):
            a, b = map(int, lines[idx].strip().split())
            items.append((a, b))
            idx += 1

        dp = [[0] * (M + 1) for _ in range(N + 1)]
        for i in range(1, N + 1):
            for j in range(1, M + 1):
                if j < items[i - 1][0]:
                    dp[i][j] = dp[i - 1][j]
                else:
                    data1 = dp[i - 1][j]
                    data2 = dp[i - 1][j - items[i - 1][0]] + items[i - 1][1]
                    dp[i][j] = max(data1, data2)
        results.append(dp[N][M])

    ans = 0
    for res in results:
        ans ^= res
    print(ans)

solve('./fufu_in.txt')
# moectf{34765768752}
```
### happyRSA
题目
```python
from Crypto.Util.number import getPrime, bytes_to_long
from random import randint
from sympy import totient
from secret import flag

def power_tower_mod(a, k, m):  # a↑↑k mod m
    if k == 1:
        return a % m
    exp = power_tower_mod(a, k - 1, totient(m))
    return pow(a, int(exp), int(m))


p = getPrime(512)
q = getPrime(512)
r = 123456
n = p * q
e = 65537
n_phi= p+q-1
x=power_tower_mod(n_phi + 1, r, pow(n_phi, 3))
m = bytes_to_long(flag)
c = pow(m, e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")
print(f"x = {x}")

'''
n = 128523866891628647198256249821889078729612915602126813095353326058434117743331117354307769466834709121615383318360553158180793808091715290853250784591576293353438657705902690576369228616974691526529115840225288717188674903706286837772359866451871219784305209267680502055721789166823585304852101129034033822731
e = 65537
c = 125986017030189249606833383146319528808010980928552142070952791820726011301355101112751401734059277025967527782109331573869703458333443026446504541008332002497683482554529670817491746530944661661838872530737844860894779846008432862757182462997411607513582892540745324152395112372620247143278397038318619295886
x = 522964948416919148730075013940176144502085141572251634384238148239059418865743755566045480035498265634350869368780682933647857349700575757065055513839460630399915983325017019073643523849095374946914449481491243177810902947558024707988938268598599450358141276922628627391081922608389234345668009502520912713141
'''
```
定义了一个指数塔，实现代码细节没细看，但是知道指数塔是怎么一回事就行，例如$2 \uparrow\uparrow 4 = 2^{2^{2^{2}}} = 2^{2^{4}} = 2^{16} = 65536$，注意算的时候是从上往下算<br >
核心代码`x=power_tower_mod(n_phi + 1, r, pow(n_phi, 3))`，实质上就是在求(p+q)的r次指数塔模pow(n_phi, 3)<br >
$$
(p+q) \uparrow\uparrow r = (p+q)^{(p+q)^{(p+q)^{...}}} =  (p+q)^{k_1} =  (p+q-1+1)^{k_1} 
$$
二项式定理
$$
(p+q-1+1)^{k_1} \equiv 1 + k_1(p+q-1) + \frac{k_1(k_1-1)}{2}(p+q-1)^2 \pmod{(p+q-1)^3}
$$
同样的有
$$
k_1 =  (p+q)^{k_2} =  (p+q-1+1)^{k_2} \\
k_1 \equiv 1 + k_2(p+q-1) + \frac{k_2(k_2-1)}{2}(p+q-1)^2 \pmod{(p+q-1)^3} 
$$
代入上面的式子可得
$$
(p+q-1+1)^{k_1} \equiv 1 +(p+q-1)+ k_2(p+q-1)^2 \pmod{(p+q-1)^3}
$$
同样的，可以把k2展开成k3再次带入，可以得到最终结果
$$
(p+q-1+1)^{k_1} \equiv 1 +(p+q-1)+ (p+q-1)^2 \pmod{(p+q-1)^3} \\
$$
注意到$1 +(p+q-1)+ (p+q-1)^2 <{(p+q-1)^3}$，所以$1 +(p+q-1)+ (p+q-1)^2 = x$，解一个一元二次方程就能得到p+q了<br >

exp
```python
import gmpy2
from Crypto.Util.number import long_to_bytes
n = 
e = 
c = 
x = 
c1 = 1 - x
a = 1
b = 1
delta = b * b - 4 * a * c1
x1 = ((-1) * b + gmpy2.isqrt(delta)) // (2 * a)  # 取正根
phi = n - x1
d = pow(e, -1, int(phi))
m = pow(c, d, n)
print(long_to_bytes(m))
# moectf{rsa_and_s7h_e1se}
```
### (半^3)部电台
题目
```python
from random import choice
from Crypto.Util.number import bytes_to_long, long_to_bytes

with open('flag.txt', 'r') as file:
    flag = file.read()


class MACHINE:

    def __init__(self):
        self.alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ ,.!?()\n'

        self.IP = [
            58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62,
            54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49,
            41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45,
            37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
        ]

        self.IP_inv = [self.IP.index(i) + 1 for i in range(1, 65)]

        self.S1 = [
            14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4,
            14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11,
            15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14,
            10, 0, 6, 13
        ]
        self.S2 = [
            15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7,
            15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13,
            1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7,
            12, 0, 5, 14, 9
        ]
        self.S3 = [
            10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9,
            3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0,
            11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3,
            11, 5, 2, 12
        ]
        self.S4 = [
            7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5,
            6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13,
            15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11,
            12, 7, 2, 14
        ]
        self.S5 = [
            2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2,
            12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7,
            8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0,
            9, 10, 4, 5, 3
        ]
        self.S6 = [
            12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2,
            7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3,
            7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7,
            6, 0, 8, 13
        ]
        self.S7 = [
            4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7,
            4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14,
            10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15,
            14, 2, 3, 12
        ]
        self.S8 = [
            13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8,
            10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2,
            0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0,
            3, 5, 6, 11
        ]
        self.S = [
            self.S1, self.S2, self.S3, self.S4, self.S5, self.S6, self.S7,
            self.S8
        ]

        self.E = [
            32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13,
            14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24,
            25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
        ]

        self.P = [
            16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8,
            24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
        ]

        self.PC_1 = [
            57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59,
            51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23,
            15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13,
            5, 28, 20, 12, 4
        ]

        self.PC_2 = [
            14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33,
            48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
        ]

        self.shift_num = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

        self.key = ''.join(choice(self.alphabet) for _ in range(8))
        self.subkey = self.generate_key(self.key.encode())

    def generate_key(self, ori_key):
        key = bin(bytes_to_long(ori_key))[2:].zfill(64)
        subkeys = []
        temp = [key[i - 1] for i in self.PC_1]
        for i in self.shift_num:
            temp[:28] = temp[:28][i:] + temp[:28][:i]
            temp[28:] = temp[28:][i:] + temp[28:][:i]
            subkeys.append(''.join(temp[j - 1] for j in self.PC_2))
        return subkeys

    def encrypt(self, text):
        if isinstance(text, str):
            text = text.encode()
        bin_flag = ''.join([bin(byte)[2:].zfill(8) for byte in text])

        padded_len = (64 - (len(bin_flag) % 64)) % 64
        padded_flag = bin_flag + '0' * padded_len

        cate_text = [
            padded_flag[i * 64:(i + 1) * 64]
            for i in range(0,
                           len(padded_flag) // 64)
        ]

        encrypted_text = ''
        for text in cate_text:
            t = ''.join(text[i - 1] for i in self.IP)
            L, R = t[:32], t[32:]

            for cnt in range(2):
                R_temp = R
                k = self.subkey[cnt]
                R_expanded = ''.join(R[i - 1] for i in self.E)
                R_xor = [
                    str(int(R_expanded[i]) ^ int(k[i])) for i in range(48)
                ]
                R_groups = [R_xor[i:i + 6] for i in range(0, 48, 6)]
                res = ''
                for i in range(8):
                    row = int(R_groups[i][0] + R_groups[i][5], base=2)
                    col = int(''.join(R_groups[i][1:5]), base=2)
                    int_res = self.S[i][16 * row + col]
                    res += bin(int_res)[2:].zfill(4)

                res_p = ''.join(res[i - 1] for i in self.P)
                new_R = ''.join(
                    str(int(res_p[i]) ^ int(L[i])) for i in range(32))
                R = new_R
                L = R_temp

            t = R + L
            t = ''.join(t[i - 1] for i in self.IP_inv)
            encrypted_text += t

        encrypted_bytes = b''
        for i in range(0, len(encrypted_text), 8):
            byte = int(encrypted_text[i:i + 8], 2)
            encrypted_bytes += bytes([byte])
        encrypted_text = encrypted_bytes
        return encrypted_text


machine = MACHINE()
text = ''.join(
    choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ ,.!?()\n')
    for _ in range(80))
en_text = machine.encrypt(text)
en_flag = machine.encrypt(flag)

print("Encrypted flag:", bytes_to_long(en_flag))
print("Random text:", bytes_to_long(text.encode()))
print("Encrypted random text:", bytes_to_long(en_text))

# Random text: 1733571697283962509488226713108269753699322498714010326656310076489877844089729148788129403124099930593602491145395337324365415309638864335256126266980930992016878248102013062728229825856295255
# Encrypted random text: 3578059052586522474100389050030320588160089073371878413925896715373042626307922378489203525965322427489129100605094275877241918595390796602423805072859665451626477779012814084741966341775758398
# Encrypted flag: ...
```
分组密码的题目，类似DES加密算法，不过只有两轮，正好对应题目说的八分之一<br >
输出给了一个明文密文对，和flag的密文，那么我们的思路就是先利用明文密文对恢复出密钥，然后解密flag<br >
由于只有两轮，结合Feistel网络公式，我们可以写出，其中L0,R0,L2,R2是我们已知的<br >
$$
L_1 = R_0 \\
R_1 = L_0 \oplus F(R_0, K_1) \\
L_2 = R_1 \\
R_2 = L_1 \oplus F(R_1, K_2) = R_0 \oplus F(L_2, K_2)
$$
计算一次异或
$$
O_1 = L_0 \oplus L_2 = F(R_0, K_1) \\
O_2 = R_0 \oplus R_2 = F(L_2, K_2)
$$
接下来通过S盒的逆运算，遍历k的值，验证是否等于F的输出，利用多个块的交集确定唯一的K1和K2，具体实现代码可见recover_subkeys()函数<br >
有了K1,K2，下一步就是要想办法恢复密钥key，PC_2会把56位密钥变成48位，大致思路就是从K1和K2通过PC_2的逆操作恢复56位中间状态，由于丢弃了8位，所以有256种可能，再通过循环移位的逆操作得到初始56位状态，通过PC_1的逆操作恢复64位主密钥，利用字母表约束筛选有效密钥，具体实现代码可见recover_main_key()函数<br >
密钥恢复好之后，剩下的就是逆向加密过程实现解密函数，然后解密flag的密文即可<br >

exp
```python
from Crypto.Util.number import bytes_to_long, long_to_bytes
import itertools

IP = 
IP_inv = 
E = 
P = 
PC_1 = 
PC_2 = 
S1 = 
S2 = 
S3 = 
S4 = 
S5 = 
S6 = 
S7 = 
S8 = 
S = [S1, S2, S3, S4, S5, S6, S7, S8]
shift_num = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ ,.!?()\n'
P_inv = [P.index(i) + 1 for i in range(1, 33)]

# 辅助函数
def bytes_to_bin(byte_arr):
    return ''.join(bin(byte)[2:].zfill(8) for byte in byte_arr)


def bin_to_bytes(bin_str):
    n = int(bin_str, 2)
    return long_to_bytes(n)


def permute(bits, perm_table):
    return ''.join(bits[i - 1] for i in perm_table)


def xor_bin(s1, s2):
    return ''.join(str(int(a) ^ int(b)) for a, b in zip(s1, s2))


def left_shift(bits, n):
    return bits[n:] + bits[:n]


def right_shift(bits, n):
    return bits[-n:] + bits[:-n]


def get_S_output(s_box, input_val):
    row = int(input_val[0] + input_val[5], 2)
    col = int(input_val[1:5], 2)
    return s_box[16 * row + col]


def recover_subkeys(plain_blocks, enc_blocks):
    # 初始化K1和K2的候选集合，每个S盒对应一个集合
    K1_candidates = [set(range(64)) for _ in range(8)]
    K2_candidates = [set(range(64)) for _ in range(8)]

    for i in range(len(plain_blocks)):
        P_bin = bytes_to_bin(plain_blocks[i])
        C_bin = bytes_to_bin(enc_blocks[i])

        P_ip = permute(P_bin, IP)
        L0 = P_ip[:32]
        R0 = P_ip[32:]

        C_ip = permute(C_bin, IP)
        R2 = C_ip[:32]
        L2 = C_ip[32:]

        O1 = xor_bin(L0, L2)
        O2 = xor_bin(R0, R2)

        O1_prime = permute(O1, P_inv)
        O2_prime = permute(O2, P_inv)

        # 扩展至48位
        A = permute(R0, E)
        B = permute(L2, E)

        A_groups = [A[j:j + 6] for j in range(0, 48, 6)]
        B_groups = [B[j:j + 6] for j in range(0, 48, 6)]
        O1_groups = [O1_prime[j:j + 4] for j in range(0, 32, 4)]
        O2_groups = [O2_prime[j:j + 4] for j in range(0, 32, 4)]

        # 对于每个S盒，更新K1候选
        for s_idx in range(8):
            possible_k1 = set()
            for k_val in range(64):
                input_val = bin(k_val)[2:].zfill(6)
                xor_val = xor_bin(A_groups[s_idx], input_val)
                s_output = get_S_output(S[s_idx], xor_val)
                if s_output == int(O1_groups[s_idx], 2):
                    possible_k1.add(k_val)
            K1_candidates[s_idx] &= possible_k1
        # 对于每个S盒，更新K2候选
        for s_idx in range(8):
            possible_k2 = set()
            for k_val in range(64):
                input_val = bin(k_val)[2:].zfill(6)
                xor_val = xor_bin(B_groups[s_idx], input_val)
                s_output = get_S_output(S[s_idx], xor_val)
                if s_output == int(O2_groups[s_idx], 2):
                    possible_k2.add(k_val)
            K2_candidates[s_idx] &= possible_k2

    K1 = ''.join(bin(list(K1_candidates[i])[0])[2:].zfill(6) for i in range(8))
    K2 = ''.join(bin(list(K2_candidates[i])[0])[2:].zfill(6) for i in range(8))
    return K1, K2


def recover_main_key(K1, K2):
    PC_2_inv = [0] * 56
    for i in range(48):
        output_bit_pos = i
        input_bit_pos = PC_2[i] - 1
        PC_2_inv[input_bit_pos] = output_bit_pos + 1

    unused_indices = []
    for i in range(56):
        if PC_2_inv[i] == 0:
            unused_indices.append(i)
    # PC_2(C1) = K1
    base_C1 = ['0'] * 56
    for i in range(56):
        if PC_2_inv[i] != 0:
            k_index = PC_2_inv[i] - 1
            base_C1[i] = K1[k_index]

    # 枚举unused_indices的2^8=256种可能
    for bits in itertools.product('01', repeat=8):
        C1 = base_C1[:]
        for idx, bit in zip(unused_indices, bits):
            C1[idx] = bit
        C1_str = ''.join(C1)
        # 检查PC_2(C1)是否等于K1
        if permute(C1_str, PC_2) != K1:
            continue
        # 计算C2 = left_shift(C1, 1)
        C2 = left_shift(C1_str, 1)
        # 检查PC_2(C2)是否等于K2
        if permute(C2, PC_2) == K2:
            # 找到候选C1，现在计算C0 = right_shift(C1_str, 1)
            C0 = right_shift(C1_str, 1)
            # 现在从C0恢复64位密钥：PC_1是从64位选56位，所以需要逆PC_1
            PC_1_inv = [0] * 64
            for i in range(56):
                input_bit_pos = PC_1[i] - 1
                PC_1_inv[input_bit_pos] = i + 1

            unused_key_indices = []
            for i in range(64):
                if PC_1_inv[i] == 0:
                    unused_key_indices.append(i)

            base_key = ['0'] * 64
            for i in range(64):
                if PC_1_inv[i] != 0:
                    c_index = PC_1_inv[i] - 1
                    base_key[i] = C0[c_index]

            # 枚举unused_key_indices的256种可能
            for key_bits in itertools.product('01', repeat=8):
                key_candidate = base_key[:]
                for idx, bit in zip(unused_key_indices, key_bits):
                    key_candidate[idx] = bit
                key_str = ''.join(key_candidate)
                key_bytes = bin_to_bytes(key_str)
                if len(key_bytes) != 8:
                    continue
                # 检查密钥是否在字母表内
                valid = True
                for byte in key_bytes:
                    if byte not in alphabet.encode():
                        valid = False
                        break
                if valid:
                    return key_bytes
    return None
def decrypt_flag(enc_flag_bytes, key):
    machine = MACHINE()
    machine.key = key.decode()
    machine.subkey = machine.generate_key(key)
    decrypted = machine.decrypt(enc_flag_bytes)
    return decrypted

# 稍作修改
class MACHINE:

    def __init__(self):
        self.alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ ,.!?()\n'
        self.IP = IP
        self.IP_inv = IP_inv
        self.S = S
        self.E = E
        self.P = P
        self.PC_1 = PC_1
        self.PC_2 = PC_2
        self.shift_num = shift_num
        self.key = None
        self.subkey = None

    def generate_key(self, ori_key):
        if isinstance(ori_key, str):
            ori_key = ori_key.encode()
        key = bin(bytes_to_long(ori_key))[2:].zfill(64)
        subkeys = []
        temp = [key[i - 1] for i in self.PC_1]
        for i in self.shift_num:
            temp[:28] = temp[:28][i:] + temp[:28][:i]
            temp[28:] = temp[28:][i:] + temp[28:][:i]
            subkeys.append(''.join(temp[j - 1] for j in self.PC_2))
        return subkeys

    def decrypt(self, enc_bytes):
        bin_enc = bytes_to_bin(enc_bytes)
        padded_len = (64 - (len(bin_enc) % 64)) % 64
        padded_enc = bin_enc + '0' * padded_len
        blocks = [
            padded_enc[i * 64:(i + 1) * 64]
            for i in range(len(padded_enc) // 64)
        ]
        decrypted_text = ''
        for block in blocks:
            t = permute(block, self.IP)
            L, R = t[:32], t[32:]
            for cnt in range(1, -1, -1):
                k = self.subkey[cnt]
                R_temp = R
                R_expanded = permute(R, self.E)
                R_xor = xor_bin(R_expanded, k)
                R_groups = [R_xor[i:i + 6] for i in range(0, 48, 6)]
                res = ''
                for i in range(8):
                    row = int(R_groups[i][0] + R_groups[i][5], 2)
                    col = int(''.join(R_groups[i][1:5]), 2)
                    int_res = self.S[i][16 * row + col]
                    res += bin(int_res)[2:].zfill(4)
                res_p = permute(res, self.P)
                new_R = xor_bin(res_p, L)
                R = new_R
                L = R_temp
            t = R + L
            t = permute(t, self.IP_inv)
            decrypted_text += t
        decrypted_bytes = b''
        for i in range(0, len(decrypted_text), 8):
            byte = int(decrypted_text[i:i + 8], 2)
            decrypted_bytes += bytes([byte])
        return decrypted_bytes
text_long = ...
en_text_long = ...
en_flag_long = ...
text_bytes = long_to_bytes(text_long)
en_text_bytes = long_to_bytes(en_text_long)
en_flag_bytes = long_to_bytes(en_flag_long)

block_size = 8
plain_blocks = []
enc_blocks = []
for i in range(0, len(text_bytes), block_size):
    plain_blocks.append(text_bytes[i:i + block_size])
    enc_blocks.append(en_text_bytes[i:i + block_size])

K1, K2 = recover_subkeys(plain_blocks, enc_blocks)
key = recover_main_key(K1, K2)
print(key)
flag = decrypt_flag(en_flag_bytes, key)
print(flag.decode())
```
输出
```
key: b'pr,vnLlH'
Dear Alice,

I hope this message finds you wel1. I鈥檓 writing to tell you that I鈥檝e been participating in Moectf recently ,
it鈥檚 a cybersecurity competition designed for students like you and me. The contest offers various tracks
such as Web, Pwn, and morE.Based on my interest5, I chose the Crypto track.
Since you鈥檝e been my long-time partner in cryptology, I鈥檓 sure you understand how much I wish our communication       
could be free from the threats of cryptographic attackS. Every time we try to connect over the internet, it feels
like there鈥檚 someone trying to steal our informatioN. How frustrating!
That鈥檚 why I believe we should learn more about cryptography to better protect ourselves!. If you agree with my idea,   
please include the flag hidden in this letter in your next replyy. If you鈥檙e not sure what it is, try connecting all    
the characters that come before dots in this letter into one lin3.

Looking forward to hearing from you!
Yours,
Bob

# moectf{1eEkSN!y3}
```
有一点错误，基本上能解密出来，虽然有ai帮忙分析，分组密码还是太难了qaq
### 神秘数字太多了
题目
求最小的正整数N，使得$\underbrace{11\cdots1}_{N\text{个}1} \equiv 114514 \pmod{10000000000099}$<br >

这道题目给了一个提示，bsgs，那就是要往离散对数的方向去靠，想办法构造出指数的形式<br >
注意到<br >
$$
\underbrace{11\cdots1}_{N\text{个}1} = \underbrace{99\cdots9}_{N\text{个}9}/9=(10^N - 1)/ 9
$$
原问题转化为
$$
10^N  \equiv 9*114514+1 \pmod{10000000000099}
$$
bsgs脚本梭哈<br >

exp
```python
def bsgs(a, b, m):
    from math import isqrt
    a %= m
    b %= m
    if b == 1:
        return 0
    n = isqrt(m) + 1
    value = {}
    an = pow(a, n, m)
    cur = b
    for q in range(n):
        value[cur] = q
        cur = cur * a % m
    cur = an
    for p in range(1, n + 2):
        if cur in value:
            return p * n - value[cur]
        cur = cur * an % m
    return -1
mod = 10000000000099
b = 9 * 114514 + 1  
N = bsgs(10, b, mod)
print(N)
# moectf{7718260004383}
```
### ez_lattice
题目(输出太长了,就不放出来了)
```python
from random import randrange
from Crypto.Util.number import getPrime, bytes_to_long
from secret import flag
assert len(flag) % 5 == 0

block_size = len(flag) // 5
m_blocks = [bytes_to_long(flag[i*block_size:(i+1)*block_size])for i in range(5)]
p = getPrime(128)

def make_mask(n, p):
    from sage.all import identity_matrix, det
    upper = identity_matrix(n)
    low   = identity_matrix(n)
    for i in range(n-1):
        for j in range(i+1, n):
            upper[i, j] = randrange(1, p)
            low[j, i]   = randrange(1, p)
    result = upper * low
    assert det(result) == 1
    return result

def matrix_to_list(mat):
    return [list(row) for row in mat]

Noise = [[randrange(1, p) for _ in range(5)] for _ in range(4)]
Noise.append(m_blocks)

M = matrix(Noise)
A = make_mask(5, p)
C = A * M

print(f"p={p}")
print(f"C={matrix_to_list(C)}")
```
代码看上去挺像ez_det那道题的，有几处不同：M的最后一行不同，是把flag分了五段填进来的；输出不同，M的内容不知道，但是知道p的值<br >
这是一道利用格的题目，在格L(M)中，M的最后一行相对于前4行的随机数来说是一个短向量。LLL算法能够将格基约简为一组几乎正交的短向量。在约简后的基中，最短的向量很可能对应格中的原始短向量，即flag的整数块，然后就能恢复flag<br >
但是L(M)未知，但：C = A × M，由于A是整数矩阵且行列式为1，这意味着：<br >
A是可逆的,A的逆矩阵也是整数矩阵<br >
接下来证明L(M) = L(C)，也就是要证下面的式子中的$\mathbf{x} \times A$可以取遍所有$\mathbb{Z}^5$中的向量<br >
$L(C) = \{ \mathbf{x} \times C \mid \mathbf{x} \in \mathbb{Z}^5 \} = \{ \mathbf{x} \times (A \times M) \mid \mathbf{x} \in \mathbb{Z}^5 \} = \{ (\mathbf{x} \times A) \times M \mid \mathbf{x} \in \mathbb{Z}^5 \}$<br >
我们需要证明对于任意$\mathbf{y} \in \mathbb{Z}^5$，存在某个 $\mathbf{x} \in \mathbb{Z}^5$，使得 $\mathbf{x} \times A = \mathbf{y}$。<br >
设 $\mathbf{x} = \mathbf{y} \times A^{-1}$<br >
由于：<br >
$\mathbf{y} \in \mathbb{Z}^5$（整数向量）<br >
$A^{-1}$ 是整数矩阵（因为 $\det(A)=1$）<br >
整数向量乘以整数矩阵的结果仍然是整数向量<br >
因此 $\mathbf{x} = \mathbf{y} \times A^{-1} \in \mathbb{Z}^5$<br >
而且：$\mathbf{x} \times A = (\mathbf{y} \times A^{-1}) \times A = \mathbf{y} \times (A^{-1} \times A) = \mathbf{y} \times I = \mathbf{y}$<br >
这就证明了对于 $\mathbb{Z}^5$ 中的任意向量 $\mathbf{y}$，都存在 $\mathbf{x} \in \mathbb{Z}^5$ 使得 $\mathbf{x} \times A = \mathbf{y}$。<br >

exp
```python
p = ...
C_list = ...

C = matrix(C_list)
L_lll = C.LLL()
v = L_lll[0]
v_abs = [abs(x) for x in v]
from Crypto.Util.number import long_to_bytes
flag = b''
for num in v_abs:
    flag += long_to_bytes(int(num))
print(flag)
# moectf{h0w_P0werfu1_7he_latt1ce_1s}
# 没有用到p
```
### Prime_in_prime
题目(输出没有贴出来)
```python
from Crypto.Util.number import long_to_bytes, bytes_to_long, getPrime
import random, gmpy2
from secret import flag

class RSAEncryptor:
    def __init__(self):
        self.g = self.a = self.b = 0
        self.e = 65537
        self.factorGen()
        self.product()

    def factorGen(self):
        while True:
            self.g = getPrime(256)
            while not gmpy2.is_prime(2*self.g*self.a+1):
                self.a = random.randint(2**255, 2**256)
            while not gmpy2.is_prime(2*self.g*self.b+1):
                self.b = random.randint(2**255, 2**256)
            self.h = 2*self.g*self.a*self.b+self.a+self.b
            if gmpy2.is_prime(self.h):
                self.N = 2*self.h*self.g+1
                print(len(bin(self.N)))
                return

    def encrypt(self, msg):
        return pow(msg, self.e, self.N)


    def product(self):
        self.flag =bytes_to_long(flag)
        self.enc = self.encrypt(self.flag)
        self.show()
        print(f'enc={self.enc}')

    def show(self):
        print(f"N={self.N}")
        print(f"e={self.e}")
        print(f"g={self.g}")


RSAEncryptor()
```
这是一道利用coppersmith定理解决的rsa问题，贴一个链接<a>https://blog.csdn.net/qq_51999772/article/details/123620932</a>可以看相关知识点,个人的理解就是：已知了p的高位，部分低位未知，由于p是N的因子，可以构造多项式 f(x) = p0 + x mod p，这个多项式模p有一个小根x。即使我们不知道p，但是Coppersmith定理在这种情况下依然适用，可以求出x，进而分解N<br >
回到这道题目，首先要注意到<br >
$$
N = 2hg + 1 = 4gagb + 2ga + 2gb + 1 = (2ga+1)*(2gb+1)
$$
所以(2ga+1)和(2gb+1)就是n的两个素因子p和q<br >
我们考虑多项式<br >
$$
f(x) = 2*g*x + 1
$$
我们希望f(a) ≡ 0 (mod p)，而p是N的因子，即使我们不知道p，只知道N，可以使用Coppersmith方法求解模N下的小根，但要求解的多项式必须是首一的。因此，我们构造：<br >
$$
h(x) = x + (2 \cdot g)^{-1} \mod N
$$

exp
```python
N =
e =
g =
enc =
M = 2 * g
inv_M = pow(M, -1, N)
R.<x> = Zmod(N)[]
f = x + inv_M
roots = f.small_roots(2**256, 0.4)
a = int(roots[0])
p = M * a + 1
if N % p == 0:
    q = N // p
    print(f"分解成功: p={p}, q={q}")
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(enc, d, N)
from Crypto.Util.number import long_to_bytes
flag = long_to_bytes(int(m))
print(flag)
# moectf{Ju57_@_5YmP1e_C0mm0n_Pr1me#!}
```
### Ez_wiener
题目
```python
from Crypto.Util.number import*
from secret import flag

p=getPrime(512)
q=getPrime(512)
m=bytes_to_long(flag)
n=p*q
phi_n=(p-1)*(q-1)
while True:
    nbits=1024
    d = getPrime(nbits // 5)
    if (GCD(d, phi_n) == 1 and 30 * pow(d, 4) < n):

        break
e = pow(d,-1,phi_n)

c=pow(m,e,n)

print ("n=",n)
print ("e=",e)
print ("c=",c)

'''
n= 84605285758757851828457377667762294175752561129610097048351349279840138483398457225774806927631502994733733589395840262513798535197234231207789297886471069978772805190331670685610247724499942260404337703802384815835647029115023558590369107257177909006753910122009460031921101203824769814404613875312981158627
e= 36007582633238869298665544067678113422327323938964762672901735035127703586926259430077542134592019226503943946361640448762427529212920888008258014995041748515569059310310043800176826513779147205500576568904875173836996771537397098255940072198687847850344965265595497240636679977485413228850326441605991445193
c= 25377227886381037011295005467170637635721288768510629994676412581338590878502600384742518383737721726526909112479581593062708169548345605933735206312240456062728769148181062074615706885490647135341795076119102022317083118693295846052739605264954692456155919893515748429944928104584602929468479102980568366803
'''
```
维纳攻击的典型题目，特征就是e大，d小，这道题里面d满足$30 \cdot d^4 < n$，比标准的界限大一点，不过也能做<br >
<a href='https://www.cnblogs.com/Mirai-haN/articles/18945027'>参考博客</a><br >
攻击步骤就是利用e/n的连分数展开，由于d的特征，k/d是e/n的连分数收敛项<br >
对分数 $\frac{e}{N}$ 进行连分数展开，得到一系列渐进分数（收敛项）$\frac{k_i}{d_i}$<br >
对于每一个收敛项 $\frac{k_i}{d_i}$，检查是否满足：$(ed_i - 1) \equiv 0 \pmod{k_i}$<br >
如果满足，则 $d_i$ 可能是私钥 $d$，且 $k_i$ 对应 $ed = k\phi(N) + 1$ 中的 $k$。<br >
计算欧拉函数 $\phi(N)$ 并分解 $N$<br >
假设找到正确的 $d_i$ 和 $k_i$，则：$\phi(N) = \frac{ed_i - 1}{k_i}$<br >
然后解二次方程：$x^2 - (N + 1 - \phi)x + N = 0$<br >
该方程的两个根即为RSA的素数因子 $p$ 和 $q$。<br >
也就是说满足$(ed_i - 1) \equiv 0 \pmod{k_i}$的$d_i$不一定就是私钥d，只有通过上面那个方程的检验(即解出的两个根的乘积为n)才能确定是d<br >
exp
```python
from Crypto.Util.number import long_to_bytes
n = 84605285758757851828457377667762294175752561129610097048351349279840138483398457225774806927631502994733733589395840262513798535197234231207789297886471069978772805190331670685610247724499942260404337703802384815835647029115023558590369107257177909006753910122009460031921101203824769814404613875312981158627
e = 36007582633238869298665544067678113422327323938964762672901735035127703586926259430077542134592019226503943946361640448762427529212920888008258014995041748515569059310310043800176826513779147205500576568904875173836996771537397098255940072198687847850344965265595497240636679977485413228850326441605991445193
c = 25377227886381037011295005467170637635721288768510629994676412581338590878502600384742518383737721726526909112479581593062708169548345605933735206312240456062728769148181062074615706885490647135341795076119102022317083118693295846052739605264954692456155919893515748429944928104584602929468479102980568366803


def wiener_attack(e, n):
    cf = continued_fraction(e / n)
    convergents = cf.convergents()
    for conv in convergents:
        k = conv.numerator()
        d = conv.denominator()
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        b = n - phi + 1
        discriminant = b ^ 2 - 4 * n
        if discriminant >= 0:
            sqrt_disc = discriminant.sqrt()
            if sqrt_disc in ZZ:
                p = (b + sqrt_disc) // 2
                q = (b - sqrt_disc) // 2
                if p * q == n:
                    return d
    return None

d = wiener_attack(e, n)
m = pow(c, d, n)
print(long_to_bytes(int(m)))
# moectf{Ez_W1NNer_@AtT@CK!||}
```
### wiener++
题目
```python
from Crypto.Util.number import *
from secret import flag

m = bytes_to_long(flag)
p = getPrime(1024)
q = getPrime(1024)
phi = (p-1)*(q-1)
E = []
for i in range(3):
    E.append(pow(getPrime(600),-1,phi))  
n = p*q
e = 65537
c = pow(m,e,n)
print(f'E = {E}')
print(f'c = {c}')
print(f'n = {n}')
"""
E = [6535354858431850852882901159552069642652745264375395319401872291559383432177438285988364127472613549365509820935925577361414464075764640533208334665987592109205997966463551882468734344050074283602043327838642976610275755119106168019918564063715435876334390534614689273949767994713168344350212980200133843053996291542940897549076525747071976992346914997811867133598974772513201381446388313238061416275364774924879724623269275665955247476790410755454726735472729022234802527690839198476806961518389403284927512824802658120648166827671254702373707128253843009043343574820976133354679456691450195111421331838281980791169, 521740717797571328928542404746379489096681606296105709448001512801594188896794342910355692394114530313434027423805653128165121456821386005483234429465641848647231537545838107252519841836568394320914726188097536963645943740347602217310772591525035163575052097127250480550907254287152638159351757425050079034153320658804563142684053234861691610577439191450390837819069924806441572660111002277302472455857154076563710145258049404077025429614021344906361972885981934904848504701502497235325466136083457136074450313163397641812912247912853463291040073062853345391031149063654983069868879608400357250959694496146579685451, 8911805261833830474004605259907370605807913822533492645509364142094890565950914302571054903181099150347283987131973548407729373207539140949793938540351210310484507151010644704903841608034912618537032004944897772587351902872171465767156632786417718010302417945824640353543336103022123477513493841427508247924758472122357830026975916981381121237555468719061263601411254700854117936657411984123602591805427708008566595616753092377705022452331809886048933193760019801687147365544765265412906882965454515613718524542064373022515540363942939377959932432943637382868458666514763671495031622571616696370398455908620153043919]
c = 6753155979488207369146877527563962489798459549318070923366033245920698810626960872130015507640079255967883699975637707573487421437682484657575346378258338966332206545439810503073328798748741132167015894650686768925239854863550203205724604895839456517875108542083858900948587934359333734716352762480295451652976617660823153097682212487885039311354081578869472189112818410420202093044127626917233949906728334691001613133349724175401388010902496533739535048147542837664443019380587362527652958368440203848684943761090115145949772541171220588682127280853035360547963393464562446348630721098472522627580664983812781660775
n = 13574881868338582214480395446670580940012507548374450902518317364375475722668157493607158810724244896266071642370444779252115446641944766507717015889181393406304349721002246334571932443491014007813032684284177348256442664560920714698180362225066349458599934259487635040453190554685942293568882945035152595000888123888791436446731739856349561654337315238581318196198972142582551083105737178416447194992839881126339173823749783111704949164881364240077721677409809320748025824802169248149833407214474947847788378002642917634973813614056523994315689432930551129372591378019659084153696307545609036884627279543075621209259
"""
```
还是维纳攻击，题目甚至比上个题还短，唯一能利用的就是E，一个朴素的想法就是去求Ei/n的连分数展开，然后用类似上面的思路去恢复phi，然后可以做三次一样的操作，不过失败了，解不出来，正好跟题目里描述的一样<br >
查阅了一番后，发现不是三个独立的维纳攻击，而是要结合在一起，是一个扩展维纳攻击<br >
参考博客<br >
https://ctf-wiki.org/crypto/asymmetric/rsa/d_attacks/rsa_extending_wiener/<br >
https://hasegawaazusa.github.io/wiener-attack.html#%E8%84%9A%E6%9C%AC-1<br >
有双指数和三指数的情况，显然这里是三指数的情况，提供了解题模板，拿过来可以直接用<br >
在这里写点我自己的理解吧(其实没看明白)
首先上来就是$e \cdot d - k \cdot \lambda(N) = 1$来了个$\lambda(N)$，不是phi(n)，然后给了$\lambda(N) = \mathrm{lcm}(p-1, q-1) = \varphi(N)/g$，也就是说λ(n)是phi(n)的因子，所以第一个式子能成立
然后构造了两种类型的等式，一种是$Gij$(叫郭等式)，一种是$W_i$(叫维纳等式)
G的构造是联立两个e，然后消去phi
$$
e_1 d_1 g - k_1 (p-1)(q-1) = g \\
e_2 d_2 g - k_2 (p-1)(q-1) = g \\
k_2 d_1 e_1 - k_1 d_2 e_2 = k_2 - k_1 
$$
W的构造是
$$
d_i g e_i - k_i N = g + k_i s \\
s = 1 - p - q
$$
至于这些式子，都可以从最上面的同余式变形得到
然后就要构造几个式子，改写成矩阵的形式，进一步构造格求解，然后用LLL算法，一通操作就能求出来......<br >
当然这里写的是两个指数的情况，三个指数得情况流程类似，矩阵当然会变得更大，然后规约...<br >

exp
```python
from Crypto.Util.number import long_to_bytes
E = ...
c = ...
n = ...
e = 65537
e1, e2, e3 = E[0], E[1], E[2]

L = matrix(ZZ, [
    [1, -n, 0, n**2, 0, 0, 0, -n**3],
    [0, e1, -e1, -n * e1, -e1, 0, n * e1, n**2 * e1],
    [0, 0, e2, -n * e2, 0, n * e2, 0, n**2 * e2],
    [0, 0, 0, e1 * e2, 0, -e1 * e2, -e1 * e2, -n * e1 * e2],
    [0, 0, 0, 0, e3, -n * e3, -n * e3, n**2 * e3],
    [0, 0, 0, 0, 0, e1 * e3, 0, -n * e1 * e3],
    [0, 0, 0, 0, 0, 0, e2 * e3, -n * e2 * e3],
    [0, 0, 0, 0, 0, 0, 0, e1 * e2 * e3]
])
alpha = 2 / 5
D = diagonal_matrix(ZZ, [floor(pow(n, 3 / 2)), n, floor(pow(n, alpha + 3/2)), floor(pow(n, 1/2)), floor(pow(n, alpha + 3/2)), floor(pow(n, alpha + 1)), floor(pow(n, alpha + 1)), 1])
M = L * D
B = M.LLL()
b = vector(ZZ, B[0])
A = b * M^(-1)
phi = floor(A[1] / A[0] * e1)

d = inverse_mod(e, phi)
m = pow(c, d, n)
flag = long_to_bytes(int(m))
print(flag)
# moectf{W1N4er_A@tT@CkRR-R@4ENggeEE|!}
```
### ezHalfGCD
题目(输出没贴出来)
```python
from Crypto.Util.number import bytes_to_long, getStrongPrime
from secret import flag

e = 11
p = getStrongPrime(1024)
q = getStrongPrime(1024)
n = p * q
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
enc_d = pow(d, e, n)
enc_phi = pow(phi, e, n)
enc_flag = pow(bytes_to_long(flag), e, n)
print(f"{e=}")
print(f"{n = }")
print(f"{enc_d = }")
print(f"{enc_phi = }")
print(f"{enc_flag = }")
```
看了一篇博客<a href='https://blog.csdn.net/m0_74345946/article/details/132888197?ops_request_misc=&request_id=&biz_id=102&utm_term=halfgcd&utm_medium=distribute.pc_search_result.none-task-blog-2~all~sobaiduweb~default-9-132888197.142^v102^control&spm=1018.2226.3001.4187'>相关信息攻击-Franklin-Reiter</a>跟里面的例题思路类似，把这道题做出来了<br >
这道题的关键点是对d和phi进行了和明文同样方法的加密，而d和phi之间本身就有一个等式关系，而且是线性的关系<br >
$$
d \cdot e = 1 + k \cdot \varphi \\
\varphi = \frac{e \cdot d - 1}{k}  
$$
抽象一下，就是phi=f(d)，那么我们就可以构造两个多项式(模n意义下)<br >
$$
g_1(x) = x^e - enc\_d \\
g_2(x) = f(x)^e - enc\_phi
$$
而d是这两个多项式的公共根，即(x-d)是g1和g2的公因式<br >
那么我们求出公因式也就是求出了d，进一步可以恢复明文<br >
这道题的另一个点就是e=11是比较小的一个数，所以$d \cdot e = 1 + k \cdot \varphi$这里的k是可以尝试枚举的<br >
根据模板改造(这题也是按时间顺序来看第一个用sagemath的题目)<br >

exp
```python
from Crypto.Util.number import long_to_bytes

e = 
n = 
enc_d = 
enc_phi = 
enc_flag = 

def franklinReiter(n, e, k, enc_d, enc_phi):
    PR.<x> = PolynomialRing(Zmod(n))
    g1 = (x) ^ e - enc_d
    g2 = ((e * x -1 ) / k) ^ e - enc_phi

    def gcd(g1,g2):
        while g2:
            g1, g2 = g2, g1 % g2
        return g1.monic()
    return -gcd(g1, g2)[0]

for k in range(1,15):
    d = franklinReiter(n, e, k, enc_d, enc_phi)
    m = pow(enc_flag, d, n)
    flag = long_to_bytes(int(m))
    if b'moectf' in flag:
        print(flag)
        break
# moectf{N0w_y0u_kn0w_h0w_t0_g3t_th1s_fl@G__!!!!!!!!!!}
```
### Ledengre_revenge
题目
```python
from Crypto.Util.number import *
from Crypto.Cipher import AES
import gmpy2
import random
from secrets import flag

p=251
e=65537

def function(x,p):
    y=0
    if x>=p:
        y=x
    elif pow(x,(p-1)//2,p)==1:
        y=pow(x,2,p)
    else:
        y=pow(x,3,p)
    return y

def matrix_to_str(matrix):
    b = bytes(sum([[matrix[row][col] for col in range(4)] for row in range(4)], []))
    return b.rstrip(b'\0')


def str_to_matrix(s):
    matrix = [[function(s[row + 4*col],p) for row in range(4)] for col in range(4)]
    return matrix

a=[[random.choice([227,233,239,251]) for row in range(4)] for col in range(4)]
p_=getPrime(256)

text_=[[pow(bytes_to_long(flag[(row+col*4)*2:(row+col*4)*2+2]),-2,p_)+1 for row in range(4)] for col in range(4)]
key = 0
for row in range(4):
    for col in range(4):
        key*=2
        key+=(pow(text_[row][col],(p_-1)//2,p_)+1)%p_//2

assert len(flag)==32
assert p_ == 71583805456773770888820224577418671344500223401233301642692926000191389937709
assert pow(key,2*e,p_) == 1679283667939124174051653611794421444808492935736643969239278575726980681302


text_=[flag[:16],flag[16:]]
cipher = AES.new(long_to_bytes(key<<107), AES.MODE_ECB)
for t in range(2):
    lis=[[0 for row in range(4)] for col in range(4)]
    for i in range(10):
        enc = cipher.encrypt(text_[t])
        matrix = str_to_matrix(enc)
        for row in range(4):
            for col in range(4):
                lis[row][col]=lis[row][col] << 1
                if matrix[row][col]>a[row][col]//2:
                    lis[row][col]+=1
        matrix = [[function(matrix[col][row],a[col][row]) for row in range(4)] for col in range(4)]
        text_[t] = matrix_to_str(matrix)
    print(f"lis{t}={lis}")

text=pow(bytes_to_long(text_[0]+text_[1]),2,p_)
print(f"text={text}")
print(f"a={a}")
```
从整体上看去，这道题还是一道类似于分组密码的题目，是对text_进行了加密<br >
第一步，观察key的生成过程<br >
```python
for row in range(4):
    for col in range(4):
        key*=2
        key+=(pow(text_[row][col],(p_-1)//2,p_)+1)%p_//2
```
`pow(text_[row][col],(p_-1)//2,p_)`结合勒让德符合的相关知识，这个值只能是1或者-1，所以key+=的值只能是0或1，结合key只有16位和下面给的约束条件，就可以先把key给爆破出来<br >
```python
p_ = 71583805456773770888820224577418671344500223401233301642692926000191389937709
e = 65537
target = 1679283667939124174051653611794421444808492935736643969239278575726980681302
for k in range(0,2**16):
    if pow(k, 2 * e, p_) == target:
        print(k)
        break
```
得到`key = 60679`<br >
第二步，题目的输出只给了我们text，而分组加密输出的密文应该是text_[0]和text_[1]，我们得把密文先还原出来<br >
`text=pow(bytes_to_long(text_[0]+text_[1]),2,p_)`这是他们之间的关系式，类似于rsa加密里面e很小的那种情况，这里只是做了一个平方，那么应该就是要进行开方来还原<br >
验证发现text确实是模p_的二次剩余，那么就要求解二次同余方程，利用了ai提供的Tonelli-Shanks算法脚本，(找不到了...)这里只放了结果，有两个根，最后应当只有一个是正确的，暂时不影响，我们写好解密算法后，两个都试一下就行了<br >
```python
r1 = 30565192635368786249732024567787542864212990230048954769681860484383995323228
r2 = 41018612821404984639088200009631128480287233171184346873011065515807394614481
# print(pow(r1, 2, p_) == text)
# print(pow(r2, 2, p_) == text) # 验证确实正确
c1 = long_to_bytes(r1)
c2 = long_to_bytes(r2)
c1_1, c1_2 = c1[:16], c1[16:]
c2_1, c2_2 = c2[:16], c2[16:]
```
第三步，还是解分组密码的逻辑，我们需要逆向str_to_matrix，matrix_to_str操作和function这个函数，这里主要就说一下function的逆向，一开始，是想从数学公式的角度找一个逆函数出来，后来弄不出来，又观察了一下，发现function的第二个参数p实际上在整个过程中只有四种可能的取值239，251，227，233，其中除了233这个特殊的，function取其他三个参数时，都是一个单射，因此逆向的方法就是遍历一次x，存下对应的y值，然后反转一下就是逆函数。233比较特殊，会出现一个x对多个y的情况，所以解密的时候，我们拿到1个y，可能恢复出多种x，会出现分支，有点像杂交随机数那道题的情况<br >
第四步，理解输出的lis0和lis1的作用是什么，lis统计了加密过程中，中间矩阵的一些特征，而由于function的逆函数不是一对一的，lis的作用就是约束我们的输出，减少可能的情况，就像校验位的作用那样<br >
(写wp的时候有点久远了，好多细节可能没有提到，大致思路应当是对的叭)<br >
(a的四个取值，包括了p，这四个数里只有233对应的不是单射，导致在处理233时，可能会出现一对二的情况，不过幸运的是即使某个位置有2个解，能通过lis约束成唯一的，这样代码就不用去递归实现，好写多了...或许能严格证明lis一定能约束成唯一值吗...?)<br >
完整exp，使用时把116行enc=c1_1，enc=c1_2和122行apply_lis_constraint()函数第二个参数lis0，lis1改成对应的，运行两次得到前后各一半flag<br >

```python
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
import itertools

p_ = 71583805456773770888820224577418671344500223401233301642692926000191389937709
e = 65537
key = 60679
a = [[239, 239, 251, 239], [233, 227, 233, 251], [251, 239, 251, 233],
     [233, 227, 251, 233]]
lis0 = [[341, 710, 523, 1016], [636, 366, 441, 790], [637, 347, 728, 426],
        [150, 184, 421, 733]]
lis1 = [[133, 301, 251, 543], [444, 996, 507, 1005], [18, 902, 379, 878],
        [235, 448, 836, 263]]
text = 26588763961966808496088145486940545448967891102453278501457496293530671899568
r1 = 30565192635368786249732024567787542864212990230048954769681860484383995323228
r2 = 41018612821404984639088200009631128480287233171184346873011065515807394614481
c1 = long_to_bytes(r1)
c2 = long_to_bytes(r2)
c1_1, c1_2 = c1[:16], c1[16:]
c2_1, c2_2 = c2[:16], c2[16:]
p = 251
cipher = AES.new(long_to_bytes(key << 107), AES.MODE_ECB)


def matrix_to_str(matrix):
    b = bytes(
        sum([[matrix[row][col] for col in range(4)] for row in range(4)], []))
    return b.rstrip(b'\0')


def inverse_matrix_to_str(s):
    matrix = [[s[row + 4 * col] for row in range(4)] for col in range(4)]
    return matrix


def str_to_matrix(s):
    matrix = [[function(s[row + 4 * col], p) for row in range(4)]
              for col in range(4)]
    return matrix


def inverse_str_to_matrix(matrix):
    s = []
    for row in range(4):
        for col in range(4):
            element = matrix[row][col]
            si = inverse_function(element, p)
            if type(si) is list:
                s.append(si[0])
            else:
                s.append(si)
    return bytes(s)


def function(x, p):
    y = 0
    if x >= p:
        y = x
    elif pow(x, (p - 1) // 2, p) == 1:
        y = pow(x, 2, p)
    else:
        y = pow(x, 3, p)
    return y



def precompute_function(p_val):
    mapping = {}
    for x in range(0, p_val):
        if x >= p_val:
            y = x
        elif pow(x, (p_val - 1) // 2, p_val) == 1:
            y = pow(x, 2, p_val)
        else:
            y = pow(x, 3, p_val)

        if y not in mapping:
            mapping[y] = []
        mapping[y].append(x)

    return mapping


def inverse_function(y, p_val):
    inverse_mapping = precompute_function(p_val)
    if y in inverse_mapping:
        return inverse_mapping[y]

    if y >= p_val:
        return y

    return []


def apply_lis_constraint(matrix, lis):
    new_matrix = [[[] for _ in range(4)] for _ in range(4)]
    for row in range(4):
        for col in range(4):
            vals = matrix[row][col]
            if not isinstance(vals, list):
                vals = [vals]
            if len(vals) > 1:
                if lis[row][col] % 2 == 1:
                    valid_vals = [v for v in vals if v > a[row][col] // 2]
                else:
                    valid_vals = [v for v in vals if v <= a[row][col] // 2]
                if not valid_vals:
                    return None
            else:
                valid_vals = vals
            new_matrix[row][col] = valid_vals
            lis[row][col] = lis[row][col] >> 1
    return new_matrix

#验证后c1是正确的那个解
enc = c1_2
for i in range(10):
    matrix = inverse_matrix_to_str(enc)
    initial_matrix = [[
        inverse_function(matrix[row][col], a[row][col]) for col in range(4)
    ] for row in range(4)]
    constrained_matrix = apply_lis_constraint(initial_matrix, lis1)
    all_candidates = []
    for row in range(4):
        for col in range(4):
            if not constrained_matrix[row][col]:
                break  
            all_candidates.append(constrained_matrix[row][col])

    for candidate in itertools.product(*all_candidates):
        idx = 0
        new_matrix = [[0] * 4 for _ in range(4)]
        for row in range(4):
            for col in range(4):
                new_matrix[row][col] = candidate[idx]
                idx += 1
        enc_bytes = inverse_str_to_matrix(new_matrix)
        enc_bytes = cipher.decrypt(enc_bytes)
        enc = enc_bytes
        print(enc)
# moectf{E@5Y_1eGendre_@nd_@ES*10}
```