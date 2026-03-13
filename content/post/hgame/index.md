+++
title = "HGAME 2026"
date = "2026-03-13"
categories = ["WP"]
image="1.png"
+++

# HGAME 2026

**前言**

寒假期间参加的一场比赛，赛时做出来 7/8 (ezCurve没出)



## Week1

### Classic

给了一个 task.py 和 flag.txt

```python
from Crypto.Util.number import *
from secret import flag
p = getPrime(512)
q = getPrime(512)
n = p * q
e = 65537
leak = p >> 230
m = bytes_to_long(flag)
c = pow(m,e,n)
print("n=",n)
print("leak=",leak)
print("c=",c)
'''
n= 103581608824736882681702548494306557458428217716535853516637603198588994047254920265300207713666564839896694140347335581147943392868972670366375164657970346843271269181099927135708348654216625303445930822821038674590817017773788412711991032701431127674068750986033616138121464799190131518444610260228947206957
leak= 6614588561261434084424582030267010885893931492438594708489233399180372535747474192128
c= 38164947954316044802514640871285562707869793354907165622336840432488893861610651450862702262363481097538127040490478908756416851240578677195459996252755566510786486707340107057971217557295217072867673485369358370289506549932119879791474279677563080377456592139035501163534305008864900509896586230830001710243
'''
```

```text
Ane Hmnknèdi joptiy cae rvz izzlttqh ie Vukltèrq; ma cae jpxsf tyupawlj iz 1553 ff zhq Maglueu Miazht Bmxaosfe Iklxezu, yqx pz wmw ugmqh hltqv Cogqrèyk dgi au huw 1586 pspdsckmqray, lqecons Flrlmwv crarnry ovljifik lod xoxeq glttgvpks.
Ux byep e rky fs jecxi anraynn 26 Cmizgr mpwnaniay luol g dqgr uf oeyjs, qeytizk pz tti aotxi vl "tti btbdihqanpl iibllx."
Iz xok 19tt glttgvf, Hanfhme qbwusqh pzs biyoopmj cemoukse, hlrihiyons e mgtmp iroi xogt qrkkd uxz zwa-glttgvf-rozk tett.
euewmc,P nobi fuu isbrd xmrk cxezyioes irktaugdewny。Flpy ie cvar rphm:VUHHX{Tti Julxmzooz sm zhq Rlc azh ane Apk}
```

可以看出 txt 的内容应该是一种古典密码的密文，解出上面那个 RSA 应该能得到一些提示

上面就是个典型的 p 高位泄露，不过这个题 epsilon 默认值是出不来的，需要调一下

(当时犯了个非常之蠢的操作，把 epsilon 拼错了，导致即使调的很小很小，却还是秒返回 [ ] )

```python
n = 103581608824736882681702548494306557458428217716535853516637603198588994047254920265300207713666564839896694140347335581147943392868972670366375164657970346843271269181099927135708348654216625303445930822821038674590817017773788412711991032701431127674068750986033616138121464799190131518444610260228947206957
leak = 6614588561261434084424582030267010885893931492438594708489233399180372535747474192128
c = 38164947954316044802514640871285562707869793354907165622336840432488893861610651450862702262363481097538127040490478908756416851240578677195459996252755566510786486707340107057971217557295217072867673485369358370289506549932119879791474279677563080377456592139035501163534305008864900509896586230830001710243
R.<x> = Zmod(n)[]
f = (leak * 2**230) + x
x0 = f.small_roots(X = 2**230,beta = 0.4,epsilon = 0.03)[0]
p = (leak * 2**230) + int(x0)
# 正常解密就行了，得到明文 Vigenere,key=hgame 
# 最后网站解个 维吉尼亚 就出来了
```

### Flux

```python
from Crypto.Util.number import *
import random
from secret import key

class Flux:
    def __init__(self, n, x):
        self.n = n
        self.a = random.randint(1, n-1)
        self.b = random.randint(1, n-1)
        self.c = random.randint(1, n-1)
        self.x = x
    
    def next(self):
        self.x = (self.a * self.x ** 2 + self.b * self.x + self.c) % self.n
        return self.x

def shash(value: str,key: int) -> int:
    length = len(value)

    if length == 0:
        return 0
    mask = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    x = (ord(value[0]) << 7) & mask
    for c in value:
        x = (key * x) & mask ^ ord(c)

    x ^= length & mask

    return x

assert key.bit_length() < 70
value = "Welcome to HGAME 2026!"
h = shash(value, key)

n = getPrime(260)
flux = Flux(n, h)
data = [flux.next() for _ in range(4)]

with open('data.txt', 'w') as f:
    f.write(f"{data}\n")
    f.write(f"{n}\n")

magic_word = "I get the key now!"
flag = "VIDAR{" + hex(shash(magic_word, key))[2:] + "}"
print(flag)
```

结构很清晰，分两步，第一步通过分析 Flux 把 h 给求出来，第二步根据 (value, h) 把 key 求出来
$$
d_0 \equiv ah^2 + bh +c \pmod n \\
d_1 \equiv ad_0^2 + bd_0 +c \pmod n \\
d_2 \equiv ad_1^2 + bd_1 +c \pmod n \\ 
d_3 \equiv ad_2^2 + bd_2 +c \pmod n \\
$$
d 表示 data 数组，而 a, b, c 本身都小于 n，故从下面三个方程把 a, b, c 解出来，最后代回第一式多项式求根即可

```python
data = [
    259574080588277578527410299002867735023798216356763871244908783144610527451187,
    954408432127642232121971189554605898975195279656270435479524132958262607464595,
    902461413507524665418054778947872375987908929501605791883614896110219051835312,
    92554599789649828855418140915311664257163346975111310560999959858873425332254
]
n = 1000081851369905197391900354119969103949357074708517572641608490670646955240669
A = [[data[0] ^ 2, data[0], 1], [data[1] ^ 2, data[1], 1], [data[2] ^ 2, data[2], 1]]
b = [data[1], data[2], data[3]]
A = matrix(Zmod(n),A)
b = vector(Zmod(n),b)
aa, bb, cc = A.solve_right(b)
R.<x> = Zmod(n)[]
f = aa*x^2 + bb*x + cc - data[0]
# f.roots()
h1 = 6866312363291178484982959720124435011938375586579989365225276248801007329194
h2 = 1851471554044636937620060405470139203302636010497407478542185697214766136647
```

下一步求 key，无脑的做法就是用 z3 求解(有的题比较复杂，可能算不出来，得考虑其他方法) 不过这个题可以，且挺快的，下面是 ai 给的一个 z3 脚本

```python
from z3 import *

def solve():
    target_value = "Welcome to HGAME 2026!"
    target_hash = 6866312363291178484982959720124435011938375586579989365225276248801007329194
    mask = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

    MASK_BITS = 256
    solver = Solver()
    key = BitVec('key', MASK_BITS)
    length = len(target_value)
    x_init_val = (ord(target_value[0]) << 7) & mask
    # 将其转换为 Z3 的 256位 常量
    x = BitVecVal(x_init_val, MASK_BITS)

    for char in target_value:
        x = (key * x) & mask ^ ord(char)
    x ^= length & mask

    solver.add(x == target_hash)
    if solver.check() == sat:
        model = solver.model()
        found_key = model[key].as_long()
        print(f"[+] Key : {found_key}")

solve()
```

最后就是依次尝试两个 hash 值，看看求出来的 key 的比特位，就结束了

### babyRSA

```python
from Crypto.Util.number import *
from gmpy2 import *
from random import *
import string

k = randint(30, 40)
str = string.digits + string.ascii_letters + "_@"
flag = b"VIDAR{" + "".join([choice(str) for i in range(k)]).encode() + b"}"
p = getPrime(120)
q = getPrime(120)
n = p * q
e = 65537
m = bytes_to_long(flag)
c = pow(m, e, n)
print(f'c = {c}')
print(f'p = {p}')
print(f'q = {q}')
'''
c = 451420045234442273941376910979916645887835448913611695130061067762180161
p = 722243413239346736518453990676052563
q = 777452004761824304315754169245494387
'''
```

一道 m>n 的 RSA 题目，搜一搜倒是比较容易搜出基本一样的类型题，参考 [2024-NSSCTF-密码工坊非官方dlc-wp-crypto | 糖醋小鸡块的blog](https://tangcuxiaojikuai.xyz/post/94c7e291.html)

n 是 240bit 左右，m 是 300bit 左右(由于 k 不确定，不过一定是比n大了)，具体地，设 pre 指 b'VIDAR{'， suf 指 b'}'，则 m 可以写成
$$
m = pre\cdot 256^{k+1} + m_0 \cdot 256 + suf
$$
可以对上面的 rsa 做一个解密得到一个 m1，$m_1 \equiv c^d \equiv m\pmod n$，也就是 m 求余 n 的值

目标是把 m0 求出来，先两边模n，然后做一个变形
$$
m_1  \equiv m \equiv pre\cdot 256^{k+1} + m_0 \cdot 256 + suf  \pmod n \\
m_0 \equiv 256^{-1}(m_1 - pre\cdot 256^{k+1} - suf) \pmod n
$$
这个式子的右边是已知的，相当于知道了 m0 求余 n 的值，记为 $m_2$，即$m_0 \equiv m_2 \pmod n$

另一方面，将 m0 展开，可以表示成下面的式子，本题中，si 大致分布在 [48, 122]
$$
m_0 = \sum_{i=0}^{k-1} 256^i s_i = s_0 + 256 s_1 + 256^2 s_2 + \ldots + 256^{k-1} s_{k-1} \\
$$
两边模 n，可得
$$
m_2 = \sum_{i=0}^{k-1} 256^i s_i - k n
$$
可依此构造出类似背包格的格，如下，是一个 (k+2)*(k+2) 的格
$$
(s_0, s_1, \ldots, s_{k-1}, 1, -k) \begin{pmatrix}
1 &  & & & &1 \\
& 1&  & & &256 \\
& & \ddots&  &  &\vdots\\
& & & 1 &  &256^{k-1} \\
& & & & 1 & -m_2 \\
& & & & & n
\end{pmatrix} = (s_0, s_1, \ldots, s_{k-1}, 1, 0)
$$
but，这个格规约不出来，博客里是这么说的，我自己配平试了试也不行，下面进行一些优化

令 $t_i = s_i - 48$，则
$$
m_2 = \sum_{i=0}^{k-1} 256^i (t_i + 48) - k n =  \sum_{i=0}^{k-1} 256^i t_i + c - k n
$$
c 是一个可以算出来的常数，现在目标向量分量落在 [0, 74] 内，比先前更小了一些，同时，ti 的平均值在37左右，因此给倒数第二列配上个37能使目标向量中值的数量级更加接近，但是发现还是不行，故再减去37，使得目标向量分量落在 [-37, 37] 内，此时倒数第二列还是1就行，用 BKZ 把 block_size 调大一些可以出结果

```python
from Crypto.Util.number import *
c = 451420045234442273941376910979916645887835448913611695130061067762180161
p = 722243413239346736518453990676052563
q = 777452004761824304315754169245494387
n = p * q
e = 65537
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m1 = pow(c, d, n)

prefix = b"VIDAR{"
suffix = b"}"
a = bytes_to_long(prefix)
b = bytes_to_long(suffix)
for k in range(30, 41):
    tmp1 = pow(256, -1, n)
    tmp2 = m1 - b - a * pow(256, k + 1, n)
    m2 = tmp1 * tmp2 % n
    A = matrix(ZZ, k + 2, k + 2)
    for i in range(k):
        A[i, i] = 1
        A[i, -1] = pow(256, i)
        m2 -= 256 ^ i * 48
        m2 -= 256 ^ i * 37
    A[k, k] = 1
    A[k, -1] = -m2
    A[k + 1, -1] = n
    for i in range(k + 2):
        A[i, -1] *= 2**120

    res = A.BKZ(block_size=20)
    for i in res:
        if i[-1] == 0 and (i[-2] == 1 or i[-2] == -1):
            if all(abs(j) < 40  for j in i[:-2]):
                flag = ''
                if i[-2] == 1:
                    for char in i[:-2][::-1]:
                        flag += chr(char + 48 + 37)
                if i[-2] == -1:
                    for char in i[:-2][::-1]:
                        flag += chr(-char + 48 + 37)
                print(flag)
```

### ezCurve

```python
from Crypto.Util.number import *
import socketserver
import logging
import io
import os
from sage.all import *

with open('flag.txt', 'rb') as f:
    flag = f.read()

HOST = '0.0.0.0'
PORT = 10000

menu = """1. get x
2. check x
> """

class Curve(socketserver.StreamRequestHandler):
    def handle(self):
        global istream, ostream

        logging.info(f"connection from {self.client_address}")
        istream = io.TextIOWrapper(self.rfile, encoding="UTF-8")
        ostream = io.TextIOWrapper(self.wfile, encoding="UTF-8", write_through=True)
        
        p = getPrime(1024)
        a = getPrime(200)
        b = getPrime(200)
        E = EllipticCurve(GF(p), [a, b])
        R = E.random_element()
        P = E.random_element()

        print(p, file = ostream)
        print(a, file = ostream)
        print(b, file = ostream)
        print(R, file = ostream)

        for i in range(30):
            print(menu, file = ostream)
            choice = int(istream.readline().strip())
            if choice == 1:
                print("t> t = ", end = "", file = ostream)
                t = int(istream.readline().strip())
                O = P + t * R
                print(int(O[0] - getPrime(163)), file = ostream)
            elif choice == 2:
                ans = int(istream.readline().strip())
                if ans == P[0]:
                    print(flag, file = ostream)
                else:
                    print("error", file = ostream)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    with socketserver.TCPServer((HOST, PORT), Curve) as server:
        logging.info(f"listening on {HOST}:{PORT}")
        server.serve_forever()
```

这个题当时是进行了一些思考和尝试，不过没想到点子上，后来得知是 echnp 模板题 [| 独奏の小屋](https://hasegawaazusa.github.io/hidden-number-problem.html#echnp椭圆曲线隐藏数问题) ，感觉就是得搜，搜到就出来了，搜不到就难说... 在 [格密码-HNP](https://hataovo.github.io/p/格密码-hnp/#echnp椭圆曲线隐藏数问题) 那篇文章里进行了一些原理的推导，这里就只贴个 exp 了

```python
from pwn import *

p = remote('127.0.0.1', 63854)

mod = int(p.recvline().decode())
a = int(p.recvline().decode())
b = int(p.recvline().decode())
R = p.recvline().decode().split(':')
Rx, Ry = int(R[0][1:]), int(R[1])

E = EllipticCurve(GF(mod), [a, b])
R = E(Rx, Ry)
G = R

def query():
    tmp = []
    for i in range(15):
        if i == 0:
            p.recvuntil(b'> \n')
            p.sendline(b'1')
            p.recvuntil(b'= ')
            p.sendline(b'0')
            tmp.append(int(p.recvline().decode()))
        else:
            p.recvuntil(b'> \n')
            p.sendline(b'1')
            p.recvuntil(b'= ')
            p.sendline(str(i).encode())
            tmp.append(int(p.recvline().decode()))

            p.recvuntil(b'> \n')
            p.sendline(b'1')
            p.recvuntil(b'= ')
            p.sendline(str(-i).encode())
            tmp.append(int(p.recvline().decode()))
    return tmp

tmp = query()
hs = [tmp[0]]
for i in range(1, len(tmp), 2):
    hs.append(tmp[i] + tmp[i + 1])

k = 163
d = len(hs) - 1
Ai = []
A0i = []
Bi = []
B0i = []
Ci = []
for i in range(1, d + 1):
    Q = i * G
    xQ = ZZ(Q[0])
    Ai.append(hs[i] - 2 * xQ)
    A0i.append(2 * (hs[0] - xQ))
    Bi.append(2 * (hs[i] * (hs[0] - xQ) - 2 * hs[0] * xQ - a - xQ ^ 2))
    B0i.append((hs[0] - xQ) ^ 2)
    Ci.append(hs[i] * (hs[0] - xQ) ^ 2 - 2 * ((hs[0] ^ 2 + a) * xQ + (a + xQ ^ 2) * hs[0] + 2 * b))

R = block_matrix(ZZ, [
    -matrix(Ci), -matrix(Bi), -diagonal_matrix(B0i), -matrix(Ai),
    -diagonal_matrix(A0i)
], ncols=1)
P = diagonal_matrix(ZZ, [mod] * d)
E = block_diagonal_matrix([
    matrix([8 ^ k]),
    diagonal_matrix([4 ^ k] * (d + 1)),
    diagonal_matrix([2 ^ k] * (d + 1))
])
M = block_matrix([[E, R], [0, P]])
shortest_vector = M.LLL()[0]
es = shortest_vector[1:d + 1] / 4 ^ k
if es[0] < 0:
    es[0] = -es[0]
print(es[0])
xP = ZZ(hs[0] + es[0])
print(xP)
p.recvuntil(b'> \n')
p.sendline(b'2')
p.sendline(str(xP).encode())
print(p.recvline())
```

## Week2

### ezDLP

```python
from Crypto.Util.number import long_to_bytes, getPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode
import hashlib
from sage.all import *
from secret import getRandomMatrix

with open('flag.txt', 'rb') as f:
    flag = pad(f.read(), AES.block_size)

# Want to factor n? I've already done it! Get it yourself.
n = 144709507748526661267852152217031923282704243254105275252262414154410511284347828603240755427862752297392095652561239549522158121842455510674435510821274029842500154931546666242034086499872050823824437303603895977092291834159890433746969317535636398062008995784281741721729948231010601796589449187553147904043991226174291329
a = Matrix(Zmod(n), getRandomMatrix())
k = getPrime(1000)
b = a ** k

data = [n, a, b]
save(data, "data.sobj")

key = hashlib.md5(long_to_bytes(k)).digest()
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(flag)
print(b64encode(ciphertext).decode())
# ieJNk5335o9lCy6Ar2XymrDy+HVHcQhikluNSra0kBafw1WDCyyuNPkLACeBsavy
```

告诉了n是可分解的，去factordb上可得n是两个大素数乘积(n=pq)且(p-1)和(q-1)都是光滑的，然后对于矩阵DLP，将其分解到p和q上分别计算

(一开始想用特征值做，模p上的特征值好算，但是模q上的特征值整到二次扩域上去了，不好做)

其实一开始就应该先考虑行列式的，$det(b) = det(a)^k$，并且det(a)和det(b)都不是0，1，-1这几个不能用的

那就把矩阵DLP转成普通DLP了，正常算就行了

```python
n, a, b = load("data.sobj")  # 用load读数据
p = 282964522500710252996522860321128988886949295243765606602614844463493284542147924563568163094392590450939540920228998768405900675902689378522299357223754617695943
q = 511405127645157121220046316928395473344738559750412727565053675377154964183416414295066240070803421575018695355362581643466329860038567115911393279779768674224503
assert p * q == n
det_a = det(a)
det_b = det(b)
kp = discrete_log(GF(p)(det_b), GF(p)(det_a))
kq = discrete_log(GF(q)(det_b), GF(q)(det_a))
modp = GF(p)(det_a).multiplicative_order()
modq = GF(q)(det_a).multiplicative_order()
ans = crt([kp, kq], [modp, modq])
assert ans.bit_length() == 1000 and det_a ^ ans == det_b

from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from base64 import b64decode
import hashlib

key = hashlib.md5(long_to_bytes(ans)).digest()
cipher = AES.new(key, AES.MODE_ECB)
enc = b64decode(b'ieJNk5335o9lCy6Ar2XymrDy+HVHcQhikluNSra0kBafw1WDCyyuNPkLACeBsavy')
print(cipher.decrypt(enc))
# hgame{1s_m@trix_d1p_rEal1y_sImpLe??}
```

### eezzDLP

```python
from Crypto.Util.number import long_to_bytes, getPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode
import hashlib
from sage.all import *
from secret import getRandomMatrix, get_random_prime

with open('flag.txt', 'rb') as f:
    flag = pad(f.read(), AES.block_size)

p = get_random_prime()
q = get_random_prime()
n = p * p

a = Matrix(Zmod(n), getRandomMatrix())
k = getPrime(660)
b = a ** k

data = [n, a, b]
save(data, "data.sobj")

key = hashlib.md5(long_to_bytes(k)).digest()
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(flag)
print(b64encode(ciphertext).decode())
# Q3UBa1pz1fi35L94peaFbPvpQe4UyXOUif3CKS/CmZdXOiV7bA5NNNjJ1KeUiAFE
```

$n=p^2$，上factordb仍可以查到p，不过这个题的(p-1)不光滑，并且det(a)=det(b)=1

假设我们找到了一个 L，满足 $A^L \equiv I \pmod p$，$I$ 是单位阵，即 $A^L = I +pX$，$X$ 是一个随机整数构成的矩阵，类似于 kp 中的 k。而 $B \equiv A^k \pmod {p^2}$，两边同时取 L 次幂可得
$$
B^L \equiv (A^L)^k  \equiv (I +pX)^k \pmod {p^2}
$$
对右边做二项式展开，$p^2$ 及高次项就消去了，可得
$$
B^L \equiv  I^k+ k \cdot I^{k-1}pX \equiv I + kpX \pmod {p^2}
$$
另一方面，$B^L \equiv (A^L)^k \pmod {p^2}$，故 $B^L \equiv (A^L)^k \equiv (I )^k \equiv I \pmod {p}$，即 $B^L = I + pY$

代回上面的式子，可得，注意消 p 的时候，模数也要变
$$
I + pY \equiv I +kpX \pmod {p^2} \\
Y \equiv  kX \pmod {p}
$$


剩下的问题是如何找到满足 $A^L \equiv I \pmod p$ 的 L，放到最后阐述

这样就可以求出一个模 p 意义下的 k，但是发现其只有 608bit

```python
n, a, b = load("data.sobj")
p = 14262553722350428046713771076551090314160260448968748240889092522867981035381835010729957810183043946868290618279293005580111881543857313243691824746036623976338940751627470874113302539
m = 2
L = 1
for i in range(1, m + 1):
    L *= (p**i - 1)
AL = a**L
BL = b**L
I = matrix.identity(2)
X = (AL - I) / p
Y = (BL - I) / p
k = pow(X[0,0], -1, p) * Y[0,0] % p
```

$k \equiv k_0 \pmod p$，即 $k = k_0 + tp$，目标的 k 是660bit，p 是612bit，则 t 大概是 48bit，直接爆破显然不行，则中间相遇，$A^{k_0+tp} \equiv B \pmod n$，令 $t = \alpha\cdot 2^{24}+\beta$，bsgs的思想，大概 2^24 复杂度可以接受，不过当时的脚本找不到了，只存了最终结果

```python
kk = 4238873411283850941524834332937913444291533048380278889933287099990199178752115950062698973120574658223722822108986551677048478954034338616186015239894923832089467914215948935216404122157104593061117
print(a^kk == b)
```

在扩张域 $\mathbb{F}_{p^k}$ 上，对于任一非零元素，有 $\lambda^{p^k-1} =1 $，在 $\mathbb{F}_{p^k}$ 环境下

**一个 $m \times m$ 的矩阵 $A$ 作用在有限域 $\mathbb{F}_p$ 上时**，它的特征值 $\lambda$ 不一定直接落在 $\mathbb{F}_p$，ezDLP 题目就是一个例子，但是其特征值一定会落在某个扩张域 $\mathbb{F}_{p^k}$ 中，其中 $k \leq m$ 

(为什么考虑的是 Fp，而不是 Zmod(n)，其中一个原因是Zmod(n)，n=pq 或是 n=p^2，Zmod(n) 都不能构成一个整环，因为有零因子，而 sagemath 中无法直接求其上矩阵的特征值)

既然我们知道所有的特征值 $\lambda_j$ 所在的扩张域阶数 $k_j$ 都在 ${1, 2, \dots, m}$ 之间，那么：

- 特征值 $\lambda_1$ 满足 $\lambda_1^{p^{k_1}-1} = 1$
- 特征值 $\lambda_2$ 满足 $\lambda_2^{p^{k_2}-1} = 1$

构造一个数 $L$，它是所有可能阶数 $(p^1-1), (p^2-1), \dots, (p^m-1)$ 的公倍数，那么对于所有的特征值，都会满足  $\lambda_j^{L} = 1$，故可以构造  $L = \prod_{i=1}^m (p^i - 1)$

从特征值回到矩阵，一个随机生成的矩阵绝大多数情况下可对角化，即，(从这里开始都是在模 p 意义下)
$$
A = P \cdot diag(\lambda_1,...,\lambda_m) \cdot P^{-1}
$$
进而，中间的 P 和 P逆 相互抵消了
$$
A^L = P \cdot diag(\lambda_1^L,...,\lambda_m^L) \cdot P^{-1} \\
A^L = P \cdot diag(1,...,1) \cdot P^{-1} = I 
$$

---

在写的时候对于一些概念有了更清晰的理解，扩张域 $\mathbb{F}_{p^k}$ 和环 $\mathbb{Z} / p^k \mathbb{Z}$ 是完全不一样的

后者中的每一个元素都是剩余类，即 $0,1,2,3,...,p^k - 1$，共 $p^k$ 个剩余类，其中与 $p^k$ 互素的有 $\varphi(p^k) = p^k-p^{k-1}$ 个。环中 p 的幂次均为该环的零因子

而 $\mathbb{F}_{p^k}$ 作为扩张域，常见的构造方式是 $\mathbb{F}_p[x] / (f(x))$，每一个元素都是一个多项式，f(x) 是 k 次不可约多项式，系数取自 Fp，共有 $p^k$ 个元素，其中除了 0 以外都是可逆元

那么上面讨论的 $\lambda $ 作为 $\mathbb{F}_{p^k}$ 中的元素，本质上不能当作一个数来看待，而是当作多项式

### ezRSA

一个菜单 RSA，比较综合，题目做了删减，保留了重要的部分

```python
flag = pad(os.environ.get("FLAG", "flag{fake_flag}").encode(), 127)

menu = """1. Encrypt message
2. Decrypt message
3. Get flag
Your choice > """

class ezRSA(socketserver.StreamRequestHandler):

    def handle(self):
        p = getPrime(512)
        q = getPrime(512)
        phi = (p - 1) * (q - 1)
        e = random.getrandbits(50)
        while GCD(e, phi) != 1:
            e = random.getrandbits(50)
        d = pow(e, -1, phi)
        n = p * q

        safe = True

        while True:
            print(menu, end='', file=ostream)
            try:
                choice = int(istream.readline().strip())
                if choice == 1:
                    print('plz give me your plaintext:', file=ostream)
                    plain = int(istream.readline().strip())

                    print('and the bit you want to flip:', file=ostream)
                    x = int(istream.readline().strip())

                    cipher = pow(plain, e ^ (1 << x), n)
                    cipher = long_to_bytes(cipher)

                    if not safe:
                        cipher = self.disguise(cipher)
                    print(base64.b64encode(cipher).decode(), file=ostream)
                elif choice == 2:
                    print('plz give me your ciphertext:', file=ostream)
                    cipher = int(istream.readline().strip())

                    plain = pow(cipher, d, n)
                    plain = long_to_bytes(plain)

                    if not safe:
                        plain = self.disguise(plain)
                    print(base64.b64encode(plain).decode(), file=ostream)
                elif choice == 3:
                    secret = pow(bytes_to_long(flag), e, n)

                    safe = False

                    print(base64.b64encode(long_to_bytes(secret)).decode(),
                          file=ostream)

            except ValueError as e:
                print("Invalid format.", file=ostream)
                continue

    def disguise(self, msg):
        res = bytearray(msg)
        mask = os.urandom(1)
        for i in range(len(res)):
            res[i] = res[i] ^ int.from_bytes(mask)
        for i in range(len(msg) - 1, -1, -1):
            res[i] = res[i] ^ int.from_bytes(mask)
            mask = os.urandom(1)
        return bytes(res)
```

首先容易发现几件事情：n 和 e 都不知道；disguise 实现了类似 OTP 的操作，但是其有问题，其会泄露 msg 的最后一个字节

那思路就大概清楚了，先把 n 和 e 都恢复出来，然后想办法利用 disguise 的特点得到明文

选项1加密时多做了一个操作，就是`e ^ (1 << x)`，x 是我们的输入，相当于是翻转了 e 的某一比特位，若 x=0，则相当于将 e 的最低比特从 1 变成 0 (e一定是奇数)，也就是 $e' = e-1$

**恢复 n:** 由于加密没有限制负数，故可以加密 -1，x 传入 1，这样得到的是 $ c\equiv (-1)^{奇} \equiv -1 \pmod n$，也就是得到了 n-1

**恢复 e:** 在翻转第 k 个比特(从低向高)时，有 $e' = e+2^k$ 或 $e' = e-2^k$，进而有 $e = e'+2^k$ 或 $e = e'-2^k$。故我们可以依次翻转 e 的50个bit，记录对应的两个数据为一组，各组应当有交集，可以确定出每一组中真正的 e 加密后的密文，然后用相应的 k 恢复出 e

**恢复 m:** 最麻烦的一步。设明文为 $M_0$，令 $M_1 = M_0 \cdot 256^{-1} \pmod N$，即 $M_0 \equiv 256 \cdot M_1 \pmod N$，进一步有 $256  M_1 = M_0 + k_0 \cdot N$ 

因为 $0 < M_0 < N$ 且 $0 < M_1 < N$，所以 $0 < 256  M_1 < 256N$，不难得出 $k_0$ 属于 $[0, 255]$ 

两边同时模 256：$0 \equiv M_0 + k_0 \cdot N \pmod{256}$ 进而有
$$
k_0 \cdot N \equiv -M_0 \pmod{256} \\
k_0 \equiv -M_0 \cdot N^{-1} \pmod{256}
$$
这里，$M_0 \pmod{256}$ 正是泄露出的最后一个字节，故可求出 $k_0$

利用 $  M_1 = M_0 \cdot 256^{-1} \pmod N$ 将密文更新为 $M_1$

重复上述过程，可以得到
$$
256  M_1 = M_0 + k_0  N \\
256  M_2 = M_1 + k_1  N \\
256  M_3 = M_2 + k_2  N\\
...
$$
每次循环收集到一个 $k_i$，循环 130 次已经足够

最后需要把 $M_0$ 给还原出来

$M_0 = 256  M_1 - k_0  N$ ，代入 $M_1 = 256  M_2 - k_1  N$

$M_0 = 256  (256  M_2 - k_1  N) - k_0  N = 256^2  M_2 - N  (k_1  256 + k_0)$

进一步地，经过 $m$ 次迭代：

$M_0 = 256^m  M_m - N  (k_0 + k_1  256^1 + k_2  256^2 + \dots + k_{m-1} 256^{m-1})$

$M_m$ 是未知的，两边同时模 $256^m$，可得

$M_0 \equiv - N  (k_0 + k_1  256^1 + k_2  256^2 + \dots + k_{m-1} 256^{m-1}) \pmod{256^m}$

$256^{130}$ 大于模数 $N$，也自然大于明文 $M_0$，故求出来的值就是真实的 $M_0$ 

最终exp

```python
from base64 import b64decode
from Crypto.Util.number import *
from pwn import *


def mydecode(enc):
    return bytes_to_long(b64decode(enc))

p = remote('forward.vidar.club', 32447)
p.recvuntil(b'> ')
p.sendline(b'1')
p.recvline()
p.sendline(b'-1')
p.recvline()
p.sendline(b'1')
n = mydecode(p.recvline()) + 1
print(f'n={n}')

def solve_e():
    e = ''
    ee = []
    for k in range(50):
        p.recvuntil(b'> ')
        p.sendline(b'1')
        p.recvline()
        p.sendline(b'2')
        p.recvline()
        p.sendline(str(k).encode())
        data = mydecode(p.recvline())
        tmp = pow(2, pow(2, k), n)
        case0 = data * pow(tmp, -1, n) % n
        case1 = data * tmp % n
        ee.append([case0, case1])

    if all(ee[0][0] in i for i in ee):
        for j in ee:
            e += str(j.index(ee[0][0]))
    elif all(ee[0][1] in i for i in ee):
        for j in ee:
            e += str(j.index(ee[0][1]))
    else:
        print('wrong')
        return
    return int(e[::-1], 2)

e = solve_e()

def test_e():
    p.recvuntil(b'> ')
    p.sendline(b'1')
    p.recvline()
    p.sendline(b'3')
    p.recvline()
    p.sendline(b'0')
    data = mydecode(p.recvline())
    print(pow(3, e - 1, n) == data)

test_e()

p.recvuntil(b'> ')
p.sendline(b'3')
c = mydecode(p.recvline())

def solve_flag():
    inv_n = inverse(n % 256, 256)
    inv_256_e = pow(inverse(256, n), e, n)
    current_c = c
    ks = []

    for i in range(130):
        p.recvuntil(b'> ')
        p.sendline(b'2')
        p.recvuntil(b'ciphertext:\n')
        p.sendline(str(current_c).encode())
        res = b64decode(p.recvline())
        y = res[-1]
        k = (-y * inv_n) % 256
        ks.append(k)
        current_c = (current_c * inv_256_e) % n
        
    S = sum([k * (256**i) for i, k in enumerate(ks)])
    m = (-S * n) % (256**len(ks))
    print(long_to_bytes(m))

solve_flag()
```

### Decision

```python
from Crypto.Util.number import *
from sage.stats.distributions.discrete_gaussian_integer import DiscreteGaussianDistributionIntegerSampler
from sage.crypto.lwe import LWE
from secret import flag

flagbin = bin(int.from_bytes(flag.split(b'hgame{')[1][:-1], 'little'))[2:].rjust(25 * 8, "0")

n, m = 25, 15
q = getPrime(128)
F = GF(q)
V = VectorSpace(F, n)
D = DiscreteGaussianDistributionIntegerSampler(2**16) 
lwe = LWE(n=n, q=q, D=D)

def encrypt_bit(bit):
    if bit == 1:
        samples_list = [lwe() for _ in range(m)]
        return [tuple(list(a) + [b]) for a, b in samples_list]
    else:
        return [tuple([F.random_element() for _ in range(n + 1)]) for _ in range(m)]

encbit = []
for bit in flagbin:
    encbit.append(encrypt_bit(int(bit)))

with open("./output", "wb") as f:
    f.write(str(encbit).encode())

# q = 256708627612544299823733222331047933697
```

DLWE 的模板题，有趣的是我 LWE 那篇里面主要参考的鸡块师傅的博客，而鸡块师傅的那篇博客里主要讲的也是一个 DLWE 题，几乎一模一样

需要区分输出的结果是 LWE 样本还是随机生成的，这个题的 m<n，故需要先拼接一下。思路就是随机取几组，归约出误差向量 e，判断其是否符合条件，找到 e 即可恢复 s，找到 s 后区分输出具体是哪一类就简单了

格攻击不写了，在 LWE 那篇里有，贴个 exp

```python
import itertools

q = 256708627612544299823733222331047933697
n, m = 25, 15
F = GF(q)
with open('output.txt') as f:
    data = eval(f.read())
AA = []
bb = []
for i in data:
    tmp1, tmp2 = [], []
    for j in i:
        tmp1.append(j[:-1])
        tmp2.append(j[-1])
    AA.append(tmp1)
    bb.append(tmp2)
AA = [matrix(F, i) for i in AA]
bb = [vector(F, i) for i in bb]

# 略有改动
def primal_attack2(A, b, m, n, p, esz):
    L = block_matrix([
        [matrix(Zmod(p), A).T.echelon_form().change_ring(ZZ), 0],
        [matrix.zero(m - n, n).augment(matrix.identity(m - n) * p), 0],
        [matrix(ZZ, b), 1],
    ])
    #print(L.dimensions())
    Q = diagonal_matrix([1] * m + [esz])
    L *= Q
    L = L.LLL()
    L /= Q
    res = L[0]

    e = None
    if (res[-1] == 1):
        e = res[:m]
    elif (res[-1] == -1):
        e = -res[:m]
    if e:      
        return e
    return None

def check(ee):
    valid_e = True
    for x in ee:
        val = int(x)
        if val > q//2:
            val -= q
        if abs(val) > 2**32:  
            valid_e = False
            break
    return valid_e

search = range(len(data) - 1, len(data) - 20, -1) 
for idxs in itertools.combinations(search, 3):
    A = []
    b = []
    for i in idxs:
        A.append(AA[i])
        b.extend(bb[i])
    A = block_matrix([A[0], A[1], A[2]], ncols=1)
    b = vector(F, b)
    ee = primal_attack2(A, b, 45, 25, q, 2**16)
    if ee:
        valid_e = check(ee)
        if valid_e:
            print(f'{ee=}')
            s = matrix(Zmod(q), A).solve_right((vector(Zmod(q), b) - vector(Zmod(q), ee)))
            break

flag = ''
for i in range(200):
    tmpA = AA[i]
    tmpb = bb[i]
    tmpe = tmpb - tmpA * s
    valid_e = check(tmpe)
    if valid_e:
        flag += '1'
    else:
        flag += '0'

from Crypto.Util.number import long_to_bytes
print(long_to_bytes(int(flag, 2))[::-1]) # 反转一下
```

具体代码细节

DiscreteGaussianDistributionIntegerSampler(2**16) 标准差 $σ = 2^{16}$ ，均值为 0 的高斯(正态)分布

lwe() 返回的是一个 n 个分量的向量，即 A 矩阵的一行，以及由此算出来的 b

故output中是一个长度为200的列表，每一个元素是一个 m*(n+1) 的二维列表
