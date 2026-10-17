+++
title = "MoeCTF 2026"
date = "2026-10-16"
categories = ["WP"]
description = "出题 & WP"
image="111.png"

+++

# MoeCTF 2026

**前言**

时间飞逝，一晃一年过去了。今年参与了 MoeCTF 密码方向的出题工作，提供了大概一半数量的题目

个人认为难度还是和 Moe 这个标签匹配的，此外感觉也还算比较"有趣"吧...

本文记录我出的题目相关部分

> 可以前往 [MoeCTF_2026/official_writeups/crypto at main · XDSEC/MoeCTF_2026](https://github.com/XDSEC/MoeCTF_2026/tree/main/official_writeups/crypto) 查阅完整题目的题解

## moeSign1n

```python
from Crypto.Util.number import *
from random import randint

flag = b'moectf{???}'
p = getPrime(512)
q = getPrime(512)
n = p * q
phi = (p - 1) * (q - 1)
while 1:
    e = randint(2, n)
    if GCD(e, phi) == 1:
        d = pow(e, -1, phi)
        break

menu = '''1. get ciphertext.
2. submit.
3. quit.'''

while 1:
    print(menu)
    choice = int(input())
    if choice == 1:
        m = bytes.fromhex(input("what message(hex form) do u want to encrtpt?\n"))
        if m == b'MoeCTF 2026':
            print('no cheat!')
            continue
        print(pow(bytes_to_long(m), e, n))
    elif choice == 2:
        enc = int(input("plz sumbit the ciphertext.\n"))
        dec = long_to_bytes(pow(enc, d, n))
        if dec == b'MoeCTF 2026':
            print("Welcome to MoeCTF 2026!")
            print(flag)
            exit()
        else:
            print("incorrect!")
    elif choice == 3:
        print("bye!")
        exit()
    else:
        print("invalid input!")
        continue
```

本题考察了 RSA 这样的一个性质 (同态性)：设 $m_0$ 的密文 $c_0 \equiv m_0^e \pmod n$

若 $m_0= m_1 \cdot m_2$，$c_1 \equiv m_1^e \pmod n$，$c_2\equiv m_2^e \pmod n$

则 $c_0 \equiv c_1 \cdot c_2 \pmod n$，这一点很容易验证

故只需要简单计算

```Python
from Crypto.Util.number import *

m0 = bytes_to_long(b'MoeCTF 2026') # 93613338762656224415593014
m1 = 2
m2 = m0 // 2
print(long_to_bytes(m1).hex())
print(long_to_bytes(m2).hex())
# 02
# 26b7b2a1aa23101918191b
```

先选择选项1，提交 02 和 26b7b2a1aa23101918191b，得到两个密文，计算他们的乘积，然后选择选项2提交即可获得 flag `moectf{0p3n_4_d00r_70_7h3_w0r1d_0f_m0d3rn_cryp706r4phy}`

---

这个题本质上还算是 RSA 入门/简单 的难度，但是后面我发现有个问题是新生第一次做，似乎不太理解远程题工作的流程，不知道是要干什么，感觉最初的时候静态题目可能更容易上手一些？二是后来我发现这个题的题目代码写的有点长了，该简化一下的...

此外，看到一个有趣的解法：在 m = bytes.fromhex(...) 的时候添加前导0，挺巧妙的

## justXOR

```python
from Crypto.Util.number import long_to_bytes

flag = b'moectf{???}'
# just a normal big prime
M = 2039129633208009090414901212304234091626233923923301042398416489123719065081065776033127561876033127924471

def gen_key(base, n):
    a = [base]
    for _ in range(n - 1):
        new_val = (3 * a[-1] + 2) % M
        a.append(new_val)
    return a[-1]

n = 10**25
key = gen_key(1, n)
enc = bytes([x ^ y for x, y in zip(flag, long_to_bytes(key))])
# b'it\x0bM\xfa-\xe3T{\xaa\x0f@\xa2\xf1@\xbd\x86e\x85\x9e\xfcp_o\x8f\xccd\x13\xceW\x13\x14\x11\x055b\xcbk\xa0'
```

最后是一个异或加密，密钥由一个数列的递推公式产生，但是直接递推计算时间不可行；由递推公式求出通项公式，可以快速计算；实际上就是这样一个式子
$$
a_n \equiv 3a_{n-1}+2\pmod M
$$
如果没有模 M，只是一个等式的话，相信大家肯定都会算 (高中知识)；不过实际上有模 M 也相差不大，照猫画虎即可，这里并不需要太多模运算的东西

$a_1=1$，当 $n \geq 2$ 时，有 $a_n \equiv 3a_{n-1}+2 \pmod M$

设 $a_n+t \equiv 3(a_{n-1}+t) \pmod M$，则 $a_n\equiv 3a_{n-1}+2t \pmod M$

$\therefore t=1$，于是 $a_n+1 \equiv 3(a_{n-1}+1) \pmod M$

这是一个等比数列的形式，故 $a_n+1 \equiv 3(a_{n-1}+1) \equiv 3^2(a_{n-2}+1)\equiv \cdots \equiv 3^{n-1}(a_{1}+1) \pmod M$

最终得到
$$
a_n\equiv 2 \cdot 3^{n-1}-1 \pmod M
$$
exp 如下

```Python
M = 2039129633208009090414901212304234091626233923923301042398416489123719065081065776033127561876033127924471
n = 10**25
key = (2 * pow(3, n - 1, M) - 1) % M
enc = b'it\x0bM\xfa-\xe3T{\xaa\x0f@\xa2\xf1@\xbd\x86e\x85\x9e\xfcp_o\x8f\xccd\x13\xceW\x13\x14\x11\x055b\xcbk\xa0'
from Crypto.Util.number import long_to_bytes
flag = bytes([x ^ y for x, y in zip(enc, long_to_bytes(key))])
print(flag)
# moectf{a_simple_sequence_problem_for_u}
```

## the_KEY_of_DES

```python
from Crypto.Cipher import DES
from random import randbytes

flag = b'moectf{???}'
print("Do u know the length of DES'key? That may be the key of DES.")
m = randbytes(8)
print("Here is the message. Please enter two different keys to generate the same ciphertext.")
print(m)
try:
    key1 = bytes.fromhex(input("input the first  key(hex): "))
    key2 = bytes.fromhex(input("input the second key(hex): "))
    des1 = DES.new(key=key1, mode=DES.MODE_ECB)
    c1 = des1.encrypt(m)
    des2 = DES.new(key=key2, mode=DES.MODE_ECB)
    c2 = des2.encrypt(m)
except:
    print("something wrong.")
    exit()

if key1 == key2:
    print("no cheat!")
    exit()

if c1 == c2:
    print("You did it! Here is the flag")
    print(flag)
    exit()
else:
    print("bye!")
    exit()
```

DES 的有效密钥是 56bit，但是会添加 8bit 的校验位，最终变成64bit；校验位与加解密无关

`from Crypto.Cipher import DES` 后，需要给 DES 提供一个 64bit 的密钥，但是并不会进行是否正确的检查，适当修改校验位即可实现”碰撞”

`from Crypto.Cipher import DES` 的处理是对于 56bit 的有效密钥，分为 8 组，每组 7bit，在每组的末端加入校验位；故只改变一个组的末尾即可，一个构造如下

```tex
56bit: \x00\x00\x00\x00\x00\x00\x00
key1: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
key2: 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000001
```

也就是说提交下面两个密钥即可获得 flag `moectf{7h3_l177l3_7r1ck_w17h_7h3_ch3ck_d1g17}`

```tex
0000000000000000
0000000000000001
```

## 1391 超市

chal.py 如下，output.txt 这里就不放了

```python
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

key = os.urandom(16)
cipher = AES.new(key, AES.MODE_ECB)

def super_sha256(x):
    # 1391 market uses super hash, no one can break it! huh~
    result = x
    for _ in range(1391):
        result = sha256(result).digest()[:13]
    return result

def verify(target, tag):
    if len(target) != len(tag):
        return False
    l = len(target)
    for i in range(l):
        tmp1, tmp2 = target[i], tag[i]
        tmp3 = super_sha256(bytes([tmp1]))
        tmp4 = super_sha256(bytes([tmp2]))
        if tmp3 != tmp4:
            return False
    return True
        
def promotion(ticket):
    if ticket[0] == b'NaiLong Model':
        tar = cipher.encrypt(pad(ticket[0], 16))[:13]    
        if verify(tar, ticket[1]):
            print('We will send it to your home later.')
        else:
            print('invalid ticket!')
    else:
        print('Sorry, there is currently only one product.')
    
menu = '''1. shopping
2. quit'''
# ⚠️ plz submit the correct tag extracted from the output.txt, format moectf{...} ⚠️

while 1:
    print(menu)
    op = int(input('choice: '))
    if op == 1:
        tmp = input('Send hex-value ticket: ')
        # format: name, tag   such as: apple, 114514
        ticket = [bytes.fromhex(i) for i in tmp.split(', ')]
        promotion(ticket)
    if op == 2:
        print('bye!')
        exit()
```

这个题的初衷就是想搞一下时间上的侧信道，原理也非常简单，如果服务器端在校验一个东西的时候是逐个字节去比对，遇到不一致的就结束；那么就可以逐个字节去爆破，通过耗时来判断当前字节是否正确，显然正确的字节会进入下一轮比较，因而耗时会更长

故为了放大单字节比较的时间，使之能体现出差异，设计了 1391 次迭代哈希计算 (致敬 1931)

其实本来是打算出成远程题目让选手自己去搞的，但是我本地通了，远程不通 (有延迟等干扰因素)，最后也没有调好，故就以这种形式放出来了。事实上直接看 output.txt 也能发现每个字节总有一个值是异常的大，直接提取出来拼起来就是 flag `moectf{abed11be2e115680f30bd4f0d2}`

> 最后一个字节形式有所不同，大家可以看看代码，想一想这是为什么

这里放一个本地测试的脚本，感兴趣的话可以自己玩一玩

```Python
from pwn import *
import time

io = process(["python", "-u", "./chal.py"])
io.recvuntil(b'choice: ')
name = '4e61694c6f6e67204d6f64656c'

def attack_one_byte(index):
    times = []
    for i in range(256):
        tmp = hex(i)[2:].zfill(2)
        ticket = name + ', ' + known + tmp + '00' * (12 - index)

        start = time.perf_counter()
        for _ in range(70):
            io.sendline(b'1')
            io.recvuntil(b'ticket: ')
            io.sendline(ticket.encode())
            io.recvuntil(b'choice: ')
        end = time.perf_counter()
        # print((end - start, tmp))
        times.append((end - start, tmp))
    
    times.sort(reverse=True)
    return times[0]

known = ''
for i in range(12):
    tmp = attack_one_byte(i)[1]
    print(f'{i}-th byte: {tmp}')
    known += tmp

for i in range(256):
    last = hex(i)[2:].zfill(2)
    io.sendline(b'1')
    io.recvuntil(b'ticket: ')
    io.sendline((name + ', ' + known + last).encode())
    tmp = io.recvline()
    correct = False
    if b'We will' in tmp:
        correct = True
        print(io.recvline())
        # break
    io.recvuntil(b'choice: ')
```

## mid_det

```python
from Crypto.Util.number import bytes_to_long

flag = b'moectf{???}'
a = bytes_to_long(flag)
n = 521
A = matrix(n, n)
for i in range(1, n + 1):
    for j in range(1, n + 1):
        A[i - 1,j - 1] = (j - i) % n + 1
        A[i - 1,j - 1] += a

print(A.det())
```

本题顺延了去年的 ez_det，再出个行列式玩一玩；实际上需要求解的就是这个循环矩阵的行列式，先考虑没有加上 a 时的情况
$$
\begin{pmatrix} 1 & 2 & 3& \cdots & n \\ n & 1 & 2&\cdots & n-1 \\ n-1 & n & 1 &\cdots & n-2 \\ \vdots & \vdots & \vdots & \cdots & \vdots \\ 2 & 3 & 4 &\cdots & 1 \end{pmatrix}
$$
有许多方法可以用于求解其行列式，相信到现在的话大家课上可能也已经见过了，这里提供一种用初等变换的方法

1. 把各行都加到第一行，然后提取公因子得到

$$
\frac{n(n+1)}{2}\left|\begin{matrix} 1 & 1 & 1& \cdots & 1 \\ n & 1 & 2&\cdots & n-1 \\ n-1 & n & 1 &\cdots & n-2 \\ \vdots & \vdots & \vdots & \cdots & \vdots \\ 2 & 3 & 4 &\cdots & 1 \end{matrix}\right|
$$

2. 将第一行除第一列以外元素消为0

$$
\frac{n(n+1)}{2}\left|\begin{matrix} 1 & 0 & 0& \cdots & 0 \\ n & 1-n & 2-n&\cdots & -1 \\ n-1 & 1 & 2-n &\cdots & -1 \\ \vdots & \vdots & \vdots & \cdots & \vdots \\ 2 & 1 & 2 &\cdots & -1 \end{matrix}\right|
$$

然后按第一行展开，得到
$$
\frac{n(n+1)}{2}\left|\begin{matrix} 1-n & 2-n&\cdots & -1 \\ 1 & 2-n &\cdots & -1 \\ \vdots & \vdots & \cdots & \vdots \\ 1 & 2 &\cdots & -1 \end{matrix}\right|
$$

3. 从下往上，依次把上一行的 -1 倍加到下一行上去，第一行不变，可得

$$
\frac{n(n+1)}{2}\left|\begin{matrix} 1-n & 2-n&\cdots&-2 & -1 \\ n &0 &\cdots&0 & 0 \\ \vdots & \vdots & \cdots & \vdots &\vdots\\ 0 & 0 &\cdots&n & 0 \end{matrix}\right|
$$

此时就很显然了，可得最终结果是
$$
\text{det} = \frac{n^{n-1} (n+1)}{2} (-1)^{n+1}
$$
加上 a 之后，核心是不变的，仍然是：把各行都加到第一行、提取公因子、将第一行除第一列以外元素消为0；此时就可以发现右下角那个 (n-1) 阶的部分是一样的，大家可以自己试一试

exp 如下

```Python
from Crypto.Util.number import long_to_bytes

n = 521
det = ...
flag = (det // (pow(n, n - 1) * pow(-1, n + 1))) - (n + 1) // 2
print(long_to_bytes(flag))
# moectf{m4ny_m37h0d5_2_c4lcul473_7h3_det_0f_a_cycl1c_m47r1x}
```

## moePoly1

```python
from Crypto.Util.number import *
import uuid

flag = "moectf{" + str(uuid.uuid4()) + "}"
l = len(flag)
rounds = l
coef = [ord(i) << 248 for i in flag]
p = getPrime(256)
print(f'{p = }')

def eval_poly(x):
    y =  sum([c * pow(x, i, p) for i, c in enumerate(coef)]) % p
    return y

def query():
    try:
        x = int(input("input x: "))
        assert 0 < x < p
    except:
        print("something wrong")
        exit()
    print(eval_poly(x))

menu = '''1. query
2. quit'''

for i in range(rounds):
    print(f'ROUND {i + 1}/{rounds}')
    print(menu)
    op = int(input('choice: '))
    if op == 1:
        query()
    if op == 2:
        exit()
print("All rounds finished. It's your time to find the flag!")
```

本题构造了一个多项式，其系数就是 flag 的各个字符，故目标就是要恢复出多项式的系数；具体而言，有 44 个系数，可以查询 44 次，是刚刚好的

这个题并没有什么密码学知识，出出来的初衷就是想让锻炼一下写交互脚本，写多长的脚本取决于你用什么方法和工具 (当然如果是 ai 完成这项任务的话那就无所谓了)

假设多项式系数分别为 $f_0, f_1,\cdots ,f_{43}$，我们查询的 x 为 $x_1,x_2,...,x_{44}$，分别得到了对应的 y，那么实际上就是得到了一个方程组，我们可以把它写成矩阵形式
$$
\begin{pmatrix} x_1^0 & x_1^1 & \cdots & x_1^{43} \\ x_2^0 & x_2^1 & \cdots & x_2^{43} \\ \vdots & \vdots & \cdots & \vdots \\ x_{44}^0 & x_{44}^1 & \cdots & x_{44}^{43} \end{pmatrix}  \begin{pmatrix}  f_0 \\ f_1 \\ \vdots \\ f_{43} \end{pmatrix} \equiv \begin{pmatrix}  y_1 \\ y_2 \\ \vdots \\ y_{44} \end{pmatrix} \pmod p
$$
然后可以用 sagemath 内置函数求解，事实上 sage 里面也有内置的多项式插值函数，在后面 moePoly4 可以看到

```Python
from pwn import *

io = remote('127.0.0.1', 51293)
io.recvuntil(b'p = ')
p = int(io.recvline()[:-1].decode())
y = []
l = 44                                   
for i in range(l):
    io.recvuntil(b'choice: ')
    io.sendline(b'1')
    io.recvuntil(b'x: ')
    io.sendline(str(i + 1).encode())
    y.append(int(io.recvline()[:-1].decode()))

A = matrix(Zmod(p), l, l)
for i in range(l):
    A[i,0] = 1
    for j in range(1, l):
        A[i,j] = pow(i + 1, j, p)
y = vector(Zmod(p), y)
ans = A.solve_right(y)
print(''.join([chr(i >> 248) for i in ans]))
```

## moePoly2

```python
from Crypto.Util.number import *
import uuid

flag = "moectf{" + str(uuid.uuid4()) + "}"
l = len(flag)
rounds = l - 13
coef = [ord(i) << 248 for i in flag]
p = getPrime(256)
print(f'{p = }')

def eval_poly(x):
    y =  sum([c * pow(x, i, p) for i, c in enumerate(coef)]) % p
    return y

def query():
    try:
        x = int(input("input x: "))
        assert 0 < x < p
    except:
        print("something wrong")
        exit()
    print(eval_poly(x))

menu = '''1. query
2. quit'''

for i in range(rounds):
    print(f'ROUND {i + 1}/{rounds}')
    print(menu)
    op = int(input('choice: '))
    if op == 1:
        query()
    if op == 2:
        exit()
print("All rounds finished. It's your time to find the flag!")
```

和 moePoly1 核心是一样的，唯一区别是查询次数少了 13 次。为什么可以变少呢？因为 flag 的内容并非都是未知的，其形如 `moectf{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` 数一下发现 flag头，大括号，连字符，这些都是已知的，共有 12 个已知量，那我们只需要再爆破一个字符即可，因为 uuid 的格式，一个字符只有 16 种可能，枚举空间很小

> 😭 我最初的想法就是最后去爆破一个字符，当时并不知道 uuid.uuid4() 这东西有一位会是固定的 4，故完全没有考虑这一点。平台生成的动态 flag 虽然格式和 uuid4 是一致的，但是并不一定具备这一特征，而我将其混为一谈了
>
> 故若有师傅因此困扰，我非常抱歉，给大家跪了！！！

回到题目，同样假设多项式系数分别为 $f_0, f_1,\cdots ,f_{43}$(其中一部分是已知的)，我们查询的 x 为 $x_1,x_2,...,x_{31}$，分别得到了对应的 y，为了方便分析，这次换个写法
$$
f_0 \begin{pmatrix} x_1^0 \\ x_2^0 \\ \vdots \\ x_{31}^0 \end{pmatrix} + f_1 \begin{pmatrix} x_1^1 \\ x_2^1 \\ \vdots \\ x_{31}^1 \end{pmatrix} + \cdots + f_{43} \begin{pmatrix} x_1^{43} \\ x_2^{43} \\ \vdots \\ x_{31}^{43} \end{pmatrix} \equiv \begin{pmatrix}  y_1 \\ y_2 \\ \vdots \\ y_{31} \end{pmatrix} \pmod p
$$
之后只需要把 12 个已知的和枚举的一个 $f_i$ 都移到右边，就可以得到一个方阵，此时解方程即可

这里提供一个我写的交互脚本

```Python
from pwn import *

io = remote('127.0.0.1', 61467)
io.recvuntil(b'p = ')
p = int(io.recvline()[:-1].decode())
y = []
l = 44 - 13                                   
for i in range(l):
    io.recvuntil(b'choice: ')
    io.sendline(b'1')
    io.recvuntil(b'x: ')
    io.sendline(str(i + 1).encode())
    y.append(int(io.recvline()[:-1].decode()))

fakeflag = 'moectf{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}'
A = matrix(Zmod(p), l, l + 13)
y = vector(Zmod(p), y)
for i in range(l):
    A[i,0] = 1
    for j in range(1, l + 13):
        A[i,j] = pow(i + 1, j, p)

A1 = A
for i in range(len(fakeflag)):
    if fakeflag[i] != 'x':
        y -= (ord(fakeflag[i]) << 248) * A.column(i)

A1 = A1.delete_columns([0, 1, 2, 3, 4, 5, 6, 43, 15, 20, 25, 30, 7])     
y1 = y
for i in '0123456789abcdef':
    y1 = y - (ord(i) << 248) * A.column(7)
    ans = A1.solve_right(y1)
    try:
        flag = i + ''.join([chr(i >> 248) for i in ans])
        if all(j in '0123456789abcdef' for j in flag):
            break
    except:
        print(i, 'wrong')
        pass
print('moectf{' + flag[:8] + '-' + flag[8:12] + '-' + flag[12:16] + '-' + flag[16:20] + '-' + flag[20:] + '}')
```

## moePoly3

```python
from Crypto.Util.number import *
from random import randint

flag = b'moectf{???}'
rounds = 1
coef = [randint(0,255) for _ in range(31)]
target = int(''.join([str(i) for i in coef]))
p = getPrime(256)
print(f'{p = }')

def eval_poly(x):
    y =  sum([c * pow(x, i, p) for i, c in enumerate(coef)]) % p
    return y

def query():
    try:
        x = int(input("input x: "))
        assert 0 < x < p
    except:
        print("something wrong")
        exit()
    print(eval_poly(x))

menu = '''1. query
2. quit'''

for i in range(rounds):
    print(f'ROUND {i + 1}/{rounds}')
    print(menu)
    op = int(input('choice: '))
    if op == 1:
        query()
    if op == 2:
        exit()

ans = int(input('OK. plz submit the answer: '))
if ans == target:
    print('Congratulations! Here is your flag: ')
    print(flag)
else:
    print('incorrect. bye!')
```

这个题查询次数更少了，需要一次恢复出 31 个系数；值得注意的是系数范围都在 0~255 之间，也就是说不会超过 8 bit

故这里的做法其实就是只需要传入 $2^8$ 即 256，各系数的二进制表示就会恰好错开，连着排列在一起

因为 $31*8=248$，而 p 是 256bit，结果也不会超过 p，这时候只需要依次读出来即可

```Python
# y = 提交 256 得到 y 
y_b = bin(y)[2:].zfill(248)
tmp = [str(int(y_b[i:i + 8], 2)) for i in range(0, len(y_b), 8)]
ans = ''.join([i for i in tmp[::-1]])
print(ans) # 提交 ans 即可得到 flag
```

这个题同样也没什么密码学知识点，算是个小游戏吧 🤖

## moePoly4

```python
from Crypto.Util.number import *
from random import randint

flag = b'moectf{???}'
rounds = 20
n = 26

def lcg(x, a, b, p):
    return (a * x + b) % p

def eval_poly(x):
    y =  sum([c * pow(x, i, p) for i, c in enumerate(coef)]) % p
    return y

def query():
    try:
        x = int(input("input x: "))
        assert 0 < x < p
    except:
        print("something wrong")
        exit()
    print(eval_poly(x))

p = 2**256 - 435
a = randint(0, p)
b = randint(0, p)
seed = randint(0, p)
tmp = seed
coef = []
for _ in range(n):
    tmp = lcg(tmp, a, b, p) 
    coef.append(tmp >> 128)

menu = '''1. query
2. quit'''

print('lcg params:')
print(f'{a = }')
print(f'{b = }')
print(f'{p = }')

for i in range(rounds):
    print(f'ROUND {i + 1}/{rounds}')
    print(menu)
    op = int(input('choice: '))
    if op == 1:
        query()
    if op == 2:
        break

ans = int(input('OK. plz submit the seed: '))
if ans == seed:
    print('Congratulations! Here is your flag: ')
    print(flag)
else:
    print('incorrect. bye!')
```

这个题本质上是我拿了之前做过的两个题拼在一起的；其任务是需要恢复 lcg 的种子，而 lcg 生成的序列是多项式的系数。那么很显然是需要两步来完成：先恢复系数，再求出种子

简而言之第一部分的关键是要注意到 $20 | p-1$，第二部分就是个 HNP 模板题

在 GitHub 上的题解里我写了一版，这里在博客里的话，就直接引用了，里面介绍的更详细一些

恢复系数：[题目切片-(一) 1-ssss](https://hataovo.github.io/p/题目切片-一/#osugaming-ctf-2025-ssss)

恢复种子：[格密码-HNP truncated lcg](https://hataovo.github.io/p/格密码-hnp/#未知-truncated-lcg)

还有一种解法没有利用 $20|p-1$，而是写了很复杂的关系式，然后直接构造的格 (~~强行顶吗~~)，倒是也能解出来，那这么想来或许许多 AI 可能都是这么搞的吧 ...?

这里放一个参考 exp

```python
from pwn import *

io = remote('127.0.0.1', 51483)
io.recvuntil(b'a = ')
a = int(io.recvline()[:-1].decode())
io.recvuntil(b'b = ')
b = int(io.recvline()[:-1].decode())
io.recvuntil(b'p = ')
p = int(io.recvline()[:-1].decode())

g0 = primitive_root(p)
g = pow(g0, (p - 1) // 20, p)
R.<x> = PolynomialRing(GF(p))
points = []
for i in range(20):
    io.recvuntil(b'choice: ')
    io.sendline(b'1')
    io.recvuntil(b'x: ')
    tmp_x = pow(g, i, p)
    io.sendline(str(tmp_x).encode())
    y = int(io.recvline()[:-1].decode())
    points.append((tmp_x, y))
ans = list(R.lagrange_polynomial(points)) # 系数列表：低次->高次
output = ans[6:]

#######
n = p
h = [i * pow(2, 128) for i in output]

l = len(h)
t, A, B = [], [], []
for i in range(l - 1):
    tmp = a * h[i] + b - h[i + 1]
    t.append(tmp % n)
for i in range(1, l):
    A.append(pow(a, i, n))
B.append(t[0])
for i in range(1, l - 1):
    B.append((a * B[-1] + t[i]) % n)

L = matrix(ZZ, l + 1, l + 1)
for i in range(l - 1):
    L[i,i] = n
    L[-2,i] = A[i]
    L[-1,i] = B[i]
L[-2,-2] = 1
L[-1,-1] = 1

print(L.LLL()[0])
c6 = h[0] + L.LLL()[0][-2]
print(c6)
tmp = c6
for _ in range(7):
    tmp = (tmp - b) * pow(a, -1, n) % n
print(tmp)
io.recvuntil(b'seed: ')
io.sendline(str(tmp).encode())
print(io.recvline())
print(io.recvline())
```