+++
title = "QCTF 2026"
date = "2026-11-07"
categories = ["WP"]
description = "出题 & WP"
image="111.png"

+++

# ?CTF 2026

**前言**

?CTF 去年的时候做了好久，记忆犹新

今年偶然的机会提供了四个题目，自我感觉对新生难度应该不算太简单也不算太难；不过在现在的环境下，想解出来这几个题确实不是难事了

不过有一说一今年题目量是少了不少，涉猎范围可能也没那么广了。一点主观感受就是出题群里确实很冷清，唉，确实是不一样了...



## Decision

```python
from Crypto.Util.number import getPrime
from random import randint

flag = b'flag{???}'
p = getPrime(512)
g = 2
key = ''

with open('output.txt', 'w') as f:
    for _ in range(40):
        coin = randint(0, 1)
        key += str(coin)
        x = randint(0, p - 2)
        y = randint(0, p - 2)
        if coin:
            z = x * y % (p - 1)
        else:
            z = randint(0, p - 2)
        data = (pow(g, x, p), pow(g, y, p), pow(g, z, p))
        f.write(str(data) + '\n')

from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

key = sha256(key.encode()).digest()[:16]
enc = AES.new(key, AES.MODE_ECB).encrypt(pad(flag, 16))
print(p)
print(enc.hex())
```

g 是 $Z_p^*$ 的生成元，目标是区分 $(g^x,g^y,g^{xy})$ 和 $(g^x,g^y,g^z)$，这是一个 DDH 问题

考虑二次剩余，若 x 为偶数 (x=2k)
$$
(\frac{g^x}{p}) = g^{x\cdot{\frac{p-1}{2}}} \equiv g^{k(p-1)}\equiv 1 \pmod p
$$
若 x 为奇数，则 (x=2k+1)
$$
(\frac{g^x}{p}) = g^{x\cdot{\frac{p-1}{2}}} \equiv g^{\frac{p-1}{2}}\equiv -1 \pmod p
$$
故：若根据二次剩余的取值，可以推出其指数的奇偶性；若 x，y，z 的奇偶性不能满足 z=xy，此时可确定 z 一定是随机产生的

这样大概可以确定 1/4 的比特位，具体的题目数据中是留下 26bit 不确定，稍微爆破一下就好了

```python
data = []
p = 9706421526104134675216178698618252594384526616513912867587820435227225196046220898188947059107560993264628438128588538107847960717709029325452940057166067
g = 2
q = (p - 1) // 2

with open('output.txt') as f:
    for i in range(40):
        tmp = eval(f.readline()[:-1])
        data.append(tmp)

key = []
for i in range(40):
    gx, gy, gz = data[i][0], data[i][1], data[i][2]
    t1, t2, t3 = pow(gx, q, p) % 2, pow(gy, q, p) % 2, pow(gz, q, p) % 2
    if (t1, t2, t3) in [(1, 1, 0), (1, 0, 0), (0, 1, 0), (0, 0, 1)]:
        key.append(0)
    else:
        key.append('?')
print(key) 
pos = [i for i, c in enumerate(key) if c == '?']

from hashlib import sha256
from Crypto.Cipher import AES

enc = bytes.fromhex('3923d855c2a08a7b9b0ce86682c52925a52e53428271c1b9e488fe9747bc63b7')
for i in range(2**len(pos)):
    tmp = list(bin(i)[2:].zfill(len(pos)))
    for j in range(len(pos)):
        key[pos[j]] = tmp[j]
    k1 = ''.join([str(i) for i in key])
    k2 = sha256(k1.encode()).digest()[:16]
    flag = AES.new(k2, AES.MODE_ECB).decrypt(enc)
    if b'flag' in flag:
        print(flag)
        break
# flag{7h15_DDH_15_vu1n_r16h7?}
```

## Curve

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from os import urandom
from Crypto.Util.number import bytes_to_long

flag = b'flag{???}'
key = urandom(16)
cipher = AES.new(key, AES.MODE_ECB)
pt = pad(flag, 16)
ct = cipher.encrypt(pt)

prec = 700            
R = RealField(prec)
E = EllipticCurve(R, [-2, 0])
gx = R(2)
gy = sqrt(gx^3 - 2 * gx)
G = E(gx, gy)
d = bytes_to_long(key)
P = d * G
print(P.x(), P.y(), ct.hex())
```

这个题实际上是仿制的 crypto hack 上 ecc 部分的一个题

声明了一条曲线，不同之处在于：ECC 使用的一般是 GF(p) 上的曲线，而这里是在实数域上的
$$
y^2 = x^3 - 2x
$$
实数域上的 ECDLP 是有办法解决的，其思路就是找到一个同态 u
$$
u(P+Q) = u(P) + u(Q)
$$
那么就有可能在同态的像所在的群里求出 d (和异常曲线的攻击方法类似)
$$
u(dG) = du(G)
$$
具体地，这里的 u 就是椭圆对数，其满足
$$
u(P+Q)\equiv u(P)+u(Q)\pmod{\Omega}
$$
这里忽略了细节，实际上 sage 中已经内置了相关函数，可以方便的使用，因此我们可以得到
$$
u(P) \equiv d u(G) \pmod{\Omega} \\
u(P) - d u(G) - k\Omega =0
$$
最后用一个格可以恢复出 d，但是由于这些数据不是整数，故需要放缩一下，大致如下
$$
Cd u(G) + Ck\Omega -Cu(P) =0 \\
(d,-1,k)\begin{pmatrix} 1&0&A\\ 0&H&B\\ 0&0&C\Omega \end{pmatrix} = (d,-H,0)
$$
但是因为实际上有精度问题和舍入误差，目标向量第三个不一定是 0，故根据第二项来判断

```python
prec = 700            
R = RealField(prec)
gx = R(2)
gy = sqrt(gx^3 - 2 * gx)
px = ...
py = ...
px, py = R(px), R(py)

E = EllipticCurve(R, [-2, 0])
L = E.period_lattice()
uG = L.e_log_RC(gx, gy, prec=prec).real()
uP = L.e_log_RC(px, py, prec=prec).real()
omega = L.real_period(prec=prec)
C = 2^prec
A = (uG * C).round()
B = (uP * C).round()
H = 2^128
M = matrix(ZZ, [[1, 0, A], [0, H, B], [0, 0, (C * omega).round()]])
d = M.LLL()[0][0]

from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
cipher = AES.new(long_to_bytes(d), AES.MODE_ECB)
ct = bytes.fromhex("52e1f1afae15867b80ad1f684b704a693a72296b8ff76035fe48db2a8d2be6323e81da9ad963a0adc38ac04e3205b3c9")
print(cipher.decrypt(ct))
# flag{GF(p)_15_3553n7141_4_53cur17y}
```

## ezDec

```python
from Crypto.Util.number import getPrime, bytes_to_long, GCD
from random import randint

def Gen():
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    phi = (p - 1) * (q - 1)
    return n, phi

def Enc(m, n):
    while 1:
        r = randint(1, n)
        if GCD(r, n) == 1:
            break
    c = pow(n + 1, m, n**2) * pow(r, n, n**2) % pow(n, 2)
    return c

def Dec():
    pass # The task is yours.

m = bytes_to_long(b'flag{???}')
pk, sk = Gen()
c = Enc(m, pk)
print(f'{pk = }')
print(f'{sk = }')
print(f'{c = }')
```

这个非常直白，把解密算法补充完整就好了，这里实际上就是 Paillier 加密算法

定义函数：$L(x)=\frac{x-1}{n}$，这里是普通整数除法

解密公式是
$$
m=L(c^\lambda\bmod n^2)\,\mu\bmod n
$$
其中，$\lambda = \phi, \ \mu = \lambda^{-1}\pmod n $

细节这里就不赘述了

```python
pk = ...
sk = ...
c = ...

n = pk
skinv = pow(sk, -1, n)
m = (pow(c, sk, n**2) - 1) // n * skinv % n
from Crypto.Util.number import long_to_bytes
print(long_to_bytes(m))
# flag{n0w_u_kn0w_P411113r_3ncryp710n_5ch3m3!!!}
```

## LinearRSA

```python
from Crypto.Util.number import getPrime, bytes_to_long
from random import randint

flag = b'flag{???}'
p = getPrime(1024)
q = getPrime(1024)
n = p * q
e = 547

r, s = randint(1, 2**1024), randint(1, 2**1024) 
a, b, h = [], [], []
for _ in range(3):
    a.append(randint(1, 2**200))
    b.append(randint(1, 2**200))
    h.append(r * a[-1] + s * b[-1])

t = bytes_to_long(flag)
m, c = [], []
for i in range(3):
    m.append(a[i] * t + b[i])
    c.append(pow(m[-1], e, n))

print(f'{n = }')
print(f'{h = }')
print(f'{c = }')
```

题目给了三组 $h_i=ra_i+sb_i$，以及 $a_i t+b_i$ 的密文。应该比较清晰的是需要两步完成：先求出 a 向量和 b 向量，然后恢复 flag

1. 恢复 a 和 b

这里用的是正交格的思想，实际上解法和之前写的 [题目切片-(二)](https://hataovo.github.io/p/题目切片-二/#downunderctf-2023-apbq-rsa-ii) 中的 apbq rsa ii 是一致的，在博客里就不重复写了

略有不同的是，最后不一定就是直接找到了 a 和 b，而是可能找到两个向量 u 和 v，a 和 b 在其张成的空间内，故这里需要小范围枚举一下线性组合，这里我专门挑了一组数据满足 $b = -u, a = -u + v$，比较好枚举一些

```python
n = ...
h = ...
c = ...

M1 = matrix(ZZ, 3, 4)
K = 2^800
for i in range(3):
    M1[i, 0] = K * h[i]
    M1[i, i + 1] = 1
v = M1.LLL()[0][1:]

M2 = matrix(ZZ, 3, 4)
for i in range(3):
    M2[i, 0] = K * v[i]
    M2[i, i + 1] = 1
u, v = M2.LLL()[0][1:], M2.LLL()[1][1:]

b = -u
a = -u + v
```

> wp 中发现，在 sage 里直接用两次 `right_kernel_matrix().LLL()` 也是可以求出一样的 u 和 v 的，许多师傅都是这么做的，更简洁一些

2. 恢复 t，即 flag

这里有点像相关信息攻击，但更简单一些，如果这样考虑
$$
m_1 = a_1t+b_1 \\
m_2 = a_2t+b_2
$$
认为 m1 和 m2 之间有线性关系，那就是标准的相关信息攻击

但实际上，可以直接看成 t 的多项式求 gcd 就行了，因为 (x-t) 是二者的公共根
$$
f_1 = (a_1  x + b_1)^e - c_1 \\
f_2 = (a_2  x + b_2)^e - c_2
$$

```python
c1, c2 = c[1:]
a1, a2 = a[1:]
b1, b2 = b[1:]
e = 547
PR.<x> = PolynomialRing(Zmod(n))

def poly_gcd(f, g):
    while g:
        f, g = g, f % g
    return f.monic()

f1 = (a1 * x + b1)^e - c1
f2 = (a2 * x + b2)^e - c2
t = -poly_gcd(f1, f2)[0]
from Crypto.Util.number import long_to_bytes
print(long_to_bytes(int(t)))
# flag{1_cr3473_4_11n34r_w0r1d_d0_y0u_11k3_7h15?}
```

