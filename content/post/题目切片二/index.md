+++
title = "题目切片-(二)"
date = "2026-09-08"
categories = ["密码学习"]
description = "连载中..."

+++

# 题目切片-(二)

**前言**

接着找一些题做一做，连载中...

接下来可能会把 apbq rsa iii 和 iv 以及 ZKpuzzle2 和 3 写一写 (如果我还比较感兴趣的话)，或者写点别的

## [Mini L-CTF 2025] Noisy

```python
from Crypto.Util.number import getPrime
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from random import getrandbits, randint
from hashlib import md5


class Noisy_cipher:
    def __init__(self, params):
        self.nbits = params["nbits"]
        self.pbits = params["nbits"]//2
        self.Mbits = params["Mbits"]
        self.k0bits = params["k0bits"]
        self.k1bits = params["k1bits"]
        self.samples = params["samples"]
        self.p = getPrime(self.pbits)
        self.q = getPrime(self.nbits)
        self.n = self.p * self.q
        self.s = randint(0, self.n)
        self.M = getrandbits(self.Mbits)
        self.pubKey = [self.n]
        self.priKey = [self.s, self.p, self.M]
    
    
    def encrypt(self,msg):
        res = []
        for i in range(self.samples):
            k0 = getrandbits(self.k0bits)
            k1 = getrandbits(self.k1bits)
            ci = self.s * (msg[i] + k0*self.M)*(1 + k1*self.p) % self.n
            res.append(ci)
        
        return res


if __name__ == '__main__':
    params = {
        "nbits":1024,
        "Mbits":30,
        "k0bits":30,
        "k1bits":512,
        "samples":20,
    }
    mbits = 24
    Noise = Noisy_cipher(params)
    n = Noise.n
    msg = [getrandbits(mbits) for _ in range(params["samples"])]
    cipher = Noise.encrypt(msg)
    with open('secret.txt', 'r') as file:
        flag = file.readlines()[0].encode()
    file.close()
    key = md5(str(msg).encode()).digest()
    aes = AES.new(key, AES.MODE_ECB)
    encrypted_flag = aes.encrypt(pad(flag, 16)).hex()
    with open('output.txt', 'a') as file:
        file.write('n = ' + str(n) + '\n')
        file.write('c = ' + str(cipher) + '\n')
        file.write('encrypted_flag = "' + encrypted_flag + '"\n')
    file.close()
```

干了一件这样的事情：
$$
c_i \equiv s(m_i+k_{0,i}M)(1+k_{1,i}p) \pmod n
$$
各参数的数量级，其中除了 n 剩下的都是未知的

```
n    1536
s    1024
p    512
k_0  30
k_1  512
M    30
m    24
```

现在已知 20 个 c，任务是要恢复出所有的 m

---

发现 $(m+k_0M)$ 这一项是小量，大约为 60 bit，记其为 a，则
$$
c_i \equiv s\cdot (x_i+k_{1,i}x_i\cdot p ) \pmod n \\
$$

做模 p 处理
$$
c_i \equiv s\cdot a_i \pmod p
$$
这时可以用正交格的思路，考虑这个格：
$$
\mathcal L = \{ u: \langle u,c\rangle\equiv0\pmod n \}
$$
即所有满足
$$
\sum_i u_i c_i\equiv0\pmod n
$$
的整数向量 u；进一步有
$$
0 \equiv \sum_i u_i c_i \equiv s\sum_i u_i a_i \pmod p
$$
s 和 p 互素，可得
$$
\sum_i u_i a_i \equiv 0\pmod p
$$
进一步地，由柯西不等式，并且 a 是短向量，如果找到的 u 也足够短，那么可以得到第二个小于号
$$
\left| \sum_i u_i a_i\right| \leq \Vert u\Vert \cdot \Vert a\Vert < p 
$$
但这个整数又是 p 的倍数，所以只能是
$$
\sum_i u_i a_i=0
$$
那么就可以对 u 向量组成的矩阵求零空间恢复出 a

> 这时关于求 u，就可能会想到 "把 c 向量当作矩阵，然后求其零空间得到 u " 的做法。但是这么做是有问题的，因为如果直接把 c 看成整数矩阵，求出来的是 $\sum_i u_i c_i = 0$，并非上述分析的 $\sum_i u_i c_i\equiv0\pmod n$，事实上普通零空间只取到了目标格里的一个很小的子集

故下一个任务是考虑如何求出 u

假设 c0 在模 n 下可逆，则
$$
c_0u_0+c_1u_1+\cdots+c_{19}u_{19}\equiv0\pmod n
$$
等价于
$$
u_0\equiv -\sum_{i=1}^{19}c_i c_0^{-1}u_i \pmod n
$$
令 $r_i=-c_i c_0^{-1}\pmod n$

于是 $u_0=nz+\sum_{i=1}^{19}r_i u_i$，可得：
$$
u=(u_0,u_1,...,u_{19})= z(n,0,\ldots,0) + u_1(r_1,1,0,\ldots) +\cdots+ u_{19}(r_{19},0,\ldots,1)
$$
所以可以构造出
$$
B= \begin{pmatrix} n&0&0&\cdots&0\\ r_1&1&0&\cdots&0\\ r_2&0&1&\cdots&0\\ \vdots&&&\ddots&\\ r_{19}&0&0&\cdots&1 \end{pmatrix}
$$
对 B 做 LLL 可以求出短向量 u

---

求出 a，即 $(m_i+k_{0,i}M)$ 之后，剩下的就是一个标准的 ACD 问题了，可以用典型的丢番图近似 SDA 格攻击，也可以继续正交格来做

> Approximate Common Divisor Problem     $a_i = pq_i + r_i$

**丢番图**：构造如下关系式，i 从 1 开始取
$$
a_i q_0 - a_0q_i = pq_iq_0 + r_iq_0 - pq_0q_i - r_0q_i = r_iq_0- r_0q_i 
$$
进一步构造格，K 取为 r 的比特位数
$$
(q_0,q_1,q_2,...,q_t)\begin{pmatrix}
2^K& a_1& a_2 &\cdots & a_t\\
& -a_0&  & &\\
& & -a_0 & &\\
& &  & \ddots& \\
& &  & &-a_0
\end{pmatrix} = (q_02^K, r_1q_0-r_0q_1,r_2q_0-r_0q_2,...,r_tq_0-r_0q_t)
$$
**正交格**：$a_i=m_i+k_{0,i}M$，这里直接就是等号，没有模了。同样是构造下面典型的格，R 取为 2的{m 的比特位数}次方
$$
B_2= \begin{pmatrix} a_0&R&0&\cdots&0\\ a_1&0&R&\cdots&0\\ \vdots&&&\ddots&\\ a_{19}&0&0&\cdots&R \end{pmatrix}
$$
任意格向量都是
$$
v= \left( \sum_i u_i a_i, Ru_0,\ldots,Ru_{19} \right)
$$
代入 $a_i=Mk_i+m_i$，有
$$
v_0-\sum_i u_i m_i = M\sum_i u_i k_i
$$
LLL 找到足够短的 v 时，左边绝对值会小于 M，所以只能有
$$
\sum_i u_i k_i =0
$$
于是得到 $k^\perp$，再求零空间得到 k，最后对 ki 取模即可恢复 mi

正交格+正交格的 exp

```python
n = ...
c = ...
encrypted_flag = ...

tmp = pow(c[0], -1, n)
r = [(ci * tmp * (-1)) % n for ci in c[1:]]
B = matrix(ZZ, 20, 20)
for i in range(1, 20):
    B[i, 0] = r[i - 1]
    B[i, i] = 1
B[0, 0] = n
u = B.LLL()[:-2]
a = u.right_kernel_matrix()[0]
a = [abs(i) for i in a]


B2 = matrix(ZZ, 20, 21)
R = 2^24
for i in range(20):
    B2[i, 0] = a[i]
    B2[i, i + 1] = R
tmp = B2.LLL()[:-1]
u2 = [list(i[1:]) for i in tmp]
for i in u2:
    for j in range(len(i)):
        i[j] //= R
k = matrix(u2).right_kernel_matrix()[0]
k = [abs(i) for i in k]

msg = []
for i in range(20):
    msg.append(a[i] % k[i])
```

第二部分用丢番图法的 exp，都能出结果

```python
K = 24
L = matrix(ZZ, 20, 20)
for i in range(1, 20):
    L[0, i] = a[i]
    L[i, i] = -a[0]
L[0, 0] = 2^K
k0 = L.LLL()[0][0] // 2^K
M = a[0] // k0
msg = []
for i in range(20):
    msg.append(a[i] % M)
```

参考：

1. [miniLCTF_2025/OfficialWriteups/Crypto/Noisy.md at main · XDSEC/miniLCTF_2025](https://github.com/XDSEC/miniLCTF_2025/blob/main/OfficialWriteups/Crypto/Noisy.md)
2. [1208.pdf](https://eprint.iacr.org/2018/1208.pdf)

## [DownUnderCTF 2023] apbq rsa i

```python
from Crypto.Util.number import getPrime, bytes_to_long
from random import randint

p = getPrime(1024)
q = getPrime(1024)
n = p * q
e = 0x10001

hints = []
for _ in range(2):
    a, b = randint(0, 2**12), randint(0, 2**312)
    hints.append(a * p + b * q)

FLAG = open('flag.txt', 'rb').read().strip()
c = pow(bytes_to_long(FLAG), e, n)
print(f'{n = }')
print(f'{c = }')
print(f'{hints = }')
```

给了条件
$$
h_0 = a_0p+b_0q \\
h_1 = a_1p+b_1q
$$
其中 a 是可以枚举的，把 p 消掉
$$
a_1h_0-a_0h_1 = a_1b_0q-a_0b_1q=(a_1b_0-a_0b_1)q
$$
之后再和 n 做一个 gcd 即可

## [DownUnderCTF 2023] apbq rsa ii

```python
from Crypto.Util.number import getPrime, bytes_to_long
from random import randint

p = getPrime(1024)
q = getPrime(1024)
n = p * q
e = 0x10001

hints = []
for _ in range(3):
    a, b = randint(0, 2**312), randint(0, 2**312)
    hints.append(a * p + b * q)

FLAG = open('flag.txt', 'rb').read().strip()
c = pow(bytes_to_long(FLAG), e, n)
print(f'{n = }')
print(f'{c = }')
print(f'{hints = }')
```

给了三组 $h_i= a_ip+b_iq$，显然无法枚举，需要找新的办法。有点像 Noisy 的后半部分的做法

这里构造的是
$$
M_1= \begin{pmatrix} Kh_1&1&0&0\\ Kh_2&0&1&0\\ Kh_3&0&0&1 \end{pmatrix}
$$
它的任意格向量都可以写成
$$
(x_1,x_2,x_3)M_1 = \left( K(x_1h_1+x_2h_2+x_3h_3), x_1,x_2,x_3 \right)
$$
若 r 向量同时与 a 向量与 b 向量正交，那么自然和 h 向量正交，此时目标向量是 $(0, r_1, r_2, r_3)$

而这时可以认为 r 就与 a 和 b 的叉乘 $\vec{a} \times \vec{b}$ 有关系，更严格地说，如果叉积三个坐标的最大公因数为 g，这个方向上最短的非零整数向量就是
$$
r=\pm\frac{\mathbf A\times\mathbf B}{g}
$$

叉乘的分量大小大概是 624 bit，而 g 大概率就是1，我们给 K 取一个大的值，如 $2^{800}$，那么 LLL 就能找到想要的向量 r

接下来希望通过 r 找回 a 向量和 b 向量，故再构造类似的格
$$
M_2= \begin{pmatrix} Kr_1&1&0&0\\ Kr_2&0&1&0\\ Kr_3&0&0&1 \end{pmatrix}
$$
它的任意格向量都可以写成
$$
(x_1,x_2,x_3)M_2 = \left(K(x_1r_1+x_2r_2+x_3r_3) ,x_1,x_2,x_3\right)
$$
如果 $\mathbf x\cdot\mathbf r=0$，对应格向量就是 $(0, x_1,x_2,x_3)$，故还是配一个大的 K，但是不一定就是直接找到了 a 和 b，而是找到两个独立短向量 $\mathbf U,\mathbf V$，它们张成整数格 $L=\{\mathbf x\in\mathbb Z^3:\mathbf   x\cdot\mathbf r=0\}$，即
$$
L = s \mathbf U + t\mathbf V
$$
实际操作后发现 U, V 的长度和 A 差不多，故作者 wp 之后枚举了小的 s 和 t，来寻找 $A=s\mathbf U+t\mathbf V$

实际上归约出的第一个分量就是 a 向量

最后有了 a 向量，只需要和 apbq rsa i 中一样构造然后 gcd 即可分解 n

```python
n = ...
c = ...
hints = ...

M1 = matrix(ZZ, 3, 4)
K = 2^800
for i in range(3):
    M1[i, 0] = K * hints[i]
    M1[i, i + 1] = 1
r = M1.LLL()[0][1:]


M2 = matrix(ZZ, 3, 4)
for i in range(3):
    M2[i, 0] = K * r[i]
    M2[i, i + 1] = 1
L = [i[1:] for i in M2.LLL()[:2]]

a1, a2, a3 = L[0]
tmp_q = gcd(a1 * hints[1] - a2 * hints[0], n)
```

参考：

[Challenges_2023_Public/crypto/apbq-rsa-ii at main · DownUnderCTF/Challenges_2023_Public](https://github.com/DownUnderCTF/Challenges_2023_Public/tree/main/crypto/apbq-rsa-ii)

## [0CTF 2025] ZKpuzzle1

```python
from sage.all import EllipticCurve, Zmod, is_prime, randint, inverse_mod
from ast import literal_eval
from secret import flag

class proofSystem:
    def __init__(self, p1, p2):
        assert is_prime(p1) and is_prime(p2)
        assert p1.bit_length() == p2.bit_length() == 256
        self.E1 = EllipticCurve(Zmod(p1), [0, 137])
        self.E2 = EllipticCurve(Zmod(p2), [0, 137])

    def myrand(self, E1, E2):
        F = Zmod(E1.order())
        r = F.random_element()
        P = r * E2.gens()[0]
        x = P.x()
        return int(r * x) & (2**128 - 1)

    def verify(self, E, r, k, w):
        G = E.gens()[0]
        P = (r*k) * G
        Q = (w[0]**3 + w[1]**3 + w[2]**3 + w[3]**3) * inverse_mod(k**2, G.order()) * G
        return P.x() == Q.x()


def task():
    ROUND = 1000
    threshold = 999
    print("hello hello")
    p1, p2 = map(int, input("Enter two primes: ").split())

    proofsystem = proofSystem(p1, p2)
    print(f"You need to succese {threshold} times in {ROUND} rounds.")
    r = proofsystem.myrand(proofsystem.E1, proofsystem.E2)
    success = 0
    for _ in range(ROUND):
        k = proofsystem.myrand(proofsystem.E2, proofsystem.E1)
        w = literal_eval(input(f"Prove for {r}, this is your mask: {k}, now give me your witness: "))
        assert len(w) == 4
        assert max(wi.bit_length() for wi in w) < 200
        print("pass the bit check")
        if proofsystem.verify(proofsystem.E1, r, k, w) and proofsystem.verify(proofsystem.E2, r, k, w):
            print(f"Good!")
            success += 1
        r += 1


    if success > threshold:
        print("You are master of math!")
        print(flag)


if __name__ == "__main__":
    try:
        task()
    except Exception:
        exit()
```

干了这样的事情：声明两条曲线


$$
E_1: y^2 \equiv x^3+137 \pmod {p_1} \\
E_2: y^2 \equiv x^3+137 \pmod {p_2}
$$
F 是 E1 的阶，r 是随机数，$P = rG_2$，x 是 P 的横坐标，myrand 返回 r\*x 的低 128 位

verify：G 是传入的 E 的生成元，记 n 为 G 的阶
$$
P = (rk)G \\
Q = [(w_0^3+w_1^3+w_2^3+w_3^3) \cdot ((k^2)^{-1} \pmod n)]\cdot G
$$
verify 验证 P 和 Q 的横坐标是否相同

任务是：

传入两个256 bit 的素数 p1 和 p2，需要在1000轮内 verify 成功999轮。r 和 k 都是已知的，p 是可控的，故 n 也是已知的，那么实际上是要找这样的4个小于200 bit 的 w
$$
(w_0^3+w_1^3+w_2^3+w_3^3) \cdot ((k^2)^{-1} \pmod n) \equiv rk \pmod n \\
(w_0^3+w_1^3+w_2^3+w_3^3) \equiv rk^3 \pmod n
$$

>由于 myrand 内部实现：`return int(r * x) & (2**128 - 1)`，会进行 r \* x 的操作，而 r 是 Zmod(E1.order()) 中的元素， x 是 Zmod(p2) 中的元素，为了不报错，需有 E1.order() == p2，进一步地发现，也得有 E2.order() == p1
>
>而且每轮传入的 w 都要通过两个 verify，故传入两个相同的 p 可以简化这一问题，此外就是要求 E.order() 和 p 相等了

故需要两步解决这个题目：找到合适的 p；之后解决四立方和问题

利用一些椭圆曲线的理论：$\#E(\mathbb F_p)=p+1-t$，故需要 t = 1

此外对于 $y^2=x^3+137$ 这种 j=0 曲线，CM 理论给出迹的关系
$$
4p=t^2+3v^2 = 1+3v^2 \\
p = (1+3v^2)/4
$$
然后就可以写一个朴素的搜索代码

```python
v = 2**128 + 1
while True:
    p = (1 + 3*v*v) // 4
    if p.nbits() == 256 and is_prime(p):
        E = EllipticCurve(Zmod(p), [0, 137])
        if E.order() == p:
            break
    v += 2
# 86844066927987146567678238756515930901692230158002800019079611962330850525581
```

v 的搜索步长为 2 的好处是：加 1 会得到偶数，而对于偶数的 v，`p = (1 + 3*v*v) // 4` 得到的一定是合数(向下取整)，是无意义的；实际操作也能很快出结果

下面求解四立方和问题
$$
(w_0^3+w_1^3+w_2^3+w_3^3) \equiv rk^3 \pmod p\\
(w_0^3+w_1^3+w_2^3+w_3^3) = rk^3 + tp
$$
对于这个问题，常见的做法是这样构造：
$$
w=(a+b, a-b, -a+c, -a-c)
$$
四立方和变为乘积的形式
$$
(a+b)^3+(a-b)^3+(-a+c)^3+(-a-c)^3 =6a(b^2-c^2)=6a(b+c)(b-c)
$$
进一步人为限制 $b - c=1$，然后记 $b+c=d$，得到一个不错的形式
$$
\sum w_i^3=6ad
$$
那么找4个 w 就变为 找 a 和 d，最后可以得到 $(a+\frac{d+1}{2},a-\frac{d+1}{2},-a+\frac{d-1}{2},-a-\frac{d-1}{2})$，故需要 d 是奇数
$$
6ad \equiv rk^3 \pmod p \\
ad \equiv 6^{-1}\cdot rk^3 \pmod p \\
$$
记 $h = 6^{-1}\cdot rk^3 \pmod p$，则 $ad = h+tp$

剩下的思路也很直接，t 自然从0开始尝试，把等号右边的数分解成两个数的乘积，不需要完全分解，也不要求 d 是素数；此外，为了满足 w 的大小限制，需要 $a,d<2^{198}$，此时
$$
w_i \leq a+\frac{d+1}{2} < 2^{198} + 2^{197}<2^{199}
$$
故 bit_length() 小于200

可以写一个简单的分解，思路如下：构造一系列 N 的候选值 $N_0=h, N_0+p,N_0+2p,...$

1. 初始化 a=1, d=N

2. 枚举小素数 q=2,3,5,7,11...，枚举到 $2^{16}$

3. 每当 $q\mid d$，就执行 $d\leftarrow d/q,\ a\leftarrow aq$，直到这个 q 无法整除

4. 检查 $a,d<2^{198}$，满足就成功；若试完这些小素数还不满足，就换下一个 N

这个题的参数限制，h 大概在256bit，故只需要分出 58 bit 左右的因子给到 a 即可满足；实际操作后发现这个朴素的算法速度大概平均一次 2s 左右，故完整跑完1000次至少也得半个小时，(不知道原始环境有没有卡时间，否则的话还需要一些优化...)

```python
primes = [int(q) for q in prime_range(2, 2**16)]
limit = 2**198

def solve(h, p):
    h, p = int(h), int(p)
    N = h 
    while True:
        a, d = 1, N
        for q in primes:
            while d % q == 0:
                d //= q
                a *= q

            if d < limit and a < limit:
                b = (d + 1) // 2
                c = (d - 1) // 2
                return [a + b, a - b, -a + c, -a - c]
        N += p
```

参考：

[ZKpuzzle::0CTF 2025](https://rechn0.github.io/2025/12/22/2025-0ctf/#ZKpuzzle1)

