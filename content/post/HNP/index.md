+++
title = "格密码-HNP"
date = "2026-07-10"
categories = ["密码学习"]

+++

# HNP

**前言**

本文记录hnp有关内容以及一些例题，前面的内容和代码主要参考了 [| 独奏の小屋](https://hasegawaazusa.github.io/hidden-number-problem.html)

以及一些收录的例题，后续慢慢补充中

## 基本概念

HNP 即 the Hidden Number Problem，隐藏数问题，种类比较多，主要参考 [| 独奏の小屋](https://hasegawaazusa.github.io/hidden-number-problem.html) 的分类进行整理

### LHNP(线性隐藏数问题)

给出了如下的方程组，e较小，目标是恢复出x
$$
\left\{\begin{array}{l}
c_{0}=r_{0} \cdot x+e_{0} \\
c_{1}=r_{1} \cdot x+e_{1} \\
\ \ \  \ \  \ \vdots \\
c_{n-1}=r_{n-1} \cdot x+e_{n-1}
\end{array} \pmod p \right.
$$
先去掉模p，得到$e_i = c_i -r_i x +k_ip$，然后利用线性关系构造格
$$
(k_0,k_1,...,k_{n-1},x,1)
\left[\begin{array}{cccccc}
p & & & & & \\
& p & & & & \\
& & \ddots & & & \\
& & & p & & \\
-r_{0} & -r_{1} & \cdots & -r_{n-1} & K/p & \\
c_{0} & c_{1} & \cdots & c_{n-1} & & K
\end{array}\right] = 
(e_0,e_1,...,e_{n-1},Kx/p,K)
$$
这是一个(n+2)*(n+2)的格子，前(n+2)列就是利用方程组构造的，为了凑成方阵，又在后面添了两列，一方面要配平，另一方面也要让使得左边向量最后两个分量x和1出现在目标向量时，和e的数量级差不多大，更好规约

故K取为$e_i$的上界，考虑到x和p差不多大，故倒数第二列补充的是K/p

### ECHNP(椭圆曲线隐藏数问题)

#### 形式

一条给定的椭圆曲线(参数已知)，取两个点R和P，其中R已知，P未知，$O = P + tR$，t可以自己取，然后可以得知$int(O[0]) - e$这样的形式，e是一个较小的量，也就是O点横坐标的高位信息，目标是恢复P的横坐标

#### 推导

核心思想和步骤如下

记$h_t \equiv (P+tR)_x - e_t \equiv \left(\frac{y_{P}-y_{Q}}{x_{P}-x_{Q}}\right)^{2}-x_{P}-x_{Q}-e_{t} \pmod p$，其中$Q=tR$（是已知量），那么ht的值是我们已知的

特殊地，先考虑t=0的情况，则有$x_P = h_0+e_0$，然后因为我们想要的是P的横坐标，故把P的纵坐标给表示出来，有下面的式子$y_{P}=\frac{x_{P}^{3}+a x_{P}+b+y_{Q}^{2}-\left(h_{0}+e_{0}+x_{P}+x_{Q}\right)\left(x_{P}-x_{Q}\right)^2}{2 y_{Q}}$(这一步即两边通分然后用曲线表达式化简），在这个式子里，右边只有e0和xp两个未知数

接下来考虑**共轭对**$P+Q$和$P-Q$，首先有这两个式子$x_Q = x_{-Q},y_Q = -y_{-Q}$，然后做的工作是计算$(P+Q)_x+(P-Q)_x$，其得到的结果(等号右边)只有xp这一个未知数，这里就不放了

然后$h_i =(P+Q)_x -e_i ,h_{-i} =(P-Q)_x -e_{-i}$，构造$\tilde{h}_i = h_i + h_{-i}, \quad \tilde{e}_i = e_i + e_{-i}$，具体地，即$(P+Q)_x+(P-Q)_x = h_i+e_i +h_{-i}+e_{-i} = \tilde{h}_i+\tilde{e}_i = g(x_P)$，右边的复杂表达式就用g抽象了，那么这个等式只有$\tilde{e}_i$和xp两个未知数，再代入$x_P = h_0+e_0$，那么就是一个关于$(\tilde{e}_i,e_0)$的方程，其形式如下

$F_i(X,Y)= X^{2}Y + A_{i}X^{2} + A_{0,i}XY + B_{i}X + B_{0,i}Y + C_{i}$，满足$F_i(e_0,\tilde{e}_i) \equiv 0 \pmod p$，$Q = iR$

当然，各个系数都有其表达式，这里也不放了，然后我们可以得到d组$(e_0,\tilde{e}_i)$方程，据此构造格
$$
\left(1,\ e_{0},\ \tilde{e}_{1},\ \cdots,\ \tilde{e}_{d},\ e_{0}^{2},\ e_{0}\tilde{e}_{1},\ \cdots,\ e_{0}\tilde{e}_{d},\ k_{1},\ \cdots,\ k_{d}\right)
\left[\begin{array}{cccc}
-C_{1} & -C_{2} & \cdots & -C_{d} \\
-B_{1} & -B_{2} & \cdots & -B_{d} \\
-B_{0,1} & 0 & \cdots & 0 \\
0 & -B_{0,2} & \cdots & 0 \\
\vdots & \vdots & \ddots & \vdots \\
0 & 0 & \cdots & -B_{0,d} \\
-A_{1} & -A_{2} & \cdots & -A_{d} \\
-A_{0,1} & 0 & \cdots & 0 \\
0 & -A_{0,2} & \cdots & 0 \\
\vdots & \vdots & \ddots & \vdots \\
0 & 0 & \cdots & -A_{0,d} \\
p &  &  &  \\
 & p &  &  \\
 &  &  &  \\
 &  & \ddots &  \\
 &  &  & p
\end{array}\right] =
\left( e_0^2 \tilde{e}_1,\ \cdots,\ e_0^2 \tilde{e}_d \right)
$$
这是一个(3d+3)*d的格，同样地，为了将其凑成一个方阵，我们将其变成下面的形式，P是d阶单位阵\*p，R是上面的系数矩阵，E的内容如下，k是e的比特位，是一个(2d+3)阶的对角阵(1+(d+1)+(d+1))，同样为了使目标向量各分量数量级相当，简单验证了一下，大小也没问题
$$
M = \begin{bmatrix}
E & R \\
0 & P
\end{bmatrix}
$$

$$
E = \begin{bmatrix}
2^{3k} & 0 & \cdots & 0 & 0 & \cdots & 0 \\
0 & 2^{2k} & \cdots & 0 & 0 & \cdots & 0 \\
\vdots & \vdots & \ddots & \vdots & \vdots & \ddots & \vdots \\
0 & 0 & \cdots & 2^{2k} & 0 & \cdots & 0 \\
0 & 0 & \cdots & 0 & 2^{k} & \cdots & 0 \\
\vdots & \vdots & \ddots & \vdots & \vdots & \ddots & \vdots \\
0 & 0 & \cdots & 0 & 0 & \cdots & 2^{k}
\end{bmatrix}
$$

M是一个(3d+3)*(3d+3)的格，最后的线性关系是
$$
\left(1,\ e_{0},\ \tilde{e}_{1},\ \cdots,\ \tilde{e}_{d},\ e_{0}^{2},\ e_{0}\tilde{e}_{1},\ \cdots,\ e_{0}\tilde{e}_{d},\ k_{1},\ \cdots,\ k_{d}\right)M = \\
\left(2^{3 k},\ e_{0} 2^{2k},\ \tilde{e}_{1} 2^{2k},\ \cdots,\ \tilde{e}_{d} 2^{2k},\ e_{0}^{2} 2^{k},\ e_{0}\tilde{e}_{1} 2^{k},\ \cdots,\ e_{0}\tilde{e}_{d} 2^{k},\ e_{0}^{2}\tilde{e}_{1},\ \cdots,\ e_{0}^{2}\tilde{e}_{d}\right)
$$

> 算了算前面的部分，后面看着计算量很庞大啊，没有算了，而且表示出来的$y_P$，也没有用上，算$\tilde{h}_i$的时候分子上的y项都是平方直接拿曲线表达式代换了，可能后面会用到？emm...

#### 代码

取自[| 独奏の小屋](https://hasegawaazusa.github.io/hidden-number-problem.html)

```python
p = p
a = a
b = b
E = EllipticCurve(GF(p), [a, b])
G = E((x, y))
hs = hs
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
    Ci.append(hs[i] * (hs[0] - xQ) ^ 2 - 2 * ((hs[0] ^ 2 +a) * xQ + (a + xQ ^ 2) * hs[0] + 2 * b))
R = block_matrix(ZZ, [-matrix(Ci), -matrix(Bi), -diagonal_matrix(B0i), -matrix(Ai), -diagonal_matrix(A0i)], ncols=1)
P = diagonal_matrix(ZZ, [p] * d)
E = block_diagonal_matrix([matrix([8^k]), diagonal_matrix([4^k] * (d + 1)), diagonal_matrix([2^k] * (d + 1))])
M = block_matrix([[E, R], [0, P]])
shortest_vector = M.LLL()[0]
es = shortest_vector[1:d+1] / 4 ^ k
if es[0] < 0:
    es[0] = -es[0]
xP = ZZ(hs[0] + es[0])
print(xP)
```

### LLBP(线性位泄露问题)

#### 形式

形如
$$
a_i x \equiv b_i \pmod N
$$
方程组，已知 ai, N。bi 的部分位已知，需要求出 x

#### MSB

**注：下面分析的是有 n+1 组数据**

最高位泄露的情况

记 N 的位数为 $\eta$，bi 泄露的最高位位数为 $\rho$，故 bi 可表示为
$$
b_i = h_i + s_i
$$
hi 是已知的高位，si 是未知的低位，进一步有
$$
x \equiv a_i^{-1}(h_i+s_i) \pmod N
$$
取两个方程可得
$$
a_0^{-1}(h_0+s_0) \equiv a_i^{-1}(h_i+s_i) \pmod N \\
s_i \equiv a_ia_0^{-1}s_0+a_ia_0^{-1}h_0 - h_i \pmod N
$$
令 $A_i = a_ia_0^{-1}$, $B_i= a_ia_0^{-1}h_0 -h_i$, 则 $s_i \equiv A_i s_0 + B_i \pmod N$

可以构造出格如下，这是一个 (n+2)*(n+2) 的格，K 取 $2^{\eta-\rho}$
$$
(k_1, \cdots, k_n, s_0, 1) \begin{bmatrix}
N & & & \\
& \ddots & & \\
& & N & \\
A_1 & \cdots & A_n & 1 \\
B_1 & \cdots & B_n & &K
\end{bmatrix} = (s_1, \cdots, s_n, s_0, K)
$$

#### LSB

最低位泄露的情况

记 N 的位数为 $\eta$，bi 泄露的最低位位数为 $\rho$，故 bi 可表示为
$$
b_i = 2^{\rho}s_i + l_i
$$
li 是已知的低位，si 是未知的低位，进一步有
$$
x \equiv a_i^{-1}(2^{\rho}s_i + l_i) \pmod N
$$
取两个方程可得
$$
a_0^{-1}(2^{\rho}s_0 + l_0) \equiv a_i^{-1}(2^{\rho}s_i + l_i) \pmod N \\
2^{\rho}s_i \equiv a_ia_0^{-1}2^{\rho}s_0+a_ia_0^{-1}l_0 - l_i \pmod N
$$
令 $A_i = a_ia_0^{-1}$, $B_i= \frac{a_ia_0^{-1}l_0 -l_i}{2^{\rho}}$, 则 $s_i \equiv A_i s_0 + B_i \pmod N$

可以构造出格如下，这是一个 (n+2)*(n+2) 的格，K 取 $2^{\eta-\rho}$
$$
(k_1, \cdots, k_n, s_0, 1) \begin{bmatrix}
N & & & \\
& \ddots & & \\
& & N & \\
A_1 & \cdots & A_n & 1 \\
B_1 & \cdots & B_n & &K
\end{bmatrix} = (s_1, \cdots, s_n, s_0, K)
$$
可以看出基本上一样

## 例题

### [DesCTF 2026] Low Bits, High Risk

```python
from hashlib import *
from secrets import randbelow
from ecdsa import SigningKey, SECP160r1, util

leak = 3
total = 61
mask = (1 << leak) - 1

def main():
    sk = SigningKey.generate(curve=SECP160r1)
    vk = sk.verifying_key
    q = SECP160r1.order
    print(hex(vk.pubkey.point.x()))
    print(hex(vk.pubkey.point.y()))
    d = sk.privkey.secret_multiplier
    flag = "DesCTF{" + md5(str(d).encode()).hexdigest() + "}"
    for i in range(total):
        msg = f"msg-{i}".encode()
        digest = sha1(msg).digest()
        h = int.from_bytes(digest, "big") % q
        k = randbelow(q - 1) + 1
        sig = sk.sign_digest(digest, sigencode=util.sigencode_string, k=k)
        r, s = util.sigdecode_string(sig, q)
        print(f"({hex(h)}, {hex(int(r))}, {hex(int(s))}, {hex(k & mask)}),")

if __name__ == "__main__":
    main()

'''
0x8e0a0071e8cf437efec4233ff8444a4ff8adba2f
0xa869fce702b70799c443b450a4d41cc4f65b3eee
(0x525931a9ff8ef95025939a57275ecedc2730421f, 0x5288ed7146c188ebda9b6c8909726c3d6f957891, 0x334c301c2d861fa8cceecabc542a5cb7dd7df7d9, 0x6),
(0x4b21047e1112dbfee487b4f23471f2fb438e268, 0x82878368ef18996109bf10adae81e1acaeb9fa25, 0xd4d9ec1faa9534a3fa4ff0fe78488ebf175cdfec, 0x4),
(0xdd2e98102508e178fdf1e289ac8342250da6408f, 0x38069b3213a57a077a38938d082a7590d0a21b95, 0xcff1f76af8f15422bb288c8af372332cc6ace970, 0x1),
... 略
'''
```

背景是 ECDSA，核心等式依旧是
$$
s \equiv k^{-1}(H(m)+rd_A) \pmod n
$$
目标是把私钥 d 求出来，给了61组消息及对应的签名，即 (h(m), r, s)

此外重要的额外信息是 `k & mask`，也就是泄露了每次用的 k 的低3位的信息

通过这个题，仔细看后发现了 LHNP 和 LLBP 构造格的思想是不一样的

[1] 一开始的做法，构造的相当于是 LHNP 的格，就是利用线性方程的思想去构造

设 $k =k_l +2^3 k_h$，对签名公式变形一下然后代入
$$
sk = sk_l+8sk_h = H +rd_A \pmod n \\
k_l+8k_h \equiv s^{-1}H+s^{-1}rd_A \pmod n \\
k_h = 8^{-1}s^{-1}H - 8^{-1}k_l +8^{-1}s^{-1}rd_A +t_i n
$$
构造如下的格，其中 $A_i =8^{-1}s_i^{-1}r_i, \  B_i = 8^{-1}s_i^{-1}H-8^{-1}k_{li}, \ K = 2^{156}$
$$
(t_0,...,t_{60},d_A,1) \begin{pmatrix}
n & & & \\
& \ddots & & \\
& & n & \\
A_0 & \cdots & A_{60} & 1/8 \\
B_0 & \cdots & B_{60} & &K
\end{pmatrix} = (k_{h0},...,k_{h60},d_A/8,K)
$$

> 这里声明的是 QQ 上的矩阵，然后规约；发现 QQ 上的矩阵只能用 LLL，不能用 BKZ

但是用 LLL 又出不来，故需要做一些调整

$k_{hi}$ 的范围大概是 $(0, n/8)$，则目标向量中的每个分量也大致落在这个范围内，对其做一个中心化 (中心处理为0)，即 $-n \le 16k_{hi}-n \le n$

原始等式 $k_{hi} = A_id +B_i +t_i n $，则变形为 $16k_{hi}-n = 16A_id +(16B_i -n)+16t_i n $

与此同时，K 调整为 n，d 也不再除8，就取 d，这样格矩阵内也没有分数了
$$
(t_0,...,t_{60},d_A,1) \begin{pmatrix}
16n & & & \\
& \ddots & & \\
& & 16n & \\
16A_0 & \cdots & 16A_{60} & 1 \\
16B_0-n & \cdots & 16B_{60}-n & &n
\end{pmatrix} = (16k_{h0}-n,...,16k_{h60}-n,d_A,n)
$$

```python
q = SECP160r1.order
n = q
data = [...]

a = []
b = []
for h, r, s, l in data:
    invs = pow(s, -1, n)
    inv8 = pow(8, -1, n)
    tmpa = (invs * inv8 * r) % n 
    tmpb = (invs * inv8 * h - inv8 * l) % n 
    a.append(tmpa)
    b.append(tmpb)

L = matrix(ZZ, 63, 63)
for i in range(61):
    L[i, i] = 16 * n
    L[-2, i] = 16 * int(a[i])
    L[-1, i] = 16 * int(b[i]) - n
L[-2, -2] = 1
L[-1, -1] = n
K = n

# block_size 调至36可以找到正确解
for ans in L.BKZ(block_size=36):
    if abs(ans[-1]) == K:
        d = ans[-2]
        print(d)
```

> 突然发现在 sage 里写 pow(a, -1, p) 返回的值的类型是模意义下的整数，不是普通整数，故需要 int() 转换一下；奇怪了，以前怎么没遇到过这种问题

[2] 再回看了一下 LLBP 的格，发现不一样，本质上是利用第一个等式和第 i 个等式这种两个式子的形式去构造
$$
sk \equiv h+rd_A \pmod n
$$
变形成 $ax \equiv b \pmod n$ 的形式，如下，多了一个常数项
$$
rs^{-1}d_A \equiv k -s^{-1}h \pmod n \\
d_A \equiv r^{-1}s(k -s^{-1}h) \equiv r^{-1}sk-r^{-1}h \pmod n
$$
类似地，联立可得
$$
r_0^{-1}s_0k_0-r_0^{-1}h_0 \equiv r_i^{-1}s_ik_i-r_i^{-1}h_i \pmod n
$$
把 k 展开，代入
$$
r_0^{-1}s_0(k_{l0} +2^3 k_{h0})-r_0^{-1}h_0 \equiv r_i^{-1}s_i(k_{li} +2^3 k_{hi})-r_i^{-1}h_i \pmod n
$$
往标准形式上变形
$$
(k_{li} +2^3 k_{hi})-s_i^{-1}h_i \equiv r_is_i^{-1}r_0^{-1}s_0(k_{l0} +2^3 k_{h0})-r_is_i^{-1}r_0^{-1}h_0 \pmod n \\
2^3 k_{hi} \equiv r_is_i^{-1}r_0^{-1}s_0(k_{l0} +2^3 k_{h0})-r_is_i^{-1}r_0^{-1}h_0 +s_i^{-1}h_i - k_{li}\pmod n \\
2^3 k_{hi} \equiv r_is_i^{-1}r_0^{-1}s_02^3 k_{h0}+r_is_i^{-1}r_0^{-1}s_0k_{l0}-r_is_i^{-1}r_0^{-1}h_0 +s_i^{-1}h_i - k_{li}\pmod n
$$
两边同乘 $8^{-1}$ 后，令 $A_i = r_is_i^{-1}r_0^{-1}s_0 $，右边剩余的为 $B_i$

则构造出了 $k_{hi}\equiv A_ik_{h0}+B_i \pmod n$ 的形式，构造和模板一样的格
$$
(t_1, \cdots, t_n, k_{h0}, 1) \begin{pmatrix}
N & & & \\
& \ddots & & \\
& & N & \\
A_1 & \cdots & A_n & 1 \\
B_1 & \cdots & B_n & &K
\end{pmatrix} = (k_{h1}, \cdots, k_{hn}, k_{h0}, K)
$$
一样地，直接用不行，中心化一下 $k_{hi} = A_ik_{h0}+B_i +t_in$ 变为 $16k_{hi}-n = 16A_ik_{h0} +(16B_i -n)+16t_i n $

```python
q = SECP160r1.order
n = q
data = [...]

a = []
b = []
h0, r0, s0, l0 = (0x525931a9ff8ef95025939a57275ecedc2730421f, 0x5288ed7146c188ebda9b6c8909726c3d6f957891, 0x334c301c2d861fa8cceecabc542a5cb7dd7df7d9, 0x6)
invr0 = pow(r0, -1, n)
inv8 = pow(8, -1, n)

for h, r, s, l in data:
    invr = pow(r, -1, n)
    invs = pow(s, -1, n)
    tmpa = (r * invs * invr0 * s0) % n 
    tmpb = (r * invs * invr0 * s0 * l0 - r * invs * invr0 * h0 + invs * h - l) % n 
    tmpb = (tmpb * inv8) % n
    a.append(tmpa)
    b.append(tmpb)

L = matrix(ZZ, 62, 62)
for i in range(60):
    L[i, i] = 16 * n
    L[-2, i] = 16 * int(a[i + 1])
    L[-1, i] = 16 * int(b[i + 1]) - n
L[-2, -2] = 1
K = n
L[-1, -1] = n

# block_size=36 同样可以找到正确解
for ans in L.BKZ(block_size=36):
    if abs(ans[-1]) == K:
        if ans[-1] == K:
            kh0 = ans[-2]
        if ans[-1] == -K:
            kh0 = -ans[-2]
        k0 = kh0 * 8 + l0
        d = (s0 * k0 - h0) * pow(r0, -1, n) % n
        print(d)
```

最后，两种构造都可以解决这个题。观察他们的形式

- $k_{hi} \equiv A_id +B_i \pmod n$
- $k_{hi}\equiv A_ik_{h0}+B_i \pmod n$

本质上好像又都是一样的，第二种用未知量 $k_{h0}$ 代替了 d。这么来看的话第一种利用了61组数据，第二种利用了60组数据，或许可以这样粗略地理解

总之，这个题只泄露了3bit，构造的格的行列式大小和目标向量的大小关系有点极限，得不断增大 BKZ 的 block_size 才能整出来

### [未知] truncated lcg

三个参数均已知的情况下的截断 LCG 求解，下面讨论高位已知的情况

题目取自 [参考链接2] 先上代码

```python
from Crypto.Util.number import *

flag = b'Spirit{*****************}'
plaintext = bytes_to_long(flag)
length = plaintext.bit_length()

a = getPrime(length)
b = getPrime(length)
n = getPrime(length)
seed = plaintext
output = []
for i in range(10):
    seed = (seed*a+b)%n
    output.append(seed>>64)
    
print("a = ",a)
print("b = ",b)
print("n = ",n)
print("output = ",output)
```

万物起源
$$
s_{i+1} \equiv as_i + b \pmod n
$$
改写成高低位的形式 (对应代码，h 代表 output 左移64位之后的结果)
$$
h_{i+1} + l_{i+1} \equiv a(h_{i} + l_{i}) + b \pmod n
$$
简单移项
$$
l_{i+1}\equiv al_i + ah_i + b -h_{i+1} \pmod n
$$
已知部分记为 $t_i \equiv ah_i + b -h_{i+1} \pmod n$，则现在的形式为
$$
l_{i+1} \equiv al_i + t_i \pmod n
$$

> HNP 的目标形式是
> 
> $r_i = A_i u + B_i \pmod n$
> 
> 其中，$A_i$ 和 $B_i$ 均已知，n 也已知，u 未知但是定值，$r_i$ 也未知

现在很接近了，但是 $l_i$ 不是定值，故还需进一步变形，考虑都往 $l_0$ 上统一，写几项观察一下
$$
l_1 \equiv al_0+ t_0 \pmod n \\
l_2 \equiv al_1+ t_1 \equiv a^2l_0+ at_0+t_1 \pmod n\\
l_3 \equiv al_2+ t_2 \equiv a^3l_0+ a^2t_0+at_1+t_2 \pmod n\\
$$
故 $l_{i} \equiv A_il_0 + B_i \pmod n \ \ (i \ge 1)$，(i=0 没意义)，其中
$$
A_i \equiv a^i \pmod n \\
B_i \equiv aB_{i-1}+t_{i-1} \pmod n \ \ (i\ge2) \\
B_1 = t_0
$$
OK，现在就可构造标准的 HNP 格了
$$
(k_1,k_2,...,k_v,l_0,1) \begin{pmatrix}
n & &  & & &    \\
 & n & & & &     \\
& & \ddots & & &\\
& &  &n & &\\
A_1&A_2 &\cdots & A_v & 1 & \\
B_1&B_2 &\cdots & B_v & & K
\end{pmatrix} = (l_1,l_2,...,l_v,l_0,K)
$$
exp，K 取1即可

```python
from Crypto.Util.number import long_to_bytes

a =  731111971045863129770849213414583830513204814328949766909151
b =  456671883153709362919394459405008275757410555181682705944711
n =  666147691257100304060287710111266554526660232037647662561651
output = [16985619148410545083429542035273917746612, 32633736473029292963326093326932585135645, 20531875000321097472853248514822638673918, 37524613187648387324374487657224279011, 21531154020699900519763323600774720747179, 1785016578450326289280053428455439687732, 15859114177482712954359285501450873939895, 10077571899928395052806024133320973530689, 30199391683019296398254401666338410561714, 21303634014034358798100587236618579995634]
h = [i * pow(2, 64) for i in output]
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

tmp = L.LLL()[0][-2] + h[0]
seed = (tmp - b) * pow(a, -1, n) % n
print(long_to_bytes(seed))
# b'Spirit{King__of__LCG_qWq}'
```

## 参考 

1. [| 独奏の小屋](https://hasegawaazusa.github.io/hidden-number-problem.html)
1. [crypto之线性同余生成器（lcg)-先知社区](https://xz.aliyun.com/news/15672)