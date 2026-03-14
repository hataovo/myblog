+++
title = "格密码-LWE"
date = "2026-03-14"
categories = ["密码学习"]

+++

# LWE

**前言**

本文记录lwe有关内容以及一些例题，前面的内容和代码主要参考了鸡块师傅的 [博客](https://tangcuxiaojikuai.xyz/post/758dd33a.html)



## 基本概念

### 形式

lwe往简单里说的话其实就是一个式子
$$
As+e \equiv b \pmod q
$$
其中，A是m*n的矩阵，s是n维向量，e是m维向量(误差向量)，b是m维向量

A和b是公钥，s是私钥，e是满足一定分布规律的误差向量(如高斯分布，也就是正态分布)，e通常较小且未知

### 困难问题
目前见过的有 搜索LWE(Search-LWE) 和 决策LWE(Decision-LWE) 两种

Search-LWE(SLWE)：给出样本的A、b，找出样本私钥s

Decision-LWE(DLWE)：给出当前样本的A、b，区分当前样本是LWE样本还是随机数

### 其他

矩阵A的形状m\*n，要求 m>=n，一般情况下都是 **m>n**，显然如果 m<n，则是欠定方程组，解不唯一

当 m<n 时，可以采用拼接的方法，即将两组样本纵向堆叠
$$
\begin{aligned}
A_1 s + e_1 &= b_1 \pmod{q} \\
A_2 s + e_2 &= b_2 \pmod{q}
\end{aligned}
$$

即可以看作是一组 $2m \times n$ 的样本
$$
\left( \frac{A_1}{A_2} \right) s + \left( \frac{e_1}{e_2} \right) = \left( \frac{b_1}{b_2} \right) \pmod{q}
$$

## 格攻击

一种比较直白的想法是求解CVP问题

若不考虑模q，即$As+e=b$，$As=b-e$，两边转置一下，b-e应当是格中向量，不过其未知，由于e比较小，故其和已知的b向量应是相近的向量，故可用babai算法去找与b向量最近的向量，认为其是b-e，恢复e进而可求s

但事实上，由于模q不可能忽略，$As=b-e+kq$，未必再与b向量邻近，效果不好

### primal attack

而且看了一些资料后，大家也似乎很少用CVP去做，都是转成SVP问题求解，而对于格的构造，我们可以利用 $As -b-kq=-e$ 构造出一个比较典型的格，以及其对应的线性关系
$$
(s_0, s_1,...,s_{n-1},1,-k_0,-k_1,...,-k_{m-1} )
\begin{pmatrix}
I_n   & A^\mathsf{T} \\
  & \mathbf{-b} \\
   & qI_{m}
\end{pmatrix} =
(s_0, s_1,...,s_{n-1},-e_0, -e_1, ...,-e_{m-1})
$$
上面的是一个(m+n+1)\*(m+n)的长方阵，我们可以在其中间加一列，变成一个(m+n+1)阶的方阵(对角线元素也更好一点)，至于线性关系，就是右边的目标向量中间也多了一个1
$$
\begin{pmatrix}
I_n &  & A^\mathsf{T} \\
 & 1 & -\mathbf{b} \\
 &  & qI_{m}
\end{pmatrix}
$$
此外，鸡块师傅博客中提到把这个分块矩阵最下面一横块移到最上面规约更快，我没有验证过

### primal attack 优化

上面的格子比较好想，但是有两个问题，一个是矩阵规模大，规约慢，另一个则是目标向量中的s分量不是小量，其出现在目标向量中不利于规约，那么我们的目标就把目标向量中的s去掉，只留下e分量

同样先做一个转置$s^TA^T+e^T \equiv b^T \pmod q$，$A^T$是一个n\*m(n<m)的矩阵，可以用初等行变换将其变成一个简化行阶梯形矩阵(RREF)，并且由于A中的元素是随机选的，其大概率上一定满足两个条件：秩为n以及前n个列向量线性无关，也就是说$A^T$可以变换成$K = [I_n,A'_{n\cdot (m-n)}]$这样的形式，而这一过程可表示为$PA^T = K$，P是一个可逆矩阵， 那么可以做以下变形$s^TA^T = s^T(P^{-1}P)A^T =  (s^TP^{-1})PA^T$，记$s' =s^TP^{-1}$，这时有$s'K-b^T \equiv -e^T \pmod q$，那么就和上面的构造一样了
$$
(s_0', s_1',...,s_{n-1}',1,-k_0,-k_1,...,-k_{m-1})
\begin{pmatrix}
K \\
 -\mathbf{b} \\
qI_{m}
\end{pmatrix} = 
(-e_0, -e_1, ...,-e_{m-1})
$$
发现这个格是一个(m+n+1)\*(m)的，不是一个方阵，还可以再处理

注意到格的最左上角(K中的左边矩阵)是单位阵，而s’向量是模q下的，他与单位阵计算乘积得到的每个值肯定也都小于q，不需要再去减去kq，故格中的$qI_m$可以变成$qI_{m-n}$(其他地方补充0调整)，并且调整一下顺序，此时的格变成下面的样子，是一个(m+1)\*(m+1)的方阵，(最后面添了一列，右下角的1在对角线上)

$$
\begin{pmatrix}
1 & & & & a_{1,1}^{\prime} & a_{2,1}^{\prime} & \cdots & a_{m-n,1}^{\prime} \\
& \ddots & & & \vdots & \vdots & & \vdots \\
& & 1 & & a_{1,n}^{\prime} & a_{2,n}^{\prime} & \cdots & a_{m-n,n}^{\prime} \\
& & &  & p & & & \\
& & & &  & p& & \\
& & & & &  &\ddots & \\
& & & & & & &p  \\
-b_{0}& & \cdots& & & \cdots& & -b_{m-1} & 1
\end{pmatrix}
$$

线性关系如下

$$
(s_0', s_1',...,s_{n-1}',-k_{n},...,-k_{m-1},1)L =(-e_0, -e_1, ...,-e_{m-1},1)
$$

---


附上上面两个版本的代码，同样取自鸡块师傅的博客

```python
# 误差e取自高斯分布，esz为其标准差
# primal_attack1
def primal_attack1(A,b,m,n,p,esz):
    L = block_matrix(
        [
            [matrix.identity(m)*p,matrix.zero(m, n+1)],
            [(matrix(A).T).stack(-vector(b)).change_ring(ZZ),matrix.identity(n+1)],
        ]
    )
    #print(L.dimensions())
    Q = diagonal_matrix([p//esz]*m + [1]*n + [p]) 
    L *= Q
    L = L.LLL()
    L /= Q
    for res in L:
        if(res[-1] == 1):
            s = vector(GF(p), res[-n-1:-1])
            return s
        elif(res[-1] == -1):
            s = -vector(GF(p), res[-n-1:-1])
            return s


# primal_attack2
def primal_attack2(A,b,m,n,p,esz):
    L = block_matrix(
        [
            [matrix(Zmod(p), A).T.echelon_form().change_ring(ZZ), 0],
            [matrix.zero(m - n, n).augment(matrix.identity(m - n) * p), 0],
            [matrix(ZZ, b), 1],
        ]
    )
    #print(L.dimensions())
    Q = diagonal_matrix([1]*m + [esz])
    L *= Q
    L = L.LLL()
    L /= Q
    res = L[0]
    if(res[-1] == 1):
        e = vector(GF(p), res[:m])
    elif(res[-1] == -1):
        e = -vector(GF(p), res[:m])
    s = matrix(Zmod(p), A).solve_right((vector(Zmod(p), b)-e))
    return s
```

## 例题

### [HGAME 2026] Decision

DLWE 模板题 [HGAME 2026](https://hataovo.github.io/p/hgame-2026/#decision)

### [N1CTF Junior 2026 1/2] LargeErrors

```python
from Crypto.Util.number import *
from sage.all import *
from random import choices
from secret import flag
assert len(flag) == 23
m = 23
n = 28
p = getPrime(64)
q = getPrime(64)
N = p * q
S = vector(Zmod(N), list(flag))
e = vector(Zmod(N), choices([p, q], k=n))
B = []
A = random_matrix(Zmod(N), n, m)
M = random_matrix(ZZ, n, n)
C = random_matrix(Zmod(N), n, m)
for _ in range(3):
    A = M*A+C
    b = A*S + e
    B.append(b)
save((A,B,M), "output")
```

m 和 n 和惯例不太一样，反着来的。对矩阵 A 做了混淆(感觉没用)，依次得到了3个 b 向量，不过只关注最后一组即可。这题的特点是 s 是一个小向量，e 的分量为 p 或 q

用 primal attack 优化版本时会因为 n 是合数 echelon_form() 报错，而且 s 本身很小，故可以用 primal attack 原始版，而且数据规模不大，直接出了

```python
A, B, M = load("output.sobj")
n = 179427755448118581754304040408782324521
p = 12397066081240970369
q = 14473404777572784809

def primal_attack1(A,b,m,n,p,esz):
    L = block_matrix(
        [
            [matrix.identity(m)*p,matrix.zero(m, n+1)],
            [(matrix(A).T).stack(-vector(b)).change_ring(ZZ),matrix.identity(n+1)],
        ]
    )
    # 配平矩阵 Q 改动了一下，原来是要把目标向量都往模数 q 的数量级上靠，这里是往误差 e 的数量级上靠
    Q = diagonal_matrix([1]*m + [esz]*n + [p])
    L *= Q
    L = L.LLL()
    L /= Q
    for res in L:
        if(res[-1] == 1):
            s = vector(res)
            return s
        elif(res[-1] == -1):
            s = -vector(res)
            return s

s = primal_attack1(A, B[-1], 28, 23, n, 2**64) # esz 设置成误差的数量级即可
```

规约结果如下，后面那部分拼起来就是 flag: `flag{1W3_W@$_v3rY_34sy}`

```text
(-14473404777572784809, -14473404777572784809, -12397066081240970369, -12397066081240970369, -14473404777572784809, -14473404777572784809, -14473404777572784809, -14473404777572784809, 
-14473404777572784809, -14473404777572784809, -12397066081240970369,-14473404777572784809, -14473404777572784809, -12397066081240970369, -12397066081240970369, -12397066081240970369, 
-14473404777572784809, -14473404777572784809, -12397066081240970369, -14473404777572784809, -12397066081240970369, -12397066081240970369, -12397066081240970369, -12397066081240970369, 
-14473404777572784809, -14473404777572784809, -14473404777572784809, -12397066081240970369, 102, 108, 97, 103, 123, 49, 87, 51, 95, 87, 64, 36, 95, 118, 51, 114, 89, 95, 51, 52, 115, 121, 125, 1)
```



## 参考

1. [LWE | 糖醋小鸡块的blog](https://tangcuxiaojikuai.xyz/post/758dd33a.html)