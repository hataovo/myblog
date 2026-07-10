+++
title = "[SekaiCTF 2026] orbital-strike"
date = "2026-07-10"
categories = ["wp"]
image="111.png"

+++

# [SekaiCTF 2026] orbital-strike

Author: [Water](https://shuizhuimiaoman.github.io/#/)

Description:

An orbital strike is an attack directed at a planetary surface from a weapon system stationed in space (orbit).

> 轨道打击是指从部署在太空（轨道）中的武器系统向行星表面发起的攻击

由此题出发，补充一些知识，最后尝试理解该题目的解法

## 结式 (resultant)

结式是代数中用来判断两个多项式是否有公共根的一个量

设有两个**一元多项式** f(x), g(x)，它们的结式记作 Res(f, g)，核心性质是：Res(f, g) = 0 当且仅当 f 和 g 有公共根

更一般地，如果
$$
f(x) = a(x - \alpha_1)(x - \alpha_2) \cdots (x - \alpha_m) \\
g(x) = b(x - \beta_1)(x - \beta_2) \cdots (x - \beta_n)
$$
则记
$$
\text{Res}(f, g) = a^n b^m \prod_{i=1}^m \prod_{j=1}^n (\alpha_i - \beta_j)\\
$$
所以只要某个 $α_i = β_j$，乘积中就出现 0，结式也就为 0

**二元/多元情况**：最常见的用途是消元，如果有两个方程 f(x, y) = 0 和 g(x, y) = 0

把它们看成关于 x 的多项式，则 Res_x(f, g) 会消去变量 x，得到只含 y 的式子

> 例如
>
> $f(x, y) = x + y$
>
> $g(x, y) = x^2 - y$
>
> $Res_x(x + y, x^2 - y) = y^2 - y$

此时 $Res_x(f, g) = 0$，表示存在某个 x，使得 f(x, y) = 0 且 g(x, y) = 0

注：二元/多元情况其实和一元情况本质上是一样的。无论有多少个变量，选取 f 和 g 中的一个变量作为主元，其他所有变量都视作常数，那么对 f 和 g 做结式就消去了这个主元，只不过得到的结果中实际上仍有其他变量

使用示例：

```python
p0 = 7
q0 = 13
N = p0 * q0
p_plus_q = p0 + q0

x, y = ZZ['x, y'].gens()
f = N - x * y
g = x + y - p_plus_q
print([f, g]) # [-x*y + 91, x + y - 20]
h = f.resultant(g, y)
print([h, factor(h)]) # [-x^2 + 20*x - 91, (-1) * (x - 13) * (x - 7)]
```

---

计算上，结式通常定义为 Sylvester 矩阵的行列式，设：(x 为主元，其他变量都视作常数)

$$
f(x) = a_m x^m + \cdots + a_0 \\ g(x) = b_n x^n + \cdots + b_0
$$
其中各系数 $a_i, b_j$ 都取自域 $\mathbb{F}$，且 $a_m b_n \neq 0$

则  
$$
\text{Res}(f, g) = \begin{vmatrix}
a_m & a_{m-1} & \cdots & a_0 & & \\
&\ddots&  &&\ddots&  \\
&&a_m&  a_{m-1}& \cdots & a_0 \\
b_n & b_{n-1} & \cdots & b_0 & & \\
&\ddots&  &&\ddots&  \\
&&b_n&b_{n-1}  & \cdots & b_0
\end{vmatrix}
$$
其中前 n 行都是 $a_i $，后 m 行都是 $b_j $；换言之，结式等于 Sylvester 矩阵的行列式

例如 m=n=2，那就是
$$
\begin{vmatrix}
a_2 & a_1 &a_0 & 0 \\
0 & a_2 & a_1 &a_0 \\
b_2 & b_1 & b_0 & 0\\
0 & b_2 & b_1 & b_0
\end{vmatrix}
$$

有时候 Sage 内置的 resultant 无法直接计算。这时可以计算 Sylvester 矩阵的行列式

```python
from sage.matrix.matrix2 import Matrix 

def resultant(f1, f2, var):
    return Matrix.determinant(f1.sylvester_matrix(f2, var))
```

---

简单记录一点原理

> 这部分可能不甚严谨，甚至有些问题，笔者并未深入研究学习...

Sylvester 矩阵实现了这个线性映射：

$(A,B)\longmapsto A(x)f(x)+B(x)g(x) $    $S\mathbf α = \mathbf β$

把 (A,B) 的系数排成一个向量，把 (Af+Bg) 的系数也排成一个向量，其中 deg(A)<n, deg(B)<m

之后，结式的定义就是 Sylvester 矩阵的行列式，Sylvester 矩阵形式如上，一般认为其行列式的值和这部分一开始的那个式子是一样的

然后可以得出结式的一个基本性质：存在多项式 $A(x),B(x)\in \mathbb Z[x]$，使得 $ A(x)f(x)+B(x)g(x)=\operatorname{Res}(f,g)$

设 $\deg f=m ,\deg g=n$，考虑所有形如 $A(x)f(x)+B(x)g(x)$ 的多项式，其中 deg(A)<n, deg(B)<m

写成
$$
A(x)=u_0+u_1x+\cdots+u_{n-1}x^{n-1}\\
 B(x)=v_0+v_1x+\cdots+v_{m-1}x^{m-1} \\
 Af+Bg = c_0+c_1x+\cdots +c_{m+n-1}x^{m+n-1}
$$
那么 $A(x)f(x)+B(x)g(x)$ 的次数小于等于 m+n-1，所以它有 m+n 个系数，由上可写出
$$
S \begin{pmatrix}
u_0\\
\vdots \\
u_{n-1} \\
v_0 \\
\vdots \\
v_{m-1}
\end{pmatrix} =  \begin{pmatrix}
c_0\\
c_1 \\
\vdots \\
c_{m+n-1}
\end{pmatrix}
$$
现在用伴随矩阵公式 $S\operatorname{adj}(S)=\det(S)I$

可得 $S\operatorname{adj}(S)=\operatorname{Res}(f,g)I$，进一步有：
$$
S\cdot \bigl(\operatorname{adj}(S)\text{ 的第一列}\bigr)
=\operatorname{Res}(f,g)
\begin{pmatrix}
1\\
0\\
\vdots \\
0
\end{pmatrix}
$$
此时把 adj(S) 的第一列当作 ui,vj 系数向量 α，得到的结果就是
$$
S\mathbf \alpha = \begin{pmatrix}
\operatorname{Res}(f,g)\\
0\\
0\\
\vdots \\
0
\end{pmatrix}
$$
右边这个向量代表的是零次多项式 Res(f, g) (常数)

换言之，找到了 u0,...,v0,... 使得 $ A(x)f(x)+B(x)g(x)=\operatorname{Res}(f,g)$

---

上面讨提到的都是整数上的多项式，下面介绍一个结论：

如果两个整数多项式在模 p 下有共同根，那么它们的 resultant 会被 p 整除

即：设 $f(x),g(x)\in \mathbb{Z}[x]$，如果存在某个 $a\in \mathbb{F}_p$ 使得 $f(a)\equiv 0 \pmod p\ \text{and} \ g(a)\equiv 0 \pmod p $

那么 $p\mid \operatorname{Res}(f,g)$，也就是说 $\operatorname{Res}(f,g)\equiv 0 \pmod p$

**简单证明**：由上知：存在多项式 $A(x),B(x)\in \mathbb Z[x]$，使得 $ A(x)f(x)+B(x)g(x)=\operatorname{Res}(f,g)$

代入 x=a，并且模 p 可得
$$
A(a)f(a)+B(a)g(a)\equiv \operatorname{Res}(f,g) \pmod p
$$
进而
$$
\operatorname{Res}(f,g) \equiv  0\pmod p
$$

## Gröbner 基

早期的时候经常会看到 Gröbner基 和 结式，但是分不清楚，故顺带学习一下

给一组多项式 $f_1, f_2, ..., f_s$，它们生成一个理想 $I = \langle f_1, f_2, ..., f_s\rangle$

Gröbner 基就是同一个理想 I 的另一组生成元 $G = \langle g_1, g_2, ..., g_t\rangle$，具有更好的性质

同样的，其可以用于求解方程组

一个简单的示例，取自 [参考链接2]：

```python
from Crypto.Util.number import *

p, q = getPrime(256), getPrime(256)
N = p * q
m1 = bytes_to_long(b"flag{12345678901234567890")
m2 = bytes_to_long(b"1234567890123456789012345")
m3 = bytes_to_long(b"6789012345678901234567890}")
e = 17
c1 = pow(m1, e, N)
c2 = pow(m2, e, N)
c3 = pow(m3, e, N)
s = m1 + m2 + m3
print(c1, c2, c3, s)
```

相当于给了四个式子
$$
x^{17} - c_1 = 0 \pmod n \\
y^{17} - c_2 = 0 \pmod n \\
z^{17} - c_3 = 0 \pmod n \\
x+y+z-s = 0 \pmod n
$$
使用 Gröbner 基可以方便地求解此方程组

```python
PR.<x, y, z> = PolynomialRing(Zmod(N))
F = [x^e - c1, y^e - c2, z^e - c3, x + y + z - s]
ideal = Ideal(F)
I = ideal.groebner_basis()
print(I)
```

输出是这样的，相当于已经给出了方程组的解

```
[x + 7832285201038728889673203618495806191666048217814099430080392419727684801164668651566065865955482611011945758945490948806579242177121949932113062087139615,
y + 7832285201038728889673203618495806191666048217814099430080392419727684801164668651566065865955816723984891498394975865395498844303963237973082573844096538,
z + 7832285201038728889673203618495806191666048217814099430080392419727684801164668651566065865869004259291738399089780207942786853960904670546825494315641298]
```

后续

```python
res = [-x.constant_coefficient() % N for x in I]
print(long_to_bytes(int(res[0])) + long_to_bytes(int(res[1])) + long_to_bytes(int(res[2])))
```

---

简单来说：结式通常处理两个多项式，消去一个变量

而 Gröbner 基更通用，可以处理多个多项式，多个变量

## 正交格

首先又需要提到矩阵的四个子空间，设 A 是 m\*n 的矩阵，r(A) = r

列空间：$b=Ax$ 即列向量的线性组合，秩为 r

行空间：$b=xA$ 即行向量的线性组合，秩为 r

零空间：$Ax=0$，秩为 n-r 

左零空间：$xA=0$，秩为 m-r

零空间的向量是列向量，又其秩为 n-r，故应当是一个 n*(n-r) 的矩阵

左零空间的向量是列向量，又其秩为 m-r，故应当是一个 (m-r)*m 的矩阵

---

正交性：

行空间的向量和零空间的向量正交

列空间的向量和左零空间的向量正交

简单证明一下：行空间的向量 x，形状 1\*n；零空间的向量 y，形状 n\*1

$x\cdot y = c\cdot A \cdot y = c\cdot (A \cdot y) = c\cdot \vec{0} = 0$

另一个类似

---

正交格怎么用，以 [参考链接4] 中的一个题为例，这里截取核心部分

```python
m = 8
n = 16
p = random_prime(2^512)
A = matrix(ZZ, m, n, [randint(-8, 8) for _ in range(m*n)])
alpha = vector(Zmod(p), [randint(0, p-1) for _ in range(m)])
B = alpha*A
key = md5(str(A.LLL()[0]).encode()).digest()
c = ... # AES key 加密 flag
# p, B, c 已知
```

这个题构造的等式
$$
B_{1\times 16} = a_{1\times 8}\cdot A_{8\times 16}
$$
只有 B 是已知的，A 是一个小矩阵，要把 A.LLL()[0] 恢复出来

若能找到矩阵 M 使得 $AM=0$，由最开始，M 应当是 n\*(n-r)，即 16\*8 (随机生成的 A 大概率满秩)
$$
BM = aAM = \vec{0}
$$
那大概思路就是：先求 M，然后求 M 的左零空间

**第一步**：求 M

可以用格来求 M，按照一般习惯，对行向量规约，故转置一下 $M^TB^T = \vec{0}$

上面虽然写的都是等号，但实际上都是在模 p 下进行的，故
$$
(m_0,m_1,...,m_{15},k)\begin{pmatrix}
I_{16\times 16}& B^T \\
0& p
\end{pmatrix} = (m_0,m_1,...,m_{15},0)
$$
对于 $M^T$ 的每一个行向量，都满足这个关系，故可在格内寻找目标向量，这里采用规约的方法找到

```python
B = Matrix(ZZ, 1, 16, B.list())
L = block_matrix([[identity_matrix(16), B.T], [matrix.zero(1, 16), p]])
MT = []
for i in L.LLL():
    if i[-1] == 0:
        MT.append(i[:-1])
MT = Matrix(ZZ, 8, 16, MT)
print(A * MT.T) # 验证
'''
[0 0 0 0 0 0 0 0]
[0 0 0 0 0 0 0 0]
[0 0 0 0 0 0 0 0]
[0 0 0 0 0 0 0 0]
[0 0 0 0 0 0 0 0]
[0 0 0 0 0 0 0 0]
[0 0 0 0 0 0 0 0]
[0 0 0 0 0 0 0 0]
'''
```

**第二步**：求 M 的左零空间

直接调用

```python
M = MT.T
A1 = M.left_kernel_matrix()
```

但是这里求出的 A1 并非所有元素都在 [-8, 8] 之间，不过 A 和 A1 都是 M 的左零空间的一组基，而 A.LLL() 之后得到的还是一组基，故大概是可以在 A1 或者 A1.LLL() 中找到题目要求的那个 A.LLL()[0] 的，(需要在A1 或者 A1.LLL() 中遍历，并且考虑反向量，甚至一些小的线性组合) ~~虽然也有可能完全找不到~~

(当然，也可再用格去求解，和第一步类似，[参考链接4] 中有，这里就不写了)

---

再区分一下：(以零空间为例)

`M.right_kernel()` 返回的是零空间对象

`M.right_kernel().basis_matrix()` 把这个零空间对象的基取出来，变成一个矩阵

`M.right_kernel_matrix()` 直接返回一个矩阵，矩阵的每一行是一组零空间基向量

后面两个的效果基本上是一样的。值得注意的是：零空间的向量一般理解就是列向量，但是两种写法得到的结果均是把零空间的基向量当作行向量存进去的，后面乘的时候需要转置一下

---

总之，目前粗浅地理解正交格似乎就是在零空间/左零空间上做文章

## 正题

```python
from Crypto.Util.number import getPrime, getRandomRange
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

FLAG = open('flag.txt','rb').read()

def lcg(a,b,p,x):
    while 1: yield (x := (a*x+next(b)) % p)

P, p = getPrime(256), getPrime(0x137)
X, A, B, a, b = [getRandomRange(0,m) for m in (P,P,p,p,p)]

# what's better than one lcg? TWO lcgs!
moons = lcg(a,iter([b]*14),p,B)
planets = lcg(A,moons,P,X)
orbit = [next(planets) for _ in range(14)]
star = AES.new(X.to_bytes(32),AES.MODE_ECB).encrypt(pad(FLAG,16)).hex()

print(f"{orbit = }")
print(f"{star = }")
```

构造了一个嵌套 lcg

moons：内层，参数：a, b, p, init=B；都是311bit数量级

planets/orbit：外层，参数：A, moons, P, init=X；A, P, X 都是256bit数量级

特点是外层的模数更小，而且 lcg 参数 'b' 是变化的，是内层 lcg 的输出；两个 lcg 所有参数均未知，只有外层 lcg 的14个输出，任务是恢复外层初始状态 X

---

**第一步**：先进行一些简单的推导与变形

记外层输出为 y，内层输出为 s
$$
y_i = Ay_{i-1} + s_i \pmod P \\
s_i = as_{i-1} + b \pmod p
$$
内层差分
$$
s_i - s_{i-1} = a(s_{i-1}-s_{i-2}) \pmod p \\
t_i = at_{i-1} \pmod p
$$
外层差分
$$
y_i - y_{i-1} = A(y_{i-1}-y_{i-2}) + (s_i - s_{i-1}) \pmod P \\
r_i = Ar_{i-1} + t_i \pmod P
$$
有
$$
t_i = r_i -Ar_{i-1} + k_i P
$$
**第二步**：恢复内层的 a 和 p

假设我们得到了若干个与 t 正交的向量 v，有
$$
\mathbf{v} \cdot \mathbf{t} = 0 \\
\sum_i v_it_i=0 \\
\sum_i v_ia^it_c\equiv 0 \pmod p \\
\sum_i v_ia^i \equiv 0 \pmod p \ (t_c \not\equiv 0 \pmod p)
$$
知道 $\mathbf{v}$ 之后可以得到一个多项式，并且这个多项式在模 p 意义下以 a 为根；因此，我们可以取3个这样的多项式，计算两组不同的结式 resultant。它们都会是 p 的倍数，之后对这些结式做 gcd，可以恢复 p，进而恢复 a

但是现在 t 是未知的，能用的只有外层的差分 r
$$
t_i= r_i - Ar_{i-1} \pmod P
$$
如果 $\mathbf v$ 同时正交于两个相邻的 r 的切片，那么其就会和 t 也正交，比如后面用的
$$
v\cdot(r_0,\dots,r_{10})=0\\
v\cdot(r_1,\dots,r_{11})=0\\
v\cdot(r_2,\dots,r_{12})=0\\
$$
这时需要用到 **Stern's Attack**，其意思大概是

这些对**截断序列**成立的正交关系，很可能也对完整隐藏序列 t 在模 p 下成立，也就是 $\mathbf{v} \cdot \mathbf{t} = 0$

故可以找
$$
Y = \begin{pmatrix}
r_0 & r_1 & \cdots & r_{10}\\
r_1 & r_2 & \cdots & r_{11}\\
r_2 & r_3 & \cdots & r_{12}
\end{pmatrix}
$$
的零空间 `rkm`，然后 LLL 一下，(用 LLL 从已知部分的正交关系里找出同时也正交于完整 t 的短向量)

虽然这里实测 `Y.right_kernel_matrix().LLL() == Y.right_kernel_matrix()`

注：Y.right_kernel_matrix() 会给出 8 个基向量，但这 8 个向量只是满足和3个 r 的切片正交，我们真正想要的是同时也正交于隐藏的 t 切片的向量，其有两个对应切片，所以额外多了两个隐藏约束
$$
v\cdot (t_1,\dots,t_{11})=0 \\
v\cdot (t_2,\dots,t_{12})=0
$$
因此真正有用的 Stern 子格维度大约是：8-2=6

所以：`rkm = Y.right_kernel_matrix().LLL()[:-2]`

**第三步**：恢复内层差分序列 t

直白的想法是，有 $\mathbf{v} \cdot \mathbf{t} = 0$ 之后，再找 v 的零空间恢复出 t，但是由于 t 太大，这里行不通

前面得到的 `rkm` 每一行是长度 11 的向量 $ v=(v_0,\dots,v_{10})$

因为 Y 取了三段 r，而如果 v 同时正交于相邻两段 r，就能推出它正交于一段 t，故现在有
$$
v\cdot(t_1,\dots,t_{11})=0 \\
v\cdot(t_2,\dots,t_{12})=0
$$
所以 `rkm` 的每一行其实给了两个滑动窗口约束，为了把这两条约束写成对同一个向量的方程，就要补 0：
$$
(v_0,\dots,v_{10},0)\cdot(t_1,\dots,t_{11},t_{12})=0 \\
(0,v_0,\dots,v_{10})\cdot(t_1,t_2,\dots,t_{12})=0
$$
如果不补0，直接把 `rkm` 拿过来的话，相当于对同一个 **v** 只进行了一条约束，最后大概率找不到结果 (也就是第三步一开始说的情况)

把所有的 **v** 按上面所说排成矩阵 M，找其零空间的基 B，代码中为 `rkm2`
$$
M =\begin{bmatrix}
0 & v_{00} & v_{01} & \cdots & v_{0n} \\
v_{00} & v_{01} & v_{02} & \cdots & 0 \\
0 & v_{10} & v_{11} & \cdots & v_{1n} \\
\vdots & \vdots & \vdots & \ddots & \vdots \\
v_{m0} & v_{m1} & v_{m2} & \cdots & 0
\end{bmatrix}
$$
rkm2 中有3个向量，每一行都是一个长度12的向量，张成候选空间 $\langle \text{rkm2}_0,\text{rkm2}_1,\text{rkm2}_2\rangle$

这个空间里包含：$(r_0,r_1,...,r_{11}),\ (r_1,r_2,...,r_{12}),\ (t_1,t_2,...,t_{12})$

则真实的 $(t_1,t_2,\dots,t_{12})$ 可表示为 $\mathbf t = uB$，但此时还不能唯一确定 t，因为零空间里可能有很多候选向量，于是要利用：内层差分 t 是模 p 下的等比数列
$$
\mathbf t \equiv c\cdot(1,a,a^2,\dots,a^{11}) \equiv cw \pmod p
$$
因为 $t=uB$，并且 $t\equiv c w\pmod p $，所以存在某个 (u,c)，使得 $uB - cw \equiv 0\pmod p $
$$
M = \begin{pmatrix}
B\\
\mathbf w
\end{pmatrix}
$$
也就是要找他的左零空间，然后找到 u，计算 uB 就恢复了 t

**注**：代码中求出 rkm2 之后还做了一步缩放，(虽然实际上缩放系数 k=1)

`rkm2.solve_left(r[1:])` 是在求 $c \cdot rkm2 = (r_1,r_2,...,r_{12})$

满足 $(r_1,r_2,...,r_{12}) = c_0B_0+c_1B_1+c_2B_2$

进行 `k = ZZ(rkm2.solve_left(r[1:])[2]); rkm2 *= k`，使得 $(r_1,r_2,...,r_{12}) = c_0'B_0'+c_1'B_1'+1\cdot B_2'$

后续 `M = rkm2[::-1]` 将 $B_2'$ 放到了最前面，然后 `left_kernel_matrix()` 通常会把第一个非零系数归一成1，所以如果坐标已经是 1，就更容易直接得到正确比例的左核向量

总之，这一步是为了确保已知参考向量 $(r_1,r_2,...,r_{12})$ 在 `rkm2` 基下的最后一个坐标被归一化为 1

>摘自 author wp
>
>One more thing to note is that because we find orthogonal vectors with LLL, `B.solve_left(y)[-1] == B.solve_left(x)[-1] == +- 1`. Additionally, when we find the last orthogonal basis (i.e. when finding **u**), the **first** entry is always equal to 1 (never −1). I'm not sure why LLL does this, but we can just accept it as a fact and manage our indices/polarity properly.

`B.solve_left(y)[-1] == B.solve_left(x)[-1] == +- 1` (这里的 r 就是 y，t 就是 x)，也就是说二者对应的最后一个基分量的系数都是 1 或 -1 (x应当是作者本地验证的)；并且一个经验/事实是，求出左零空间后第一个分量总会是 1，结合这两条性质，调整顺序后恢复出来的直接就是 t 

我也试了下别的顺序确实没法直接弄出来，感觉这里应当是一些技巧罢，有点玄学

**第四步**：恢复外层的 A 和 P

到这里就简单了
$$
r_i = Ar_{i-1} + t_i \pmod P \\
r_{i+1} = Ar_{i} + t_{i+1} \pmod P\\
(r_i - t_i)r_{i-1}^{-1} \equiv (r_{i+1} - t_{i+1})r_{i}^{-1} \pmod P \\
(r_i - t_i)r_i \equiv (r_{i+1} - t_{i+1})r_{i-1} \pmod P
$$ {(r_i - t_i)}
取两组数据 gcd 一下恢复 P，最后代回去恢复 A (**注意公式下标和实际索引略有差异**)

最后倒恢复 X
$$
r_0 \equiv y_0 - y_{-1} \pmod P \\
X \equiv y_{-1} \equiv y_0 - r_0 \pmod P
$$
另一方面
$$
y_1 - y_{0} = A(y_{0}-y_{-1}) + (s_1 - s_{0}) \mod P \\
$$
`t[0]` 放的是 s[2]-s[1]，故 `t[-1]` 应当是 s[1]-s[0]，而 $t[0] \equiv at[-1] \pmod p$，代码中兼顾了 t[-1] 为正和为负的两种情况 (例如是 p-7，当正数处理就直接算；当 -7 处理，需要减去 p；最终结果是前者)

代入即可求得 $y_{-1}$

---

完整 exp

```python
from Crypto.Cipher import AES

orbit = [46157012221654917396851254347154820393060391878580715960476654689260395468184, 36926194633341127588542680684095293820802193681748458943524916140809713523560, 16005201943847263206512436577001283414470030273089746675203830598137794555134, 28937919714389596084610407023450127584695575606301484773390370819366639643218, 11459012353705334109041842799942754581703065868230253271729711591416155557180, 31030059279554219046464541926833857543445131889728181065565033726460506326840, 20987315604501021667042879662101693092441980938033961081037347214532349371248, 76741461130245451493723909055453557280102065396647043801270629949855565452326, 84258885183671683674472390974667571532577240974449641001706593550302243268268, 59535034089467707172052245359810812420431903279354584714432674122159502991956, 7115679899033391144975170596669540596311296590450661546000723388170577963715, 35572951991838484594163260879328705523576344587262461128887804475450813563036, 85569022704397114858282741078883377190544624744955636482627379979792474136036, 5047270986830280372910174287287823507537624765267582560460157826800286170460]
star = '1664ff83cbca2643b357bcdc8c3d6e1548615a18cec73e734a82e163b32a9b0c367c61bab01140a04ac8eda8b007d1d6'
r = vector(orbit[1:]) - vector(orbit[:-1])

Y = matrix(ZZ,3,11)
for i in range(3):
    Y[i] = vector(r[i:i+11])
rkm = Y.right_kernel_matrix().LLL()[:-2]

R.<x> = PolynomialRing(ZZ)
poly0 = sum([rkm[0,i]*x**i for i in range(11)])
poly1 = sum([rkm[1,i]*x**i for i in range(11)])
poly2 = sum([rkm[2,i]*x**i for i in range(11)])

res0 = poly0.resultant(poly1)
res1 = poly1.resultant(poly2)
p = gcd(res0,res1).factor()[-1][0]

poly0 = poly0.change_ring(GF(p))
poly1 = poly1.change_ring(GF(p))
a = gcd(poly0,poly1).roots()[0][0]

M = matrix(0,12)
for row in rkm:
    M = M.stack(matrix([0]+list(row)))
    M = M.stack(matrix(list(row)+[0]))
rkm2 = M.right_kernel_matrix().LLL()
k = ZZ(rkm2.solve_left(r[1:])[2])
rkm2 *= k

M = rkm2[::-1].stack(vector(a**i for i in range(len(r)-1)))
t = vector(M.left_kernel_matrix()[0, 2::-1]).lift_centered()*rkm2

gcd_a = r[0]*(r[2]-t[1])-r[1]*(r[1]-t[0])
gcd_b = r[1]*(r[3]-t[2])-r[2]*(r[2]-t[1])
P = gcd(gcd_a,gcd_b).factor()[-1][0]
A = mod((r[1]-t[0])/r[0],P)

X = orbit[0]-(r[0]-mod(ZZ(mod(t[0]/a,p))-p,P))/A
flag = AES.new(X.to_bytes(),AES.MODE_ECB).decrypt(bytes.fromhex(star))
if not flag.isascii():
    X = orbit[0]-(r[0]-mod(mod(t[0]/a,p),P))/A
    flag = AES.new(X.to_bytes(),AES.MODE_ECB).decrypt(bytes.fromhex(star))
print(flag.decode())
# SEKAI{orbital_strike_like_miku_miku_beam!!!}
```

## 总结

这个题以我的水平来说还是太难了，感觉需要正交格这块玩的很6才行，虽然目前也没有完全理解掌握吧，还有一些地方比较模糊，但还是学到不少东西。未来仍需继续努力，夯实基本功 🐈

## 参考

0. [Water's Blog official writeup](https://shuizhuimiaoman.github.io/#/sekaictf-2026-author-writeup)

1. [入门向\]结式在CTF Crypto中的应用 - 知乎](https://zhuanlan.zhihu.com/p/674151864)

2. [Gröbner 基学习与CTF题目实践应用-先知社区](https://xz.aliyun.com/news/17347)

3. [HSSP与正交格学习笔记 | Tover's Blog](https://tover.xyz/p/HSSP-note/)

4. [正交格 - suhanhan的博客](https://suhanhan-cpu.github.io/2024/12/25/正交格/)