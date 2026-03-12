+++
title = "LilCTF 2025"
date = "2026-02-05"
categories = ["WP"]
image="1.png"
+++

# LilCTF 2025

**前言**

线代crypto belike...

困难，神奇，有趣

## ez_math

```python
from sage.all import *
from Crypto.Util.number import *

flag = b'LILCTF{test_flag}'[7:-1]
lambda1 = bytes_to_long(flag[:len(flag)//2])
lambda2 = bytes_to_long(flag[len(flag)//2:])
p = getPrime(512)
def mul(vector, c):
    return [vector[0]*c, vector[1]*c]

v1 = [getPrime(128), getPrime(128)]
v2 = [getPrime(128), getPrime(128)]

A = matrix(GF(p), [v1, v2])
B = matrix(GF(p), [mul(v1,lambda1), mul(v2,lambda2)])
C = A.inverse() * B

print(f'p = {p}')
print(f'C = {str(C).replace(" ", ",").replace("\n", ",").replace("[,", "[")}')

# p = 9620154777088870694266521670168986508003314866222315790126552504304846236696183733266828489404860276326158191906907396234236947215466295418632056113826161
# C = [7062910478232783138765983170626687981202937184255408287607971780139482616525215270216675887321965798418829038273232695370210503086491228434856538620699645,7096268905956462643320137667780334763649635657732499491108171622164208662688609295607684620630301031789132814209784948222802930089030287484015336757787801],[7341430053606172329602911405905754386729224669425325419124733847060694853483825396200841609125574923525535532184467150746385826443392039086079562905059808,2557244298856087555500538499542298526800377681966907502518580724165363620170968463050152602083665991230143669519866828587671059318627542153367879596260872]
```

**方法一**

$$
A = \begin{pmatrix}
a & b \\
c & d
\end{pmatrix}
,
B = \begin{pmatrix}
f_1a & f_1b \\
f_2c & f_2d
\end{pmatrix}
$$

$$
C = A^{-1}B = \frac{1}{ad-bc} \begin{pmatrix}
d & -b \\
-c & a
\end{pmatrix} 
\begin{pmatrix}
f_1a & f_1b \\
f_2c & f_2d
\end{pmatrix}
= \frac{1}{ad-bc}\begin{pmatrix}
f_1ad-f_2bc & f_1bd-f_2bd \\
-f_1ac+f_2ac & -f_1bc+f_2ad
\end{pmatrix}
$$

故C[0, 0] + C[1, 1] = f1 + f2

另一方面$|C| = |A^{-1}||B| = \frac{|B|}{|A|} = f_1f_2$

联立解方程即可，exp

```python
p = 9620154777088870694266521670168986508003314866222315790126552504304846236696183733266828489404860276326158191906907396234236947215466295418632056113826161
C = [7062910478232783138765983170626687981202937184255408287607971780139482616525215270216675887321965798418829038273232695370210503086491228434856538620699645,7096268905956462643320137667780334763649635657732499491108171622164208662688609295607684620630301031789132814209784948222802930089030287484015336757787801], [7341430053606172329602911405905754386729224669425325419124733847060694853483825396200841609125574923525535532184467150746385826443392039086079562905059808,2557244298856087555500538499542298526800377681966907502518580724165363620170968463050152602083665991230143669519866828587671059318627542153367879596260872]
C = matrix(GF(p), C)
ji = det(C)
he = C[0][0] + C[1][1]
x, y = var('x'), var('y')
ans = solve([x * y == int(ji), x + y == int(he)], [x, y])
```

```python
from Crypto.Util.number import long_to_bytes
f1 = 461081882199191304136043558055592717274072444511548267131743
f2 = 310431440615324582056084165589022472378402725080813836002613
print(b'LILCTF{' + long_to_bytes(f1) + long_to_bytes(f2) + b'}')
# LILCTF{It_w4s_the_be5t_of_times_1t_wa5_the_w0rst_of_t1me5}
```

**方法二**

特征值做法，记


$$
\alpha_1 = (a,\ b),\quad
\alpha_2 = (c,\ d)
$$
则$C=A^{-1}B$，可得$AC=B$，分块
$$
\begin{pmatrix}
\alpha_1 \\
\alpha_2
\end{pmatrix}
C = \begin{pmatrix}
\alpha_1C \\
\alpha_2C
\end{pmatrix}
=  \begin{pmatrix}
f_1\alpha_1 \\
f_2\alpha_2
\end{pmatrix}
$$
即$\alpha_iC =  f_i\alpha_i$，和特征值定义不太一样，因为标准定义的特征向量在矩阵右边，是一个列向量

对$\alpha_iC =  f_i\alpha_i$两边转置可得，$C^T\alpha_i^T =  f_i\alpha_i^T$，这就是标准的定义式了，不过$f_i$现在是$C^T$的特征值，而不难得到$C$和$C^T$具有相同特征值，因为$det(C-\lambda I) = det(C^T -\lambda I)$，(行列式转置值不变)

综上，f1和f2为C的两个特征值，利用sage内置函数求即可，显然更简洁

```python
p = 9620154777088870694266521670168986508003314866222315790126552504304846236696183733266828489404860276326158191906907396234236947215466295418632056113826161
C = [7062910478232783138765983170626687981202937184255408287607971780139482616525215270216675887321965798418829038273232695370210503086491228434856538620699645,7096268905956462643320137667780334763649635657732499491108171622164208662688609295607684620630301031789132814209784948222802930089030287484015336757787801], [7341430053606172329602911405905754386729224669425325419124733847060694853483825396200841609125574923525535532184467150746385826443392039086079562905059808,2557244298856087555500538499542298526800377681966907502518580724165363620170968463050152602083665991230143669519866828587671059318627542153367879596260872]
C = matrix(GF(p), C)
from Crypto.Util.number import long_to_bytes
flag = b''
for f in C.eigenvalues():
    flag += long_to_bytes(int(f))
print(b'LILCTF{' + flag + b'}')
```

## mid_math

```python
from sage.all import *
from Crypto.Util.number import *
from tqdm import tqdm
from random import randint
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

flag = b'LILCTF{test_flag}'

p = getPrime(64)
P = GF(p)

key = randint(2**62, p)

def mul(vector, c):
    return [vector[0]*c, vector[1]*c, vector[2]*c, vector[3]*c, vector[4]*c]

v1 = [getPrime(64), getPrime(64), getPrime(64), getPrime(64), getPrime(64)]
v2 = [getPrime(64), getPrime(64), getPrime(64), getPrime(64), getPrime(64)]
v3 = [getPrime(64), getPrime(64), getPrime(64), getPrime(64), getPrime(64)]
v4 = [getPrime(64), getPrime(64), getPrime(64), getPrime(64), getPrime(64)]
v5 = [getPrime(64), getPrime(64), getPrime(64), getPrime(64), getPrime(64)]
a, b, c, d, e = getPrime(64), getPrime(64), getPrime(64), getPrime(64),  0

A = matrix(P, [v1, v2, v3, v4, v5])
B = matrix(P, [mul(v1,a), mul(v2,b), mul(v3, c), mul(v4, d), mul(v5, e)])
C = A.inverse() * B
D = C**key

key = pad(long_to_bytes(key), 16)
aes = AES.new(key,AES.MODE_ECB)
msg = aes.encrypt(pad(flag, 64))

print(f"p = {p}")
print(f'C = {[i for i in C]}'.replace('(', '[').replace(')', ']'))
print(f'D = {[i for i in D]}'.replace('(', '[').replace(')', ']'))
print(f"msg = {msg}")

#p = 14668080038311483271
#C = [[11315841881544731102, 2283439871732792326, 6800685968958241983, 6426158106328779372, 9681186993951502212], [4729583429936371197, 9934441408437898498, 12454838789798706101, 1137624354220162514, 8961427323294527914], [12212265161975165517, 8264257544674837561, 10531819068765930248, 4088354401871232602, 14653951889442072670], [6045978019175462652, 11202714988272207073, 13562937263226951112, 6648446245634067896, 13902820281072641413], [1046075193917103481, 3617988773170202613, 3590111338369894405, 2646640112163975771, 5966864698750134707]]
#D = [[1785348659555163021, 3612773974290420260, 8587341808081935796, 4393730037042586815, 10490463205723658044], [10457678631610076741, 1645527195687648140, 13013316081830726847, 12925223531522879912, 5478687620744215372], [9878636900393157276, 13274969755872629366, 3231582918568068174, 7045188483430589163, 5126509884591016427], [4914941908205759200, 7480989013464904670, 5860406622199128154, 8016615177615097542, 13266674393818320551], [3005316032591310201, 6624508725257625760, 7972954954270186094, 5331046349070112118, 6127026494304272395]]
#msg = b"\xcc]B:\xe8\xbc\x91\xe2\x93\xaa\x88\x17\xc4\xe5\x97\x87@\x0fd\xb5p\x81\x1e\x98,Z\xe1n`\xaf\xe0%:\xb7\x8aD\x03\xd2Wu5\xcd\xc4#m'\xa7\xa4\x80\x0b\xf7\xda8\x1b\x82k#\xc1gP\xbd/\xb5j"
```

矩阵规模变大，上面的方法一不再好用，故仍从特征值角度入手

同样的有$\alpha_iC =  f_i\alpha_i$，在这个题中，abcde即为C的5个特征值，而$D = C^k$，D的特征值为C对应特征值的k次幂那么实质上就是解决离散对数问题，而且将矩阵上的离散对数转到了特征值上的离散对数，这很重要，因为矩阵的阶似乎不是很平凡，但是由于指数空间是64bit的，bsgs脚本直接跑不出来

但是看wp解离散对数用的是discrete_log()函数，感觉不对劲，不应该是用的函数的问题，一看发现这个p有问题，p-1分解后最大素因子只有44bit，故这个dlp问题可解

因不知C和D的特征值对应关系，只好全试一试，此外C的五个特征值(除0以外)，有两个阶为p-1，故用此计算

记$q \ | \ p-1$，由$\lambda_c ^k \equiv \lambda_D \pmod p$，可得$(\lambda_C ^k)^{\frac{p-1}{q}} \equiv (\lambda_D) ^{\frac{p-1}{q}} \equiv (\lambda_C ^{\frac{p-1}{q}})^k \pmod p$，而$\lambda_C ^{\frac{p-1}{q}}$的阶为q(需要$\lambda_C$的阶为p-1)，故由此式可得$k \equiv k_i \pmod q$，最后CRT组合即可

```python
p = 14668080038311483271
C = [[11315841881544731102, 2283439871732792326, 6800685968958241983, 6426158106328779372, 9681186993951502212], [4729583429936371197, 9934441408437898498, 12454838789798706101, 1137624354220162514, 8961427323294527914], [12212265161975165517, 8264257544674837561, 10531819068765930248, 4088354401871232602, 14653951889442072670], [6045978019175462652, 11202714988272207073, 13562937263226951112, 6648446245634067896, 13902820281072641413], [1046075193917103481, 3617988773170202613, 3590111338369894405, 2646640112163975771, 5966864698750134707]]
D = [[1785348659555163021, 3612773974290420260, 8587341808081935796, 4393730037042586815, 10490463205723658044], [10457678631610076741, 1645527195687648140, 13013316081830726847, 12925223531522879912, 5478687620744215372], [9878636900393157276, 13274969755872629366, 3231582918568068174, 7045188483430589163, 5126509884591016427], [4914941908205759200, 7480989013464904670, 5860406622199128154, 8016615177615097542, 13266674393818320551], [3005316032591310201, 6624508725257625760, 7972954954270186094, 5331046349070112118, 6127026494304272395]]
msg = b"\xcc]B:\xe8\xbc\x91\xe2\x93\xaa\x88\x17\xc4\xe5\x97\x87@\x0fd\xb5p\x81\x1e\x98,Z\xe1n`\xaf\xe0%:\xb7\x8aD\x03\xd2Wu5\xcd\xc4#m'\xa7\xa4\x80\x0b\xf7\xda8\x1b\x82k#\xc1gP\xbd/\xb5j"
C = matrix(GF(p), C)
D = matrix(GF(p), D)
c = C.eigenvalues()[1:]
d = D.eigenvalues()[1:]

factor = [2, 5, 17, 21379, 4035868083389]
from sage.groups.generic import bsgs
def solve(cc, dd):
    ans = []
    for fac in factor:
        tmp = (p - 1) // fac
        F = GF(p)
        g = F(cc**tmp)
        y = F(dd**tmp)
        try:
            x = bsgs(g, y, bounds=(0, fac))  # g^x = y (mod p)
            ans.append(x)
        except:
            pass
    return ans

from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import pad
from sympy.ntheory.modular import crt

assert c[3].multiplicative_order() == p - 1
for i in range(4):
    try:
        ans = solve(c[1], d[i])
        key, _ = crt(factor, ans)
        print(key)             
        key = pad(long_to_bytes(key), 16)
        aes = AES.new(key,AES.MODE_ECB)
        flag = aes.decrypt(msg)
        print(flag)
    except:
        print('pass')
# LILCTF{Are_y0u_5till_4wake_que5t1on_m4ker!}
```

若用discrete_log()

```python
for i in range(4):
    try:
        tmp = int(discrete_log(d[0], c[i]))
        print(tmp)
        key = pad(long_to_bytes(tmp), 16)
        aes = AES.new(key,AES.MODE_ECB)
        flag = aes.decrypt(msg)
        print(flag)
    except:
        pass
```

DLP小结

```text
1. python版bsgs脚本
2. sage内置bsgs函数
from sage.groups.generic import bsgs
F = GF(p)
g = F(g)
y = F(a)
x = bsgs(g, y, bounds=(0, 2 ^ 32))  # g^x = y (mod p)
3. sage内置discrete_log函数
F = GF(p)
a = F(a)  # 目标值
base = F(base)  # 底数
x = discrete_log(a, base)  # 计算 base^x = a (mod p)
4. sage内置.log()方法
F = GF(p)
a = F(a)  # 目标值
base = F(base)  # 底数
x = a.log(base) # base^a = a (mod p)
```

## Linear

```python
import os
import random
import signal

signal.alarm(10)

flag = os.getenv("LILCTF_FLAG", "LILCTF{default}")

nrows = 16
ncols = 32

A = [[random.randint(1, 1919810) for _ in range(ncols)] for _ in range(nrows)]
x = [random.randint(1, 114514) for _ in range(ncols)]

b = [sum(A[i][j] * x[j] for j in range(ncols)) for i in range(nrows)]
print(A)
print(b)

xx = list(map(int, input("Enter your solution: ").strip().split()))
if xx != x:
    print("Oh, your linear algebra needs to be practiced.")
else:
    print("Bravo! Here is your flag:")
    print(flag)
```

$Ax=b$，16个方程，32个未知数，起初的想法是先找一特解，然后求A的右核空间，做线性组合，利用条件筛选，但再想想觉得几乎不可能实现，题目有10s限制，~~就算没有也算不出来~~

然后就想不到什么办法了，再次学习wp，将b转为矩阵，求b的左核空间，即$ker(b)\ b = 0$，然后有$ker(b)Ax =0$，即x应属于$ker(b)A$的右核空间，而x的元素比A少了一个数量级，故用LLL可求	~~(结合LLL求是真没想到)~~

```python
from pwn import *

p = remote('127.0.0.1', 7070)
A = eval(p.recvline().decode())
b = eval(p.recvline().decode())
nrows = 16
ncols = 32
A = matrix(A)
b = matrix(nrows, 1, b)

tmp1 = b.left_kernel().basis_matrix() # .basis_matrix()将向量组转为矩阵
tmp2 = tmp1 * A
tmp3 = tmp2.right_kernel().basis_matrix()
x1 = [-i for i in tmp3.LLL()[0]]

p.recvuntil(b'Enter your solution: ')
ans = ''
for i in x1:
    ans += (str(i)+' ')
p.sendline(ans.encode())
print(p.recvline())
print(p.recvline())
```

> 矩阵的四个子空间

设 A 为$m \times n$矩阵，rank(A) = r 则：

列空间  $C(A) = \{ \mathbf{y} \in \mathbb{R}^m \mid \mathbf{y} = A\mathbf{x} \}$，即$A$列向量的线性组合，维数$r$

行空间  $C(A^\mathsf{T}) = \{ \mathbf{y} \in \mathbb{R}^n \mid \mathbf{y} = A^\mathsf{T} \mathbf{x} \}$，即$A$行向量的线性组合，这里做了转置，维数$r$

零空间  $N(A) = \{ \mathbf{x} \in \mathbb{R}^n \mid A\mathbf{x} = \mathbf{0} \}$，右核空间，维数$n-r$

左零空间  $N(A^\mathsf{T}) = \{ \mathbf{x} \in \mathbb{R}^m \mid A^\mathsf{T} \mathbf{x} = \mathbf{0} \}$，左核空间，这里做了转置，维数$m-r$

注：维数指的不是一个向量的分量个数，而应是一组基中的向量个数

结合上面例子，b是一个16\*1的矩阵，故其左核空间的维数应为15，进一步转为矩阵后形状为15\*16(15个有16个分量的行向量拼起来)，$ker(b)A$是15\*32的，故其右核空间维数应为17，转矩阵后应为32\*17(17个有32个分量的列向量拼起来)，但是saga返回的是17\*32，是做了个转置。恰好的是LLL规约的是行向量，可以直接LLL

## baaaaaag

```python
from Crypto.Util.number import *
import random
from Crypto.Cipher import AES
import hashlib
from Crypto.Util.Padding import pad
from secret import flag

p = random.getrandbits(72)
assert len(bin(p)[2:]) == 72

a = [getPrime(90) for _ in range(72)]
b = 0
t = p
for i in a:
    temp = t % 2
    b += temp * i
    t = t >> 1

key = hashlib.sha256(str(p).encode()).digest()
cipher = AES.new(key, AES.MODE_ECB)
flag = pad(flag,16)
ciphertext = cipher.encrypt(flag)

print(f'a = {a}')
print(f'b = {b}')
print(f"ciphertext = {ciphertext}")
```

背包格，最初的构造，pi为p的第i比特位(从低位开始)，b的bit长度为95
$$
(p_0 \ \  p_1 \ \ \dots \ \ p_{71} \ \  -1) 
\begin{pmatrix}
1 & 0 & \cdots & 0 & a_0 \\
0 & 1 & \cdots & 0 & a_1 \\
\vdots & \vdots & \ddots & \vdots & \vdots \\
0 & 0 & \cdots & 1 & a_{71} \\
0 & 0 & \cdots & 0 & b
\end{pmatrix} =
(p_0 \ \  p_1 \ \ \dots \ \ p_{71} \ \  0)
$$
but给最后一列配了配，还是规约不出来

不中了，补一补背包密码的知识，搜到大佬博客[背包密码 | DexterJie'Blog](https://dexterjie.github.io/2024/07/29/背包密码/#背包密码)

感觉学到很多压缩后的精华，摘抄如下

CTF中出现的背包问题通常形如：$ S = \sum_{i=0}^{n-1} x_i M_i $

其中 $M$ 为背包的公钥，$S$ 为密文，记 $n = \operatorname{len}(M)$，背包密度 $d = \frac{n}{\log_2(\max(M))}$

构造的格有2种，一种是上面的(n+1)\*(n+1)的格，另一种也是(n+1)\*(n+1)，如下
$$
(p_0 \ \  p_1 \ \ \dots \ \ p_{71} \ \  -1)
\begin{pmatrix}
2 & 0 & \cdots & 0 & a_0 \\
0 & 2 & \cdots & 0 & a_1 \\
\vdots & \vdots & \ddots & \vdots & \vdots \\
0 & 0 & \cdots & 2 & a_{71} \\
1 & 1 & \cdots & 1 & b
\end{pmatrix} = (2p_0-1 \ \  2p_1-1 \ \ \dots \ \ 2p_{71}-1 \ \  0)
$$
因此目标向量取值应属于{-1,1}(除去最后一个0)

第二种比第一种好在第二种格的行列式会更大一些

上面两个格一般在用的时候会在最后一列乘上`N = ceil(sqrt(n))`	(个人感觉作用就是配平)

另外，规约算法除LLL外还可以用BKZ，sagemath中的BKZ()可以设置参数，例如BKZ(block_size = 16)，指定了BKZ算法中的块大小。默认情况下是block_size = 10，block_size越大，执行速度越慢，但结果更精确

[The Relation Between Lattice Reduction Algorithm and Knapsack Density](https://github.com/DexterJie/CTF_Repo/tree/main/The%20Relation%20Between%20Lattice%20Reduction%20Algorithm%20and%20Knapsack%20Density)



更强的是这个实验结果，可以得到几个很有用的信息

- 第二种格成功率比第一种高
- BKZ算法比LLL算法成功率高，当然block_size越大成功率越高，实验里测试了20和26

对于本题，背包密度d约为0.8，站在巨人肩膀上，策略：第二种格，BKZ，block_size = 26，实操后发现block_size需调至27，exp如下，有两点注意，一是考虑目标向量可能带了个负号，二是搜索规约后的所有结果(虽然解就是第一个)

```python
a = [965032030645819473226880279, 699680391768891665598556373, 1022177754214744901247677527, 680767714574395595448529297, 1051144590442830830160656147, 1168660688736302219798380151, 796387349856554292443995049, 740579849809188939723024937, 940772121362440582976978071, 787438752754751885229607747, 1057710371763143522769262019, 792170184324681833710987771, 912844392679297386754386581, 906787506373115208506221831, 1073356067972226734803331711, 1230248891920689478236428803, 713426848479513005774497331, 979527247256538239116435051, 979496765566798546828265437, 836939515442243300252499479, 1185281999050646451167583269, 673490198827213717568519179, 776378201435505605316348517, 809920773352200236442451667, 1032450692535471534282750757, 1116346000400545215913754039, 1147788846283552769049123803, 994439464049503065517009393, 825645323767262265006257537, 1076742721724413264636318241, 731782018659142904179016783, 656162889354758353371699131, 1045520414263498704019552571, 1213714972395170583781976983, 949950729999198576080781001, 1150032993579134750099465519, 975992662970919388672800773, 1129148699796142943831843099, 898871798141537568624106939, 997718314505250470787513281, 631543452089232890507925619, 831335899173370929279633943, 1186748765521175593031174791, 884252194903912680865071301, 1016020417916761281986717467, 896205582917201847609656147, 959440423632738884107086307, 993368100536690520995612807, 702602277993849887546504851, 1102807438605649402749034481, 629539427333081638691538089, 887663258680338594196147387, 1001965883259152684661493409, 1043811683483962480162133633, 938713759383186904819771339, 1023699641268310599371568653, 784025822858960757703945309, 986182634512707587971047731, 1064739425741411525721437119, 1209428051066908071290286953, 667510673843333963641751177, 642828919542760339851273551, 1086628537309368288204342599, 1084848944960506663668298859, 667827295200373631038775959, 752634137348312783761723507, 707994297795744761368888949, 747998982630688589828284363, 710184791175333909291593189, 651183930154725716807946709, 724836607223400074343868079, 1118993538091590299721647899]
b = 34962396275078207988771864327
ciphertext = b'Lo~G\xf46>\xd609\x8e\x8e\xf5\xf83\xb5\xf0\x8f\x9f6&\xea\x02\xfa\xb1_L\x85\x93\x93\xf7,`|\xc6\xbe\x05&\x85\x8bC\xcd\xe6?TV4q'

def solve():
    n = len(a)
    d = n / log(max(a), 2)
    print(f"背包密度为: {CDF(d)}")

    Ge = Matrix(ZZ, n + 1, n + 1)
    for i in range(n):
        Ge[i, i] = 2
        Ge[-1, i] = 1
        Ge[i, -1] = a[i]
    Ge[-1, -1] = b
    N = ceil(sqrt(n))
    Ge[:, -1] *= N

    ans = []
    for line in Ge.BKZ(block_size=27):
        if set(line[:-1]).issubset({-1, 1}): # 约束条件
            p0 = ''
            p1 = ''
            for i in line[:-1]:
                if i == 1:
                    p0 += '1'
                    p1 += '0'
                if i == -1:
                    p0 += '0'
                    p1 += '1'
            p0 = int(p0[::-1], 2)
            p1 = int(p1[::-1], 2)
            if len(bin(p0)[2:]) == 72:
                ans.append(p0)
            if len(bin(p1)[2:]) == 72:
                ans.append(p1)
    return ans

ans = solve()
from Crypto.Cipher import AES
import hashlib
for p in ans:
    key = hashlib.sha256(str(p).encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    flag = cipher.decrypt(ciphertext)
    print(flag)
# LILCTF{M4ybe_7he_brut3_f0rce_1s_be5t}
```

> 反转字符串，reversed函数有返回值，不是原地修改...

## Space Travel

```python
from Crypto.Cipher import AES
from hashlib import md5
from params import vecs
from os import urandom

key = int("".join([vecs[int.from_bytes(urandom(2)) & 0xfff] for _ in range(50)]), 2)

print("🎁 :", [[nonce := int(urandom(50*2).hex(), 16), (bin(nonce & key).count("1")) % 2] for _ in range(600)])
print("🚩 :", AES.new(key=md5(str(key).encode()).digest(), nonce=b"Tiffany", mode=AES.MODE_CTR).encrypt(open("flag.txt", "rb").read()))
```

params.py内容`vecs = ['0111001101001000', '1010111100000111', '1111100010110100', ...]`，为4096个16bit序列

gift中的nonce和AES-CTR模式的nonce应是两码事，我们的任务是通过gift恢复key，即给了600个nonce的值以及bin(nonce & key).count("1")，可以表达为下面的形式，nij为gift中的第i个nonce的第j比特位(从高向低)，kj为key的第j比特位(也是从高向低)
$$
\begin{pmatrix}
n_{00} & n_{01} & \cdots & n_{0,799} \\
n_{10} & n_{11} & \cdots & n_{1,799} \\
\vdots & \vdots & \ddots & \vdots \\
n_{599,0} & n_{599,1} & \cdots & n_{599,799}
\end{pmatrix}
\begin{pmatrix}
k_0 \\
k_1 \\
\vdots \\
k_{799}
\end{pmatrix}
\equiv
\begin{pmatrix}
c_0 \\
c_1 \\
\vdots \\
c_{599}
\end{pmatrix}
\pmod 2
$$
那么看着就很像linear那个题，600个方程，800个未知数，但是多了个模数2，没法再用同样的方法找k向量，因为模2意义下的向量空间里，大多数向量都差不多大，故规约不出来。而且事实上，对于一个模意义下的矩阵，没法直接用LLL或BKZ，需转为整数矩阵，即添加一项$2(t_0 \ \ t_1 \cdots t_{599} )^T$，变得不好分析

只好再看wp学习了，是想将方程组降维，而key取自vecs数组，将vecs转为一个4096*16的矩阵V1，发现其秩只有13，若为12的话，则12\*50=600，刚刚好

此时考虑vecs是由特定线性变换Ax+b生成，我们用矩阵V各行减去第一行v0，发现新得到的矩阵V2的秩只有12，我们取出其一组基L(12*16)，在sage中可以用.echelon_form()方法实现，其是将一个矩阵化为行阶梯形，那么显然V2中的任一个(行)向量可由L线性组合表示，进而，V1中的任一向量$v_i = z_i L +v_0$，$z_i$是一个1\*12的向量，恰好$2^{12}=4096$，可以变换出完整的vecs

求出zi之后，将原等式中的k向量和N矩阵做一个分组操作，可得$nv_i = n(z_iL+v_0)=nLz_i+nv_0$，据此重构一下等式，$N diag(L^T)\vec{z}+N\vec{v}_0\equiv c \pmod 2$，可解出600个z变量，然后重新计算出v向量，即key

实际写exp注意形状和转置，，还有下面这个
$$
\begin{pmatrix}
L^\mathsf{T} &  &  &  \\
 & L^\mathsf{T} &  &  \\
 &  & \ddots &  \\
 &  &  & L^\mathsf{T}
\end{pmatrix}
\begin{pmatrix}
z_0 \\
z_1 \\
\vdots \\
z_{49}
\end{pmatrix}
= \begin{pmatrix}
L^Tz_0 \\
L^Tz_1 \\
\vdots \\
L^Tz_{49}
\end{pmatrix}
$$

```python
from params import vecs

with open('output.txt') as f:
    gift = eval(f.readline().split(': ')[1])
    enc = eval(f.readline().split(': ')[1])

tmp = []
b = []
for i in gift:
    tmp1 = list(bin(i[0])[2:].zfill(800))
    tmp.append(tmp1)
    b.append(i[1])
N = matrix(Zmod(2), tmp)
c = vector(Zmod(2), b)

V1 = matrix(GF(2), 4096, 16)
for i in range(4096):
    for j in range(16):
        V1[i, j] = int(vecs[i][j])
# print(V1.rank()) # 13

v0 = V1[0]
V2 = matrix(GF(2), [v - v0 for v in V1[1:]])
print(V2.rank()) # 12
L = V2.echelon_form()[:12]

v00 = []
for _ in range(50):
    v00.extend(v0)
v00 = vector(GF(2), v00)

LL = block_diagonal_matrix([L.transpose() for _ in range(50)])
c -= N * v00
zz = (N * LL).solve_right(c)
k = (LL * zz + v00).list()
key = int(''.join([str(i) for i in k]), 2)

from Crypto.Cipher import AES
from hashlib import md5
aes = AES.new(key=md5(str(key).encode()).digest(), nonce=b"Tiffany", mode=AES.MODE_CTR)
flag = aes.decrypt(enc)
print(flag)
# LILCTF{Un1qUe_s0luti0n_1N_sUbSp4C3!}
```

线代好神奇 ∑( 口 ||
