+++
title = "0xGame 2026"
date = "2026-10-25"
categories = ["WP"]
image="111.png"

+++

# 0xGame 2026

**前言**

国庆附近那两周有点闲，并且之前看到了在 moe 群里的宣传，想着参加玩一玩，复习下知识也学一学出题思路

之前也刷到过 0xGame 2025 的 wp，虽然没做过，但是看着质量还挺好

but，今年的题目我是真的看力竭了，不敢恭维。基本所有的题目形式都背离了传统 crypto 那种直白、开门见山的方式，要么没有附件，要么附件奇奇怪怪的，大抵就是 AI 生成的

现在 CTF 环境下，倒也不是说不好，反正我是欣赏不来这种方式，很无趣。不过既然写都写了，索性就水一期吧



## Week1

### 天使大人

经典的 sagemath 签到题，运行代码得到结果，附件就不放了

`e834598ba8cf6695cc9299364fe4fa63b05a1b55f847ab5aecb6d5dc251e2b77`

提交到环境即可得到 `0xGame{r34lly g00d st3p f0rw4ord}`

### decode for love

一道古典密码，密文是一串 emoji

```
🙃💵🌿🎤🚪🌏🐎🥋🚫😆✅👁☺❓🚨🍴🥋🌊🏹🕹🐘🛩🍵😊🔪🍍🖐❓😂🐍✅👣🌊🍎🔬☺🛩☃🐎🐎🚰🖐📂🌪🚰🐎🚪🐅🤣🎅🔄🐅😆🔪☺💵🍍🌉🏹🚨🍴🌉😀🐅
```

base100 尝试后不行，那就是 [emoji-aes](https://emoji-aes.miaotony.xyz/) 在线网站，结合题目描述 "密码是0x2026"，得到

```
TFVKVktQVU5OTEFBQQ==
```

base64 得到

```
LUJVKPUNNLAAA
```

都是字母，猜测是维吉尼亚或者凯撒，但是没有密钥了，尝试了凯撒，发现偏移量为 7 时解密得到

```
ENCODINGGETTT
```

故 flag 是 `0xGame{ENCODINGGETTT}`

### RSA永恒花园

```python
from Crypto.Util.number import *
import gmpy2
from secret import flag

p,q=[getPrime(256)for _ in range(2)]
n=p*q
e=65537
m=bytes_to_long(flag)
c=gmpy2.powmod(m,e,n)

print(f"e={e}")
print(f"c={c}")
print(f"n={n}")
#n=1094173864157052742180970732204035761200373294544920599091384213147634998428893478471799725789126733249762575289978183379707653724402714674353159335433389
#c=10073137615027377140510981218791415001906117916633551597480408677492183003649126231396950464383049976806132394959240819342154566927353181638708426838182688
#hint1: assert(len(n)==155)
#hint2: flag中有待清洗的淤泥
```

上来 factordb 就发现 3 是 n 的一个因子，然后 n//3 也是个素数，还以为 `getPrime(256)` 是来误导的，结果解密之后发现不对

hint1 提示 len(n) 是 155，但是现在 n 的十进制长度只有 154，之后发现这是 RSA-155，末尾少了一个 7，参考网站 [RSA-155](http://www.fact-index.com/r/rs/rsa_155.html)

那就可以解密了

```python
c = 10073137615027377140510981218791415001906117916633551597480408677492183003649126231396950464383049976806132394959240819342154566927353181638708426838182688
p = 102639592829741105772054196573991675900716567808038066803341933521790711307779
q = 106603488380168454820927220360012878679207958575989291522270608237193062808643
n = p * q
phi = (p - 1) * (q - 1)
e = 65537
d = pow(e, -1, phi)
m = pow(c, d, n)
from Crypto.Util.number import long_to_bytes
print(long_to_bytes(m))
```

得到 `b'\xff\x00\x1370xGame{%you_\xef\xbf\xa5have@keen#eyes&for*Crypto!}\x80\x00\x7f\xee'`

根据提示去掉一些东西，尝试几次后得到 `0xGame{youhavekeeneyesforCrypto}`

### [深具传统的ECC之诞生]

week1 从这题开始也是没有附件可以看了...

连上环境发现每次输出都是一样的，就是要解一个 ECDLP

```python
p = 380025560263444925282186340357451425457046895363401263284043
E = EllipticCurve(GF(p), [3, 0])
G = E(89416635389252243162818482998273067753365476637225933437342, 246277781258250668709138589808946483685012465285148814183503)
Q = E(329460413071651533403262472631632126805896556373758724864455, 299273891016902567464505544081763716760408274149519169100436)
n = E.order()
print(factor(n))
# 2^2 * 116869069 * 172348369 * 261535163 * 345477907 * 355841179 * 357636161 * 410202269
```

看了一下发现 E 的阶是光滑的，那就很简单了，直接一步就行了

```python
k = discrete_log(Q, G, operation='+')
```

最后 long_to_bytes 得到 `0xGame{master's touch}`

### 约会大作战

还是发现连上环境发现每次输出都是一样的，p, g, A, B 大概都能猜到是什么意思，应该是一个 DH，需要求出私钥，H 暂时不知道是什么东西

```python
p = 388833750346006219667820785344430140855484475062589057642020739950696608038990565935417569828087468214747408046067
g = 103714720834290513989502874473405218798656206163959233171649809516800750703772779354623632778685213623898889140867
A = 58289858704445358110102862579451926022357279133462645315495234808315843973820504669107180318191167920540051356986
assert 2 <= B <= p - 2
B = [80065171487457769705927728504158709376126756567256739364513810327487907967962500153929065739378045346597405910020, 166653378340666055057947382349710117915658639480023134859369126294840954423961605279375700842287616126770566196501, 384440545326950985920993020618551862830855804814447287772502100479042693748103139473799146827281891605339317880061, 114519017132005897210877691821942933743041961087170580749801669473973246902402011273632564394428116078692753806088, 371845835881215076965045471549644956765616918810284422052915116889386784344665832214305182557329669409692964985029, 357928226677185185644427481691778455471040910649809038526932887640478852274505133357303108936117229783121271409682, 156332351160576873119020393721318979094011078012887335831665204872082055517656572077813474900323578215719447140773, 314815467978756527516294120224950771016495206694908593150103638896270311392510125981994682047930555238986733402915, 167042235735698045535247506124550171039202037878985348672318394764106919883429903606721341281025439118576021113020, 85442934605078905344340853034232658761571489079563924566330695826709850990142222455850294131471963926347636536616, 258815661758707322891907223651910742061711523609296483173958191778726458856064083911944256155238046980986479876340, 121091795135099618184210788583764468665464241414262562492818589316897572436438683499678821540728959535849613348353]
H = ['87f83df23fd993da9953e1a15bdd9bbf474fe25d29cafe5a0b025be6cdf2d417', '35475a482fe1a2e53c047c353805d4b6a17d3ec4087223ac730fb17fad079b41', '5ab5da53341c3d1ef24a48118e528c6853a4adb0da3a894967096ff25c1b4eaa', '30c437e6656f8affc47ef2a223e6fd2f82c79fb9ef98064aebb6c226c90ec5e5', 'a23f2b8e6cfc78c5eb57ce9f6b5283efea0fd7c3a99fbd6761554bd39762cfce', 'bef89885436bb4db645173c8af294fe268417273e6818093db9afbaee65cd43c', 'eeda54eb2b1b4ebe6697b4a2a1c8428c237e6075dd66857b049904b06b4dcc63', 'e99eb62ddd9786ccd741cfdca00ef0c432d96c2204d9c30b3f6a82d46960310c', '7a79ba575c4a70e9cc7ee9478a5dac81fd26ae4056d8836cc9bc30ca7ae0bcf7', '121fc523f07d32950bad3ecb91e122f1a4661e7a7d6b8d612005ad7ee10ba4f2', 'bd14d80fba3b77ef19a748ed1e7e74628f5e8b7575ec86a4f1a84be551305b8d', '6c4938e664739700e30710b0c79620407ca6456c3811ddfa6e4495818b8bc94b']
a =
```

依旧先看看 p-1的分解，发现有小因子；

```python
2 * 1019 * 1021 * 1031 * 1033 * 1039 * 1049 * 1051 * 1061 * 1063 * 1069 * 1087 * 1091 * 107127419953267537834712165532754056682176296465612267395856017589170896397351
```

本想依此把 a 的一部分先求出来，但是发现 g 并不是生成元，其阶为最后的那个大因子 r，故行不通

后发现列表 B 的长度也是 12，而且其中每个 B 的阶对应恰好就是 12 个小素数；结合 H 的形式，猜测其是共享密钥的哈希值，因为有 64 个 hex 字符，猜测是 sha256；故思路就是爆破，根据 H 来验证，最后 CRT 组合

```python
from hashlib import sha256
from Crypto.Util.number import long_to_bytes

F = GF(p)
fac = [1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091]
yu = []
for i in range(12):
    bb = F(B[i])
    n = fac[i]
    for j in range(n):
        tmp = bb^j
        if sha256(long_to_bytes(int(tmp))).hexdigest() == H[i]:
            yu.append(j)
            break
a = crt(yu, fac) # 4864282585427355431495804301385912           
```

验证发现确实是对的；之后进入第二阶段，大意就是给了 A 和 B，自己选一个 m，计算 $M = B^m \pmod p$

使得 `long_to_bytes(M)[-1:]` 为 'A B C' 三个中的一个，这个倒是简单，枚举一下就好了

阴的是每道题看不懂应该选哪个，只能一个个试了

```python
p = 36272096122227019337481487694261510078593805655056412526305801980873014537421657846873843868330284459444115491258807
g = 4
A = ...
B = ...
ans = {}
m = 1
while 1:
    M = pow(B, m, p)
    tmp1 = long_to_bytes(int(M))[-1:]
    if tmp1 in (b'A', b'B', b'C'):
        ans[tmp1] = m
    if len(ans) == 3:
        break
    m += 1
```

最终尝试得到正确答案为 C A C 得到 `0xGame{Master_Origami}`

### 为美好的密码献上解密

发现连上环境发现每次输出的公钥都是一样的

```bash
[+] Welcome to challenge the treasures of the Balkans!
[+] curve = NIST521p
[+] hash = sha512
[+] public_key:
-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBCmmiMNZTXuR44GdzljZErCUcNgf5jpCcPTL31HYx
8EUdoFh4JC+4kUBFxTn7VzuHxFUBLYmNGO1Jow6QqpDfLb0B+2d4vs4wjNqvFZ1ET79VDt1AcgyS
GWX8KlAgizrmIGwXJmp1UfewMhv2f5EDbu3vVU9mf1WeP2aRaDHmG4ryVkg=
-----END PUBLIC KEY-----

[+] hint: k(use in generating the random number k(in the ECDSA formula)is generated by Linear_Feedback_shift_resgister_of_length_five

How many signatures do you want? 1-60:
```

可以指定获取签名的数量，之后的交互是

```bash
Have you decrypted successfully? (y/n): y
nonono,you didn't minimally interact to avoid the monster's sight,and this can get you the answer with minimal interaction
:
```

大致意思好像是要找到最小的数量，之后发现 [0] 和 [31] 的 r 是一样的，那么应该就是传入 32

发现是对的，进入下一阶段，需要伪造一个签名

```bash
Have you decrypted successfully? (y/n): y
[+] Then sign this message for me.
message = the treasure lies hidden within the mirror
[+] The r is fixed.
r = 2661740802050217063228768716723360960729859168756973147706671368418802944996427808491545080627771902352094241225065558662157113545570916814161637315895999846
s =
```

r 复用的话，k 应该也是一样的，根据签名公式
$$
s \equiv k^{-1}(H(m) + rd_A) \pmod n
$$
可以消去 k，求出私钥

```python
from hashlib import sha512
from Crypto.Util.number import bytes_to_long

msg1 = "260bd2c3a48a3bd21443a81a5c49b7c4"
m1 = bytes_to_long(sha512(msg1.encode()).digest())
r1 = 6736120566221017033514492557295196754703301346835173053979889966351344619039955630406780637592198777772367261957524627104144664739928736798974973254899006141
s1 = 6822723206461818108559086117139401505308468220100284405184691669844435672102549286184446452359841893085745328979342089337887110538460202692389937629654768645
msg2 = "04ebde5d12c9fa3a327503bfc242a989"
m2 = bytes_to_long(sha512(msg2.encode()).digest())
r2 = 6736120566221017033514492557295196754703301346835173053979889966351344619039955630406780637592198777772367261957524627104144664739928736798974973254899006141
s2 = 851205795505696861374058751193071028211089475422055378999364749837142609329258544214431815623436798407466043646587117635856045263384425029353837549955716338

n = 6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449
d = (pow(s2, -1, n) * m2 - pow(s1, -1, n) * m1) * pow((r1 * (pow(s1, -1, n) - pow(s2, -1, n))), -1, n) % n
```

伪造签名，但是此时 k 是不知道的，不过不需要解 DLP，因为 r 是曲线的 G 的横坐标，故 k 应该等于 1

```python
message = "the treasure lies hidden within the mirror"
m = bytes_to_long(sha512(message.encode()).digest())
r = 2661740802050217063228768716723360960729859168756973147706671368418802944996427808491545080627771902352094241225065558662157113545570916814161637315895999846
k = 1
s = pow(k, -1, n) * (m + r * d) % n
```

提交后发现不对，故再尝试 k=-1，二者对应的 r 是一致的

最终得到 `0xGame{Offer the decryption for the beautiful password}`

---

回顾一下，`[+] hint: k(use in generating the random number k(in the ECDSA formula)is generated by Linear_Feedback_shift_resgister_of_length_five` 这个东西，我想大概意思是 5 位的 LFSR，最大周期是 $2^5-1=31$，故第 32 个 k 会和第 1 个 k 一致，因此 r 也是一致的

### 四月是你的谎言

依旧发现连上环境每次输出都是一样的

```bash
message = YOU DID LIVE IN MY HEART
hash(key+message) = 46af62962126aa38e4f1680a6c64bc6b
please echo the mission in hash(key+message+response)

new longing:
```

意思应该是现在有了 `hash(key+message)`，要提交一个新的 hash 值 `hash(key+message+response)`

但是不知道 response 是什么东西，题面里说 `就在回应里面在告白后面加上晚来的 TOO吧`

猜测 response 就是 TOO (包括前面的一个空格)

那这应该就是一个哈希长度扩展攻击，hash 是 128 位的，猜测是 md5，而长度扩展攻击是需要考虑 padding 的，故 response = padding + TOO，并不需要知道 key，也能算出新的哈希值

这里就直接用工具 hash_extender 来进行攻击了，命令如下

```bash
./hash_extender \
  --format md5 \
  --data 'YOU DID LIVE IN MY HEART' \
  --signature 46af62962126aa38e4f1680a6c64bc6b \
  --secret 1 \
  --append ' TOO' \
  --out-data-format hex
```

由 md5 的 padding 规则，key 的长度在 1~31 之间扩展出来的哈希都是一样的，先试一下

得到 `1577a52a3a88f80645a7e977801ae5d2`

是正确的，提交得到 flag `0xGame{you lie in April}`

## Week2

### 群友群友群？

一个古典密码，给了 ciphertext.jpg 和 hint.jpg

结合 hint.jpg 的内容 "猪" 和题目描述不难猜到是猪圈密码，实际上是个变种猪圈密码，可以参考

[CTF密码学中的一些常用图形密码 - Kicky_Mu - 博客园](https://www.cnblogs.com/mumuhhh/articles/17774458.html)

对照解密得到

```
WELCOME
TO
SIGNUP
```

故 flag 就是 `0xGame{WELCOMETOSIGNUP}`

看题目描述以为还有一层栅栏密码，实际上没有

### 命运石之门

```python
from Crypto.Cipher import AES
from base64 import b64decode

KEY = bytes.fromhex("185608cdb3409b141aa6812757d41cc9")
IV = bytes.fromhex("2d1aed23dff9f1f2e30836642237a752")

conditions = {
    8: 85,
    30: 108,
    41: 50,
    63: 122,
    67: 115,
    91: 75,
    104: 103,
    122: 90,
    143: 52,
}

try:
    c2 = b64decode(input("c2.encode('base64')=").strip(), validate=True)
    if len(c2) != 256:
        raise ValueError

    m2 = AES.new(KEY, AES.MODE_CBC, IV).decrypt(c2)
    if not all(m2[pos] == value for pos, value in conditions.items()):
        raise ValueError
    
    from secret import flag
    print(flag)

except Exception:
    print("失败了失败了失败了...")
```

依旧没看懂这是什么梗，不过题目还是挺简单的

key 和 iv 都给了，需要提交一个密文，使得解密后明文指定位置是指定的值，那直接随便构造一个满足的明文再加密一下就行了

```python
from Crypto.Cipher import AES
from base64 import b64encode

KEY = bytes.fromhex("185608cdb3409b141aa6812757d41cc9")
IV = bytes.fromhex("2d1aed23dff9f1f2e30836642237a752")
m2 = [0] * 256
conditions = {
    8: 85,
    30: 108,
    41: 50,
    63: 122,
    67: 115,
    91: 75,
    104: 103,
    122: 90,
    143: 52,
}
for i, j in conditions.items():
    m2[i] = j
c2 = AES.new(KEY, AES.MODE_CBC, IV).encrypt(bytes(m2))
print(b64encode(c2))
# 8uJo1BMdtCthdd/Sdn06A3BuYbyEZN4GUolQRgimgW96K9bu4Hm262JxmhUDOUoCiZe0SIPYR10YvwwNyYDqbiZqe06o9CT6WAsNbbKIrLeTuXF7bJ/xEmLlI+erSDegFrrcXrawJ3Dhan4IivjRMq0ZydyT/40dAuZyYb7QLBptDF9qbotCUZxaLhwznnWO5beLwrgzMpvM8WimadIf2N2abMYTJ5qkAhMlWWnaeaeVNFftetCLMow/fE0cE1Hne5eGxDxxgPK5U98Rp0bNc6ufAEVgRVKoyS6C1NRQD4FWBs+L4FqwAeFE3nKGGXkZn/PFFZEozs8Z1nKurXCP/Q==
```

提交即可得到 flag `0xGame{th15 15 my v1ct0ry}`

1.048596 文件里似乎是给了一个例子？但是没法直接用，不知道具体有什么用

### 夏天仍未结束

这里是非预期解法，附件太杂了，就不放了

烟火.md 内说明了任务是要恢复原始音频，是一个可以播放的 FLAC 文件

此外，里面说了对于附件中的两个容器，将其拼接后结构如下

```
QFLAC2 标识 | 小端序长度 | JSON manifest | FLAC 元数据 | 加密数据
```

需要提交的是 "解密后识别直接包裹0xGame{}"，FLAC 元数据是没有加密的，里面可能有信息

先用脚本提取一下数据

```python
import io
import json

with open("quantum_echo1.qflac", "rb") as f:
    data = f.read()
with open("quantum_echo2.qflac", "rb") as f:
    data += f.read()
f = io.BytesIO(data)
assert f.read(8) == b"QFLAC2\x00\x00"
manifest_len = int.from_bytes(f.read(4), "little")
manifest = json.loads(f.read(manifest_len))
metadata_len = int.from_bytes(f.read(4), "little")
flac_metadata = f.read(metadata_len)
```

然后直接查看元数据

```python
print(repr(flac_metadata.decode("utf-8", errors="ignore")[:1000]))
```

其中可以清楚的看到 `Title=打上花火`

提交  `0xGame{打上花火}` 发现是对的

实际预期解法就是一个密钥复用的异或加密，其中一个明文已知。然后套了一堆乱七八糟的东西进去...

### 契约之吻

```python
from random import randrange
from secret import f_coeffs, s_coeffs, error

d = 64
scale = 2^44
n = 24
p = 2147483647

secret = vector(ZZ, [f_coeffs[i] if i < len(f_coeffs) else (1 if i == n else 0) for i in range(d)])
mt = matrix(ZZ, [[randrange(0, scale) for _ in range(d)] for _ in range(d)])
mt[0] = [i for i in secret]

new_mt = matrix(ZZ, d)
for i in range(d):
    row = random_vector(ZZ, d, x=257)
    for j in range(i):
        row[j] = 0
    row[i] = 1
    new_mt[i] = row * mt

H = new_mt

R.<x> = PolynomialRing(ZZ)
F = x^n + sum(f_coeffs[i] * x^i for i in range(len(f_coeffs)))
A = vector(ZZ, [1624513444, 7887634, 1850144002, 1333320193, 1148549154, 28619938, 1601341874, 353058494, 224962944, 1491387826, 612016532, 1078815215, 1270428426, 748164318, 1219377558, 1238933391, 1824650003, 469831872, 712295407, 559376837, 1804640269, 1147167506, 818193445, 1043390130])
a = sum(A[i] * x^i for i in range(n))
M_A = matrix(ZZ, n, n)
for j in range(n):
    col = (a * x^j) % F
    for i in range(n):
        M_A[i, j] = col[i]

B = (M_A * vector(ZZ, s_coeffs) + vector(ZZ, error)).apply_map(lambda v: v % p)
```

这题倒是相对常规一些，因为还有不少东西是需要猜的。mt 第一行是 secret，其余就是随机元素，记为 M，然后进行了计算
$$
H = R\cdot M
$$
实际上 H 的每一个行向量都是 M 的行向量的线性组合，并且组合系数矩阵 R 可逆，也就是说 H 和 M 张成的线性空间是一样的；猜测 M 的第一行是个短向量，故对 H 做 LLL 就能恢复出来，也就是 f_coeffs

然后下面就是个 LWE 问题 $b=As + e \pmod p $了，但是从始至终没出现 flag，故猜测 s_coeffs 的内容就是 flag；那说明 s 和 e 都不大，用这个格就能恢复出 s 和 e 
$$
\begin{pmatrix}
I_n &   & A^{\mathrm T} \\
    & 1 & -\mathbf{b} \\
    &   & qI_m
\end{pmatrix}
$$

```python
H = ...
A = ...
B = ...
n = 24
p = 2147483647

R.<x> = PolynomialRing(ZZ)
f_coeffs = -H.LLL()[0][:24]
F = x^n + sum(f_coeffs[i] * x^i for i in range(len(f_coeffs)))
a = sum(A[i] * x^i for i in range(n))
M_A = matrix(ZZ, n, n)
for j in range(n):
    col = (a * x^j) % F
    for i in range(n):
        M_A[i, j] = col[i]
        
def primal_attack1(A,b,m,n,p,esz):
    L = block_matrix(
        [
            [matrix.identity(m)*p,matrix.zero(m, n+1)],
            [(matrix(A).T).stack(-vector(b)).change_ring(ZZ),matrix.identity(n+1)],
        ]
    )
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

s = primal_attack1(M_A, B, n, n, p, 3)
for i in s:
    try:
        print(chr(i), end='')
    except:
        pass
# 0xGame{kiss then kill}
```

### charlotte

同样，附件太杂了，就不放了

给了三个不完整的 RSA 私钥文件，先提取下有用信息。base64 decode 之后读取数据，发现模数 n 相同，而且可以完整读取；第一段和第二段只能读出 e 的高位部分，第三段的 e 可以完整读取

即
$$
e_1=e_{1\mathrm{high}}\cdot 2^{256}+x,\qquad
e_2=e_{2\mathrm{high}}\cdot 2^{256}+y,
\quad 0\le x,y<2^{256}
$$
此外给的信息是
$$
\text{fingerprint} \equiv e^3 \pmod n
$$
二者结合很明显是个小根问题，可以用 Coppersmith

```python
n = ...
e1_high = ...
e2_high = ...
e3 = ...
fingerprint_1 = ...
fingerprint_2 = ...

R.<x> = PolynomialRing(Zmod(n))
def solve_e(high, fingerprint):
    base = high << 256
    f = (base + x)^3 - fingerprint
    roots = f.small_roots(X=2^256, beta=1, epsilon=1/10)[0]
    return base + roots
e1 = int(solve_e(e1_high, fingerprint_1))
e2 = int(solve_e(e2_high, fingerprint_2))
```

接下来利用 `private_exponent_bits = 384`，这肯定是小私钥攻击，但是直接用维纳攻击这里不行；而且给了三组，不是三个独立的维纳攻击，而是要结合在一起，是一个扩展维纳攻击

其实和 moectf 2025 的 [wiener++] 这个题一样了，代码可以参考 [wiener attack 笔记 | 独奏の小屋](https://hasegawaazusa.github.io/wiener-attack.html#脚本-1)

d 是 384 位，则 $d < N^\alpha$ α 取 0.4 即可

```python
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

c = ...
d = pow(e1 * e2 * e3, -1, phi)
m = pow(c, d, n)
from Crypto.Util.number import long_to_bytes
print(long_to_bytes(m))
# 0xGame{Welcome home}
```

### 老师傅的波纹

全场唯一看上去正常的题，不过可惜没有 get 到出题人的点。

```python
from secrets import flag
from Crypto.Util.number import getPrime
BITS = 80
a = int(flag[5:-1], 16)
p = getPrime(BITS)
while True:
    A = ZZ(randrange(1, p))
    B = ZZ(randrange(1, p))
    if (4 * A^3 + 27 * B^2) % p == 0:
        continue
    E = EllipticCurve(GF(p), [A, B])
    n = E.order()
    if is_prime(n) and n != p and n != p + 1:
        break
G = E.random_point()
Q = a * G
print(f"p = {p}")
print(f"A = {A}")
print(f"B = {B}")
print(f"n = {n}")
print(f"G = ({ZZ(G.xy()[0])}, {ZZ(G.xy()[1])})")
print(f"Q = ({ZZ(Q.xy()[0])}, {ZZ(Q.xy()[1])})")
# p = 1208925819614629174270411
# A = 183150304136760995950581
# B = 794569627338707454052582
# n = 1208925819612932406971299
# G = (181528231928396052728802, 1540136182689226613050)
# Q = (339758143822552101710854, 503250777866725616991088)
```

题目给出椭圆曲线及 $Q=aG$，要求恢复 a。群阶 n 是约 $2^{80}$ 的素数，因此非零点 G 的阶就是 n。常规题型，如无效曲线，光滑数等等都被排除在外了。

故只能采用 Pollard ρ 暴力求解，预期需要 $O(\sqrt n)$，即约 $2^{40}$ 量级的群运算。

这题是让 AI 写的 cpp 爆破脚本做的，加了一些优化来提速，最后跑了 3 个小时出的结果，这里就不放了，因为我也没看懂...

### None game None life zero!

```
lfsr.py
mt19937.py
ot.py
protocol.py
```

这个题没做，应该是和伪随机数相关的。四个附件，浓浓的 AIGC 味道，实在没有看的欲望，略了。



**后记**

AI 对 CTF 的冲击不仅在于做题方面，出题也是，这点在之前 moe 出题的时候就有所体会了。其他方向可能还好一些，对于 crypto，我觉得面对 AI 出的题和人出的题，感受是完全不一样的，因为绝大多数情况下，选手就是在和 challenge.py 打交道，实际上就是一眼丁真了。不过，这是新生赛，新生可能没有这个概念，让新生在一开始就以这种形式接触，是好还是坏呢？我也不知道...

这是我打 CTF 第二年打的第一个新生赛，也会是最后一个新生赛了，得把时间花在刀刃上了。以后也要改变策略了，看到是 AIGC 的题，直接让 AI 做就完事了。虽然我估计 CTF 本身也会越打越少了，x_x

