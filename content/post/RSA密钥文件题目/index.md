+++
title = "RSA密钥文件题目"
date = "2025-11-16"
description = "RSA之.key文件或.pem文件简单总结"
categories = ["学习记录"]
tags = ["总结"]
image="123.png"
+++





# RSA密钥文件有关题目

**前言**

做RSA的时候有时候会遇到这种题目：给了一个.key文件或者.pem文件，但由于不清楚其格式是什么样的，一头雾水，所以这里结合一个例子仔细分析了一下密钥文件，主要是私钥文件的内容格式，最后附了几道题加深理解

**省流**

这种题本质上还是基础题型的RSA，只是多了两步，首先需要从文件中提取数据，最后需要考虑加密格式来解密

解密时优先考虑用cyberchef

常用命令
```
openssl rsa -in private.key -text -noout # 查看
openssl pkeyutl -decrypt -in flag.txt -inkey private.key -out out.txt # 解密
```

## 密钥(私钥，公钥)证书格式

私钥证书内容格式

```
RSAPrivateKey ::= SEQUENCE {
    version           Version,     0表示两个素数的RSA  1表示多素数的RSA
    modulus           INTEGER,  -- n
    publicExponent    INTEGER,  -- e
    privateExponent   INTEGER,  -- d
    prime1            INTEGER,  -- p
    prime2            INTEGER,  -- q
    exponent1         INTEGER,  -- d mod (p-1)
    exponent2         INTEGER,  -- d mod (q-1)
    coefficient       INTEGER,  -- (inverse of q) mod p
    otherPrimeInfos   OtherPrimeInfos OPTIONAL
}
```


一个私钥证书示例(private.key)

```
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCsWryPAQj9cp1O9UDVRQEWg3k7dsQfalNs8Xa4/ZOsTVvWwfu6
EPWbr3av5ewn/SCWqJbltLaJd122sBH1lcPygyxTtkQvPCamnVdtN+3qzZ0VxZkT
i7jaoR+SPgsPEiCZYN0JsJ104A0SZ0bXtAslmpIc4sE/+kqHSd5dfZmHVQIDAQAB
AoGBAKXl6N2VV3vtmLFprHAcLYHoJwcvuHOsuoSAn5BMtJoDFEVRDuX4cRDcAdgp
7fhH09hwil6sZY9IEDJKo97Ju4LcjrT3UtOGXWJOeEZCJHfP5s/62/2lZCAHjK3G
V1udujf1K0g0M0RcZLE41Rep8zKj/ASr4cmXkQgEgZ4gsII5AkEA1BP03n7liHYj
9SMoUVGceGtBhvyfVjzU74q1TFpmhWzQ3/hMqIfI498I5+voPBnFJj1Op1aE2wHH
RVKtnlqW3wJBANAMs3TXKCTP/cJm0LRXttzXgpID/jkY4e0KHZhpuJdkbBFs+Z1Z
BxfgfHwXVO17O1VOwZZNf2uh//oeFqH/LEsCQEJ70xrhCxHhf1o84EnF3Nh/PzaT
AVxmi5ZglH9QI62WNFDSJS38C0UsST1zXgVhSsW3GG4rGFET2KVpytXGrl8CQHS1
a0Y0HFTqSJPxUUqZmf8w9hIrI0Wsa7CpaAjD5cUnlGgCFdTqyEvgpnSGMiI2awZj
87z5JG2gpxQMJO4jUxkCQBiGHY58w0/yuRRr6HnAbF1LiS7JzedbXK3f3vO/IhMs
jZPBfOdeQyWnih3FT83o+L/u+PfUIEy9iaz0+KriuHQ=
-----END RSA PRIVATE KEY-----
```

是base64编码后的内容，base64解码，下面是测试代码

```python
import base64

s = """
MIICXAIBAAKBgQCsWryPAQj9cp1O9UDVRQEWg3k7dsQfalNs8Xa4/ZOsTVvWwfu6
EPWbr3av5ewn/SCWqJbltLaJd122sBH1lcPygyxTtkQvPCamnVdtN+3qzZ0VxZkT
i7jaoR+SPgsPEiCZYN0JsJ104A0SZ0bXtAslmpIc4sE/+kqHSd5dfZmHVQIDAQAB
AoGBAKXl6N2VV3vtmLFprHAcLYHoJwcvuHOsuoSAn5BMtJoDFEVRDuX4cRDcAdgp
7fhH09hwil6sZY9IEDJKo97Ju4LcjrT3UtOGXWJOeEZCJHfP5s/62/2lZCAHjK3G
V1udujf1K0g0M0RcZLE41Rep8zKj/ASr4cmXkQgEgZ4gsII5AkEA1BP03n7liHYj
9SMoUVGceGtBhvyfVjzU74q1TFpmhWzQ3/hMqIfI498I5+voPBnFJj1Op1aE2wHH
RVKtnlqW3wJBANAMs3TXKCTP/cJm0LRXttzXgpID/jkY4e0KHZhpuJdkbBFs+Z1Z
BxfgfHwXVO17O1VOwZZNf2uh//oeFqH/LEsCQEJ70xrhCxHhf1o84EnF3Nh/PzaT
AVxmi5ZglH9QI62WNFDSJS38C0UsST1zXgVhSsW3GG4rGFET2KVpytXGrl8CQHS1
a0Y0HFTqSJPxUUqZmf8w9hIrI0Wsa7CpaAjD5cUnlGgCFdTqyEvgpnSGMiI2awZj
87z5JG2gpxQMJO4jUxkCQBiGHY58w0/yuRRr6HnAbF1LiS7JzedbXK3f3vO/IhMs
jZPBfOdeQyWnih3FT83o+L/u+PfUIEy9iaz0+KriuHQ=
"""
s1 = base64.b64decode(s)
print(s1.hex())
```
私钥证书在十六进制下的一些格式

```
3082xxxx  #30是开始的标志  82表示接下来两个字节代表长度 
020100    #02是整数的标志  01表示这个整数占1个字节  00表示值为0x00=0  即两个素数的RSA
028181    #02是整数的标志  中间的81代表后面一个跟着一个单字节长度  最后的81代表长度为0x81字节
0203      #02是整数的标志  03表示长度为3个字节
0241      #02是整数的标志  41表示长度为0x41个字节
```

这里涉及到一个ASN.1 结构中的长度编码规则，具体地<br >

- 短格式：长度 ≤ 127(即7F)，直接用1字节表示长度<br >
- 长格式：长度 > 127(即7F)，用(0x80 + 后续字节数)，然后是实际长度<br >

结合上面<br >
短格式的例子：0241，表示有0x41个字节<br >
长格式的例子：028181，表示有0x81个字节；3082025c，表示有0x025c个字节<br >


在打印出s1.hex后，结合上面的格式将其分割，'||'是我添加的，原来没有
```
'3082025c' # 开始的标志，此后一共有0x025c个字节(不包括这4个字节)
'020100'   # 02是整数的标志  01表示这个整数占1个字节  00表示值为0x00=0  即两个素数的RSA
'028181||00ac5abc8f0108fd729d4ef540d545011683793b76c41f6a536cf176b8fd93ac4d5bd6c1fbba10f59baf76afe5ec27fd2096a896e5b4b689775db6b011f595c3f2832c53b6442f3c26a69d576d37edeacd9d15c599138bb8daa11f923e0b0f12209960dd09b09d74e00d126746d7b40b259a921ce2c13ffa4a8749de5d7d998755' # 028181表示0x81字节的整数 即n
'0203||010001' # 表示3字节整数 即e
'028181||00a5e5e8dd95577bed98b169ac701c2d81e827072fb873acba84809f904cb49a031445510ee5f87110dc01d829edf847d3d8708a5eac658f4810324aa3dec9bb82dc8eb4f752d3865d624e7846422477cfe6cffadbfda56420078cadc6575b9dba37f52b483433445c64b138d517a9f332a3fc04abe1c997910804819e20b08239' # 表示0x81字节整数 即d
'0241||00d413f4de7ee5887623f5232851519c786b4186fc9f563cd4ef8ab54c5a66856cd0dff84ca887c8e3df08e7ebe83c19c5263d4ea75684db01c74552ad9e5a96df' # 表示0x41字节整数 即p
'0241||00d00cb374d72824cffdc266d0b457b6dcd7829203fe3918e1ed0a1d9869b897646c116cf99d590717e07c7c1754ed7b3b554ec1964d7f6ba1fffa1e16a1ff2c4b' # 表示0x41字节整数 即q
'0240||427bd31ae10b11e17f5a3ce049c5dcd87f3f3693015c668b9660947f5023ad963450d2252dfc0b452c493d735e05614ac5b7186e2b185113d8a569cad5c6ae5f' # 表示0x40字节整数 即dp
'0240||74b56b46341c54ea4893f1514a9999ff30f6122b2345ac6bb0a96808c3e5c52794680215d4eac84be0a674863222366b0663f3bcf9246da0a7140c24ee235319' # 表示0x40字节整数 即dq
'0240||18861d8e7cc34ff2b9146be879c06c5d4b892ec9cde75b5caddfdef3bf22132c8d93c17ce75e4325a78a1dc54fcde8f8bfeef8f7d4204cbd89acf4f8aae2b874' # 表示0x40字节整数 即 q^(-1) mod p
```

我们可以用openssl验证<br >

用命令`openssl rsa -in private.key -text -noout`，得到输出，和上面的结果是一样的
```
Private-Key: (1024 bit, 2 primes)
modulus:
    00:ac:5a:bc:8f:01:08:fd:72:9d:4e:f5:40:d5:45:
    01:16:83:79:3b:76:c4:1f:6a:53:6c:f1:76:b8:fd:
    93:ac:4d:5b:d6:c1:fb:ba:10:f5:9b:af:76:af:e5:
    ec:27:fd:20:96:a8:96:e5:b4:b6:89:77:5d:b6:b0:
    11:f5:95:c3:f2:83:2c:53:b6:44:2f:3c:26:a6:9d:
    57:6d:37:ed:ea:cd:9d:15:c5:99:13:8b:b8:da:a1:
    1f:92:3e:0b:0f:12:20:99:60:dd:09:b0:9d:74:e0:
    0d:12:67:46:d7:b4:0b:25:9a:92:1c:e2:c1:3f:fa:
    4a:87:49:de:5d:7d:99:87:55
publicExponent: 65537 (0x10001)
privateExponent:
    00:a5:e5:e8:dd:95:57:7b:ed:98:b1:69:ac:70:1c:
    2d:81:e8:27:07:2f:b8:73:ac:ba:84:80:9f:90:4c:
    b4:9a:03:14:45:51:0e:e5:f8:71:10:dc:01:d8:29:
    ed:f8:47:d3:d8:70:8a:5e:ac:65:8f:48:10:32:4a:
    a3:de:c9:bb:82:dc:8e:b4:f7:52:d3:86:5d:62:4e:
    78:46:42:24:77:cf:e6:cf:fa:db:fd:a5:64:20:07:
    8c:ad:c6:57:5b:9d:ba:37:f5:2b:48:34:33:44:5c:
    64:b1:38:d5:17:a9:f3:32:a3:fc:04:ab:e1:c9:97:
    91:08:04:81:9e:20:b0:82:39
prime1:
    00:d4:13:f4:de:7e:e5:88:76:23:f5:23:28:51:51:
    9c:78:6b:41:86:fc:9f:56:3c:d4:ef:8a:b5:4c:5a:
    66:85:6c:d0:df:f8:4c:a8:87:c8:e3:df:08:e7:eb:
    e8:3c:19:c5:26:3d:4e:a7:56:84:db:01:c7:45:52:
    ad:9e:5a:96:df
prime2:
    00:d0:0c:b3:74:d7:28:24:cf:fd:c2:66:d0:b4:57:
    b6:dc:d7:82:92:03:fe:39:18:e1:ed:0a:1d:98:69:
    b8:97:64:6c:11:6c:f9:9d:59:07:17:e0:7c:7c:17:
    54:ed:7b:3b:55:4e:c1:96:4d:7f:6b:a1:ff:fa:1e:
    16:a1:ff:2c:4b
exponent1:
    42:7b:d3:1a:e1:0b:11:e1:7f:5a:3c:e0:49:c5:dc:
    d8:7f:3f:36:93:01:5c:66:8b:96:60:94:7f:50:23:
    ad:96:34:50:d2:25:2d:fc:0b:45:2c:49:3d:73:5e:
    05:61:4a:c5:b7:18:6e:2b:18:51:13:d8:a5:69:ca:
    d5:c6:ae:5f
exponent2:
    74:b5:6b:46:34:1c:54:ea:48:93:f1:51:4a:99:99:
    ff:30:f6:12:2b:23:45:ac:6b:b0:a9:68:08:c3:e5:
    c5:27:94:68:02:15:d4:ea:c8:4b:e0:a6:74:86:32:
    22:36:6b:06:63:f3:bc:f9:24:6d:a0:a7:14:0c:24:
    ee:23:53:19
coefficient:
    18:86:1d:8e:7c:c3:4f:f2:b9:14:6b:e8:79:c0:6c:
    5d:4b:89:2e:c9:cd:e7:5b:5c:ad:df:de:f3:bf:22:
    13:2c:8d:93:c1:7c:e7:5e:43:25:a7:8a:1d:c5:4f:
    cd:e8:f8:bf:ee:f8:f7:d4:20:4c:bd:89:ac:f4:f8:
    aa:e2:b8:74
```

> 一个由私钥恢复公钥的网站[在线RSA公钥恢复工具](https://rtcd.io/zh-cn/rsa-pubkey-recovery/)<br >


类似地，读取公钥文件的命令`openssl rsa -in public.key -pubin -text -noout`，略有不同<br >

输出结果内容比私钥文件少很多，只有n和e<br >

```
Public-Key: (1024 bit)
Modulus:
    00:ac:5a:bc:8f:01:08:fd:72:9d:4e:f5:40:d5:45:
    01:16:83:79:3b:76:c4:1f:6a:53:6c:f1:76:b8:fd:
    93:ac:4d:5b:d6:c1:fb:ba:10:f5:9b:af:76:af:e5:
    ec:27:fd:20:96:a8:96:e5:b4:b6:89:77:5d:b6:b0:
    11:f5:95:c3:f2:83:2c:53:b6:44:2f:3c:26:a6:9d:
    57:6d:37:ed:ea:cd:9d:15:c5:99:13:8b:b8:da:a1:
    1f:92:3e:0b:0f:12:20:99:60:dd:09:b0:9d:74:e0:
    0d:12:67:46:d7:b4:0b:25:9a:92:1c:e2:c1:3f:fa:
    4a:87:49:de:5d:7d:99:87:55
Exponent: 65537 (0x10001)
```

我们看看base64解码后的内容，没有问题

```
'30819f' # 开始的标志，此后一共有0x9f个字节(不包括这3个字节)
'300d06092a864886f70d010101050003818d00308189' # 一些配置和参数，不是很重要
'028181||00ac5abc8f0108fd729d4ef540d545011683793b76c41f6a536cf176b8fd93ac4d5bd6c1fbba10f59baf76afe5ec27fd2096a896e5b4b689775db6b011f595c3f2832c53b6442f3c26a69d576d37edeacd9d15c599138bb8daa11f923e0b0f12209960dd09b09d74e00d126746d7b40b259a921ce2c13ffa4a8749de5d7d998755' # 表示0x81字节整数 即n
'0203||010001' # 3字节整数，即e
```

至此，RSA密钥证书的格式已经基本摸清楚了，下面看看例题吧

## T1
应当是最基础的一种类型，给了一个private.key文件和一个存密文的flag.txt<br >
我上面分析的例子就是这个private.key文件的内容，可见其是完整的，各种参数都有<br >
flag.txt直接打开不出意外是乱码，因为明文加密后得到一个大整数，转为字节序列(方法和bytes_to_long一样)存在txt中，不过不影响，用代码二进制模式读取即可<br >
有两种方法解决，第一种是把d拿过来自己写一个脚本，第二种则是用openssl直接解密

### 方法一
exp
```python
from Crypto.Util.number import long_to_bytes, bytes_to_long
with open('flag.txt', 'rb') as f:
    c = f.read()
c = bytes_to_long(c)
d = '00a5e5e8dd95577bed98b169ac701c2d81e827072fb873acba84809f904cb49a031445510ee5f87110dc01d829edf847d3d8708a5eac658f4810324aa3dec9bb82dc8eb4f752d3865d624e7846422477cfe6cffadbfda56420078cadc6575b9dba37f52b483433445c64b138d517a9f332a3fc04abe1c997910804819e20b08239'
n = '00ac5abc8f0108fd729d4ef540d545011683793b76c41f6a536cf176b8fd93ac4d5bd6c1fbba10f59baf76afe5ec27fd2096a896e5b4b689775db6b011f595c3f2832c53b6442f3c26a69d576d37edeacd9d15c599138bb8daa11f923e0b0f12209960dd09b09d74e00d126746d7b40b259a921ce2c13ffa4a8749de5d7d998755'
d = int(d, 16)
n = int(n, 16)
m = pow(c, d, n)
print(long_to_bytes(m))
```
输出结果
```
b"\x02\r\x83\xb1\xd4\x08\xfd!\x13\x8e\xd9\x98\xd8A\x88\x1a\xae\x02'\xf1_\xd0Z(m\x01s\xa4\xe9\x06`\xaf\xe0\xe7\xb6\x9bF\xc1\x12?\x7f\x08\x95.\xc9\x8f.\x8e\xf1\xefx-W\xf9\t\x1d8|\x85R\x03M\xf47\xcd\xb3\xff\xd5\x9ag-\x19\xb9\x92Y\x06\xc5\xe3\xc1[\xe1\xa8%\xf1\x86V\xee\x9a\x00flag{57c2f8cf484134e31167e294cc8441c3}"
```
得到`flag{57c2f8cf484134e31167e294cc8441c3}`，不过前面有一些奇怪的填充

### 方法二

密钥证书完整，直接用命令，也可以得到flag，没有奇怪的填充🤔
```bash
$ openssl pkeyutl -decrypt -in flag.txt -inkey private.key -out out.txt
$ cat out.txt
flag{57c2f8cf484134e31167e294cc8441c3}
```
## T2

T1的方法一解密结果的填充我一开始并没有太在意，只关注了flag，好巧不巧又遇到了一道题

同样是给了一个完整的私钥pem文件和一个enc文件存密文，那岂不是和上面一毛一样？

结果是用方法一自己写脚本没问题，但是方法二直接openssl出来的结果相去甚远，遂询问ai

得知OpenSSL默认使用PKCS#1 v1.5填充，其格式大概是这样子的

```
00 02 [随机填充] 00 [实际数据]

00：起始字节
02：表示这是加密块
随机填充：至少8个非零字节
00：分隔符
实际数据：真正的明文
```

> 00 02 [随机填充] 00 [实际数据] # 我查到的大部分都是这样的<br >
> 00 02 [随机填充] FF [实际数据] # 也有资料是这样的


大概流程是这样的，依然是把密文文件的字节串转大整数(这一步都一样)，然后计算c的d次方模n，得到大整数m1，然后转字节串，去找上面的标志位(\x00 \x02这些)，最后拿出真正的明文

而这个题其密文文件在由明文加密而来时是没有使用PKCS#1 v1.5填充的，就是纯粹的直接计算，因此解密后的结果中找不到对应的标志位，openssl默认解密结果就不对

解决办法有三种，其一就是自己写脚本，其本质上就是不考虑填充

第二稍微修改命令加一个参数`openssl pkeyutl -decrypt -in enc -inkey key.pem -out out.txt -pkeyopt rsa_padding_mode:none`

第三用cyberchef选择模式也可以正常解密(自然而然地，T1也可以用cyberchef)

## T1-续

知道了PKCS#1 v1.5这一事实后，T1的问题就可以解决了

```
b"\x02\r\x83\xb1\xd4\x08\xfd!\x13\x8e\xd9\x98\xd8A\x88\x1a\xae\x02'\xf1_\xd0Z(m\x01s\xa4\xe9\x06`\xaf\xe0\xe7\xb6\x9bF\xc1\x12?\x7f\x08\x95.\xc9\x8f.\x8e\xf1\xefx-W\xf9\t\x1d8|\x85R\x03M\xf47\xcd\xb3\xff\xd5\x9ag-\x19\xb9\x92Y\x06\xc5\xe3\xc1[\xe1\xa8%\xf1\x86V\xee\x9a\x00flag{57c2f8cf484134e31167e294cc8441c3}"
```

正是`00 02 [随机填充] 00 [实际数据]`的格式，用openssl默认提取最后\x00后的flag

什么？你说开头怎么不是\x00，那是因为m = pow(c, d, n)计算出的m最高位的0被省略了，因此long_to_bytes(m)的时候，最高位的\x00也被省略了，上面的输出结果是127字节，少的那1个字节正是省略的\x00

## T3

这个题给了一个broken_sk.pem文件和一个secret.enc文件<br >
broken_sk.pem内容如下，是不完整的

```
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQIDAQABAoIBABMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAG8CgYEA0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJeb90PpxojA50U2EDfCfDcCgYEA9AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIcCgYEArRm/+wIkn36m4NO4ydBcX338mdBciA2Jr6bFLFnNELVprOnugAlz7Z3Dj6wt7Zut/9KPq82Ah7tb+H5qVxMcym7FVa0RSoMi8ud91Z8y+h1hEwE8jka9O3FyXijkQldf7W/BwfjbomfIxmsZLrnn9pKrhXvXoN7MuxITkIH1iz0CgYEA1ppidZzdVeIsDdnoHjqemwiRB6o5pgdgFbPpIseZAy7wTOqLIQBS8LWglPcPu8/rBRZazGnWJ8tBAw9MPQNKEucRhCSYHe01A4nsgwrWk+YMGw5+imUZvvahgfW+kq+LAETI0LhCcOM0xZATjD6d+aKeya9F2wXwxEOx4JYjnTUCgYAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADvyaZUzJ3fr3oVuWx3LDMbY/aQlg==
-----END RSA PRIVATE KEY-----
```

这时候我们尝试用openssl命令`openssl rsa -in broken_sk.pem -text -noout`读取，内容如下

```
Private-Key: (2048 bit, 2 primes)
modulus:
    00:c9:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:01
publicExponent: 65537 (0x10001)
privateExponent:
    13:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    6f
prime1:
    00:d0:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:97:9b:f7:43:e9:c6:88:
    c0:e7:45:36:10:37:c2:7c:37
prime2:
    00:f4:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:87
exponent1:
    00:ad:19:bf:fb:02:24:9f:7e:a6:e0:d3:b8:c9:d0:
    5c:5f:7d:fc:99:d0:5c:88:0d:89:af:a6:c5:2c:59:
    cd:10:b5:69:ac:e9:ee:80:09:73:ed:9d:c3:8f:ac:
    2d:ed:9b:ad:ff:d2:8f:ab:cd:80:87:bb:5b:f8:7e:
    6a:57:13:1c:ca:6e:c5:55:ad:11:4a:83:22:f2:e7:
    7d:d5:9f:32:fa:1d:61:13:01:3c:8e:46:bd:3b:71:
    72:5e:28:e4:42:57:5f:ed:6f:c1:c1:f8:db:a2:67:
    c8:c6:6b:19:2e:b9:e7:f6:92:ab:85:7b:d7:a0:de:
    cc:bb:12:13:90:81:f5:8b:3d
exponent2:
    00:d6:9a:62:75:9c:dd:55:e2:2c:0d:d9:e8:1e:3a:
    9e:9b:08:91:07:aa:39:a6:07:60:15:b3:e9:22:c7:
    99:03:2e:f0:4c:ea:8b:21:00:52:f0:b5:a0:94:f7:
    0f:bb:cf:eb:05:16:5a:cc:69:d6:27:cb:41:03:0f:
    4c:3d:03:4a:12:e7:11:84:24:98:1d:ed:35:03:89:
    ec:83:0a:d6:93:e6:0c:1b:0e:7e:8a:65:19:be:f6:
    a1:81:f5:be:92:af:8b:00:44:c8:d0:b8:42:70:e3:
    34:c5:90:13:8c:3e:9d:f9:a2:9e:c9:af:45:db:05:
    f0:c4:43:b1:e0:96:23:9d:35
coefficient:
    20:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:ef:c9:a6:54:cc:9d:df:af:7a:15:b9:6c:
    77:2c:33:1b:63:f6:90:96
```

好了，到这里清楚的看出来就是一个dp，dq泄露的问题，e已知，n未知

[参考]([密码技术能力提升题目练习](https://hataovo.github.io/p/密码技术能力提升题目练习/#rsa5))，恢复出p和q

exp

```python
from Crypto.Util.number import isPrime

tmp11 = '''
00:ad:19:bf:fb:02:24:9f:7e:a6:e0:d3:b8:c9:d0:
5c:5f:7d:fc:99:d0:5c:88:0d:89:af:a6:c5:2c:59:
cd:10:b5:69:ac:e9:ee:80:09:73:ed:9d:c3:8f:ac:
2d:ed:9b:ad:ff:d2:8f:ab:cd:80:87:bb:5b:f8:7e:
6a:57:13:1c:ca:6e:c5:55:ad:11:4a:83:22:f2:e7:
7d:d5:9f:32:fa:1d:61:13:01:3c:8e:46:bd:3b:71:
72:5e:28:e4:42:57:5f:ed:6f:c1:c1:f8:db:a2:67:
c8:c6:6b:19:2e:b9:e7:f6:92:ab:85:7b:d7:a0:de:
cc:bb:12:13:90:81:f5:8b:3d
'''
tmp22 = '''
00:d6:9a:62:75:9c:dd:55:e2:2c:0d:d9:e8:1e:3a:
9e:9b:08:91:07:aa:39:a6:07:60:15:b3:e9:22:c7:
99:03:2e:f0:4c:ea:8b:21:00:52:f0:b5:a0:94:f7:
0f:bb:cf:eb:05:16:5a:cc:69:d6:27:cb:41:03:0f:
4c:3d:03:4a:12:e7:11:84:24:98:1d:ed:35:03:89:
ec:83:0a:d6:93:e6:0c:1b:0e:7e:8a:65:19:be:f6:
a1:81:f5:be:92:af:8b:00:44:c8:d0:b8:42:70:e3:
34:c5:90:13:8c:3e:9d:f9:a2:9e:c9:af:45:db:05:
f0:c4:43:b1:e0:96:23:9d:35
'''
dp = int(tmp11.replace(':', '').replace('\n', ''), 16)
dq = int(tmp22.replace(':', '').replace('\n', ''), 16)
e = 65537
for i in range(1, e):
    tmp1 = (e * dp - 1) % i
    tmp2 = (e * dp - 1) // i + 1
    if isPrime(tmp2) and tmp1 == 0:
        p = tmp2

for i in range(1, e):
    tmp1 = (e * dq - 1) % i
    tmp2 = (e * dq - 1) // i + 1
    if isPrime(tmp2) and tmp1 == 0:
        q = tmp2
# p = 147673116768123046501026066807038926715915264969442823763204208720475579535213477786210371187742193605880627754665653951186744519004661448520641122167660320120916066617377213467621875332444790635885712675701692302167245584599460230318670678706064901636515350423028037212575403191070279218091882059694812068919
# q = 171948646963038974435691793127831642257172420943060283745665555608701434414995570207450463094959389391741516208924038087804230983903133933532912182896192626915878363234805008629862688524283683392186453931930481499933370069645646443294030138569978008539334897839068026907252820219214009652777264505794114374279
```

算出p和q后，我们可以计算出密钥文件中缺失的其他部分，可以验证除了私钥d和给的那两个字节对应不上，其他都完全一样，我们合理怀疑是d的那两个字节出错了(最后确实可以得到结果)

接下来重构密钥文件，创建一个key.asn1文件，记事本编辑写入如下内容
```
asn1=SEQUENCE:rsa_key

[rsa_key]
version=INTEGER:0
modulus=INTEGER:0x...
pubExp=INTEGER:65537
privExp=INTEGER:0x...
p=INTEGER:0x...
q=INTEGER:0x...
e1=INTEGER:0x...
e2=INTEGER:0x...
coeff=INTEGER:0x...
```

然后用命令

```
openssl asn1parse -genconf key.asn1 -out key.der # 生成DER格式的密钥
openssl rsa -in key.der -inform DER -out key.pem # 转换为PEM格式
```

最后解密，当时在这里坐牢好久，怎么都弄不出来，后来知道RSA除了PKCS#1 v1.5填充以外，还有一种方式叫做OAEP，正是这一道题用的

而cyberchef中的rsa解密恰好有三种模式PKCS#1 v1.5, OAEP, RAW无填充，可以直接梭，当然也可以写脚本，`from Crypto.Cipher import PKCS1_OAEP`也能实现一样的效果，具体脚本就不放了，可以让ai写，实际上也不如直接用cyberchef
(T2可以用cyberchef解其实也是在此之后发现的)
