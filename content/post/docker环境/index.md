+++
title = "Docker搭建环境"
date = "2026-01-29"
categories = ["其他"]

+++

# 使用Docker Desktop搭建题目本地环境

**前言**

之前一直想试试在本地搭建远程题目所需的环境，于是本文简单记录一下

## 过程

1. windows安装Docker Desktop，配置环境变量，这个是好久之前安的了，故略过
2. 准备所需内容，这里以题目linear的内容为例

```
linear/
├── Dockerfile
└── src/
    ├── chall.py
    └── init.sh
```

3. 运行Docker Desktop，在linear文件夹打开cmd，执行如下命令

```bash
# -t 指定镜像名
docker build -t linear .
```

此时在Docker Desktop左侧的Builds和Images中均可看到创建的镜像

4. 执行

```bash
# -d 后台运行 -p 主机端口:容器端口 作用：将容器端口映射到主机端口
# --name 给容器命名 最后一个参数为刚才创建的镜像名称
docker run -d -p 7070:70 --name linear linear
```

此时在Docker Desktop左侧的Containers可看到创建的容器正在运行

5. wsl中`nc 127.0.0.1 7070`或`nc localhost 7070`即可连接上

6. 停止容器与重新启动，也可以在Docker Desktop里手动点

```bash
# 停止容器
docker stop ctf-challenge

# 重新启动
docker start ctf-challenge
```

## 其他

初始dockerfile内容

```dockerfile
FROM ghcr.io/gzctf/challenge-base/python:alpine

COPY --chown=ctf:ctf --chmod=500 src/chall.py /home/ctf/chall.py
COPY --chown=ctf:ctf --chmod=500 src/init.sh /init.sh

CMD ["/init.sh"]
```

个人理解第一行应该是以gzctf的镜像为基础镜像进行操作，它应已经是一个比较完备的镜像

然后复制chall.py和init.sh，并执行init.sh

init.sh

```bash
#!/bin/sh

if [ "$LILCTF_FLAG" ]; then
    :
elif [ "$A1CTF_FLAG" ]; then
    export LILCTF_FLAG="$A1CTF_FLAG"
    unset A1CTF_FLAG
elif [ "$GZCTF_FLAG" ]; then
    export LILCTF_FLAG="$GZCTF_FLAG"
    unset GZCTF_FLAG
elif [ "$FLAG" ]; then
    export LILCTF_FLAG="$FLAG"
    unset FLAG
else
    export LILCTF_FLAG="LILCTF{!!!!_FLAG_ERROR_ASK_ADMIN_!!!!}"
fi

socat -T10 TCP-LISTEN:70,reuseaddr,fork EXEC:"python3 -u /home/ctf/chall.py",stderr
```

逐层设置flag，最后一行信息 70端口，执行chall.py

打通后可以发现输出的是`LILCTF{!!!!_FLAG_ERROR_ASK_ADMIN_!!!!}`，说明前面的变量都不存在

也可以修改init.sh为

```bash
#!/bin/sh

export LILCTF_FLAG="hata{test_flag}"

socat -T10 TCP-LISTEN:70,reuseaddr,fork EXEC:"python3 -u /home/ctf/chall.py",stderr
```

这样打通后输出的就是`hata{test_flag}`

## to do

在此基础上研究一下如何出题？找到一些或许有用的博客，以后有兴趣看看

[密码出题指北 | Harry's Blog](https://harry0597.com/2022/06/04/密码出题指北/)

[CTF密码题是怎么炼成的 | 4XWi11's Blog](https://4xwi11.github.io/posts/921543e1/#more)

[基于阿里云搭建CTF docker动态题目兼密码出题小tips | saga131密之作坊](https://saga131.github.io/2025/05/11/基于阿里云搭建CTF-docker动态题目兼密码出题小tips/)

