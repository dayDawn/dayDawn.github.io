---
layout:     post   				    # 使用的布局（不需要改）
title:      BUU 7.15 				# 标题 
subtitle:   BUU刷题					#副标题
date:       2021-07-15 				# 时间
author:     DD 						# 作者
header-img: img/post-bg-2015.jpg 	#这篇文章标题背景图片
catalog: true 						# 是否归档
tags:								#标签
    - BUU
---



﻿@[TOC](buu刷题)
# 
## 
### 

## zip
打恺压缩包，发现里面有很多加密压缩包，但是里面的内容非常小，小于5字节，可以尝试使用CRC32爆破得到其内容
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210715104720802.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0dyYXBlU291cg==,size_16,color_FFFFFF,t_70)
发现是base64编码，解码得到![在这里插入图片描述](https://img-blog.csdnimg.cn/20210715120924658.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0dyYXBlU291cg==,size_16,color_FFFFFF,t_70)
是rar文件
010打开，添加rar文件头

```python
52 61 72 21 1A 07 00
```
在注释中发现flag
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021071512192544.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0dyYXBlU291cg==,size_16,color_FFFFFF,t_70)

## [RoarCTF2019]黄金6年
查看文件尾发现base64编码

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210715124509126.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0dyYXBlU291cg==,size_16,color_FFFFFF,t_70)
存出来，发现需要密码，去视频里面慢慢找
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210715125100955.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0dyYXBlU291cg==,size_16,color_FFFFFF,t_70)


```kotlin
key1:i
```
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021071512552387.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0dyYXBlU291cg==,size_16,color_FFFFFF,t_70)

```objectivec
key2:want
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210715125259392.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0dyYXBlU291cg==,size_16,color_FFFFFF,t_70)

```markup
key3:play
```
中间有个坑。。。最后一张二维码背景是黑的根本找不到！！！（做题的时候根本没找到，还是根据黄金6年的梗猜出来的内容。。。后来看大神题解才知道在哪）
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210715142857491.png)

所以密码是

iwantplayctf

得到flag

## 间谍启示录
foremost分离得到一个rar文件
解压得到flag.exe
机密文件里就是flag

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021071515402555.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0dyYXBlU291cg==,size_16,color_FFFFFF,t_70)
## [安洵杯 2019]吹着贝斯扫二维码
二维码拼图后得到密码
扫描得到

> BASE Family Bucket ???
85->64->85->13->16->32

查看压缩包发现注释
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210715162458512.png)
然后按照顺序来
是逆着的顺序

> base32->十六进制解码->ROT13->base85->base64->base85

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210715162548667.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0dyYXBlU291cg==,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210715162716232.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210715162750800.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0dyYXBlU291cg==,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210715162827372.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0dyYXBlU291cg==,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210715162844159.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0dyYXBlU291cg==,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210715162905793.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0dyYXBlU291cg==,size_16,color_FFFFFF,t_70)
得到压缩包密码
得到flag
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210715163006102.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0dyYXBlU291cg==,size_16,color_FFFFFF,t_70)

## [ACTF新生赛2020]swp

得到一个pcapng
http.request发现一个压缩包，有密码，因为没有什么思路就试试是不是伪加密，
![在这里插入图片描述](https://img-blog.csdnimg.cn/202107151742106.png)
在将01改成00后
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021071517425758.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0dyYXBlU291cg==,size_16,color_FFFFFF,t_70)
里面的swp文件可以提取出来了，得到flag
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021071517432649.png)
## 小易的U盘
得到
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210715174541996.png)
打开提示不是该文件类型，010打开发现是rar文件
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210715174610461.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0dyYXBlU291cg==,size_16,color_FFFFFF,t_70)
修改后缀解压得到
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210715182202207.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0dyYXBlU291cg==,size_16,color_FFFFFF,t_70)
用ida打开得到flag
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210715182142309.png)

## 从娃娃抓起

```python
0086   1562   2535   5174             中文电码
 人      工     智     能
bnhn s wwy vffg vffg rrhy fhnv        五笔编码
也   要 从   娃   娃   抓   起

请将你得到的这句话转为md5提交，md5统一为32位小写。
提交格式：flag{md5}

```

## [WUSTCTF2020]alison_likes_jojo
打开，发现boki.jpg后有一个压缩包
提取出来，有密码先看第二个，看了半天没有什么头绪，爆破压缩包试试
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210715184516794.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0dyYXBlU291cg==,size_16,color_FFFFFF,t_70)
得到密码
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210715184539657.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0dyYXBlU291cg==,size_16,color_FFFFFF,t_70)
多次解密得到
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210715184600278.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0dyYXBlU291cg==,size_16,color_FFFFFF,t_70)
没有头绪，查wp发现是outguess隐写，得到flag
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210715185519588.png)
## [DDCTF2018](╯°□°）╯︵ ┻━┻
按照每两位截取

```python
['d4', 'e8', 'e1', 'f4', 'a0', 'f7', 'e1', 'f3', 'a0', 'e6', 'e1', 'f3', 'f4', 'a1', 'a0', 'd4', 'e8', 'e5', 'a0', 'e6', 'ec', 'e1', 'e7', 'a0', 'e9', 'f3', 'ba', 'a0', 'c4', 'c4', 'c3', 'd4', 'c6', 'fb', 'b9', 'b2', 'b2', 'e1', 'e2', 'b9', 'b9', 'b7', 'b4', 'e1', 'b4', 'b7', 'e3', 'e4', 'b3', 'b2', 'b2', 'e3', 'e6', 'b4', 'b3', 'e2', 'b5', 'b0', 'b6', 'b1', 'b0', 'e6', 'e1', 'e5', 'e1', 'b5', 'fd']

```
转成10进制

```python
[212, 232, 225, 244, 160, 247, 225, 243, 160, 230, 225, 243, 244, 161, 160, 212, 232, 229, 160, 230, 236, 225, 231, 160, 233, 243, 186, 160, 196, 196, 195, 212, 198, 251, 185, 178, 178, 225, 226, 185, 185, 183, 180, 225, 180, 183, 227, 228, 179, 178, 178, 227, 230, 180, 179, 226, 181, 176, 182, 177, 176, 230, 225, 229, 225, 181, 253]

```
每个减128
再转成字符串，得到flag

```python
That was fast! The flag is: DDCTF{922ab9974a47cd322cf43b50610faea5}

```

## [GUET-CTF2019]zips
解压得到一个压缩包
爆破得到密码
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210715194645487.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L0dyYXBlU291cg==,size_16,color_FFFFFF,t_70)
又得到一个加密zip

111.zip是伪加密，解压后得到两个
setup.sh里面是这个，在kali里面执行一下试试
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210715195240881.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210715195545665.png)
这里是以时间戳作为压缩包的密码，但是出题的时候的时间戳肯定和现在不一样，估摸一下确定时间戳前两位为15

使用ARCHPR掩码爆破，设置掩码15????????.??，掩码符号?
