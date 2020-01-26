flint
======
[English](README.md)

一个使用 Enigma 加密的 TCP 代理。依赖于 [botan](https://github.com/etcimon/botan) 加密库。

构建
------
```
dub build --build=release
```
构建完成后生成的可执行文件 `flint` 或 `flint.exe` 包含服务端和客户端，可以独立运行。
项目目录下的 `flint.config` 是默认客户端配置文件。使用参数 `--config=flint.config_server` 可以启动服务端。

生成密钥对
------
```
cd keytool
dub --build=release
```
将 `privkey.key` 复制到服务端目录下，`pubkey.key` 复制到客户端目录下。

用法
------
使用 `--config=<file>` 指定配置文件。配置各项说明如下：

`type` 可以是 `client` （指定运行为客户端）或者 `server`（指定运行为服务端）。

`rotors` 和 `rings` 是 Enigma 机中转子的设置。  
`reflector` 是 Enigma 机中反射器的设置。  
目前只支持使用 3 个转子。参考 [enigma.d](source/enigma.d) 来设置这些值。它们并不重要，因为现在谁都可以轻易破解 Enigma 加密。如果你不明白这些是什么，从 `flint.config` 里复制这三项设置即可。

客户端配置文件中的 `listen` 和 `port` 指定监听应用程序连接的地址和端口； `remote` 和 `rport` 指定服务器地址和端口。服务端配置文件中的 `listen` 和 `port` 指定监听客户端连接的地址和端口； `remote` 和 `rport` 指定将应用程序连接代理到的地址和端口。  
`timeout` 指定客户端或服务端对另一方的超时时间，不影响应用程序连接。  
`idletimeout` 指定断开客户端连接需要的空闲时间，只影响服务端。

`keyfile` 指定 RSA 公钥或私钥的位置。  
`powleadingzero` 指定客户端工作量证明中需要的前导 `0x00` 数量。  
`powfirstbytemax` 指定客户端工作量证明中首个非零字节的最大值。  
`powsalt` 是工作量证明在哈希中使用的盐值。  
`maxdisconnectdelay` 是在连接断开前随机延时的最大值。

工作原理
------
Flint 和 [bananaphone](https://github.com/david415/bananaphone) 基于类似的想法。因为使用 Enigma 机加密所有流量，所以 flint 产生的流量只含有字母和空格。
