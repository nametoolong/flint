flint
======
[English](README.md)

一个使用 enigma 加密的 TCP 代理。依赖于 [botan](https://github.com/etcimon/botan).

Enigma 机 **不是** 一种安全的加密方式，建议使用 [stunnel](https://www.stunnel.org/index.html) 保证保密性。

构建
------
```
dub build --build=release
```
服务端使用 `--config=flint.config_server` 启动。

生成密钥对
------
```
cd keytool
dub --build=release
```
将 privkey.key 复制到服务端目录下，pubkey.key 复制到客户端目录下。