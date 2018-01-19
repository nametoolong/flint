flint
======
[中文](README.zh_cn.md)

Simple TCP proxy using Enigma rotor cipher applied to base24 encoded data, written in D. The only dependency is [botan](https://github.com/etcimon/botan).

Flint provides strong integrity and **really weak confidentiality**, as Enigma is a WWII cipher. It is recommended to use [stunnel](https://www.stunnel.org/index.html) for some true confidentiality.

Building
------
```
dub build --build=release
```
The example client side config is `flint.config` and server side `flint.config_server`.
You can start the server using `--config=flint.config_server`.

Where are my keys?
------
```
cd keytool
dub --build=release
```
The files pubkey.key and privkey.key will be created under the folder keytool. The server requires privkey.key and the client requires pubkey.key.