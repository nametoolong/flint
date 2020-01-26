flint
======
[简体中文](README.zh_cn.md)

Flint is an experimental TCP proxy using Enigma rotor cipher. The only dependency is [botan](https://github.com/etcimon/botan).

I wrote flint to make my ~script kiddie~ pentesting life easier. It could hide from old-school rule-based corporate firewalls. It provided a secret way to access my servers in case they were under attack. And to my surprise it also worked smoothly circumventing GFW, even with the most stringent blocking in place.

Building
------
```
dub build --build=release
```
The generated executable `flint` or `flint.exe` can act as both client and server and is self-contained.
The example client side config is `flint.config` and server side `flint.config_server`.
You can start the server using `--config=flint.config_server`.

Where are my keys?
------
```
cd keytool
dub --build=release
```
The files `pubkey.key` and `privkey.key` will be created under the folder `keytool`. The server requires `privkey.key` and the client requires `pubkey.key`.

Usage
------
Use `--config=<file>` to specify a config file.

`type` should be `client` or `server`.

`rotors` and `rings` should be the settings of the first, second and third rotors. `reflector` is the type of the reflector. Only 3 rotors are supported currently. See [enigma.d](source/enigma.d) for available types. Not that they are important though, since anyone can break Enigma rotor cipher with no difficulty. Use the values in `flint.config` if you don't know what they are.

On client side, `listen` and `port` specify where to listen for application connections and `remote` and `rport` specify the server address. On server side, `listen` and `port` specify where to listen for clients and `remote` and `rport` specify where to forward applications connections to. `timeout` is the timeout of client or server connections and does not affect application connections. `idletimeout` affects only the server and specifies the length of inactivity before disconnecting a client.

`keyfile` specifies the location of RSA public or private key file. `powleadingzero` is the required number of leading zero bytes (`0x00`) in client's proof of work and `powfirstbytemax` is the the highest acceptable value of the first non-zero byte in client's proof of work. `powsalt` is the salt value for proof of work hashes. `maxdisconnectdelay` is the the maximum delay when disconnecting, during which a random delay between 0 and this value will be chosen and the shutdown of connection will only be done after the random delay.

How does it work?
------
Flint is based on the same idea behind [bananaphone](https://github.com/david415/bananaphone). In detail, Flint multiplexes application TCP connections in one TCP connection and uses Enigma rotor cipher to encrypt all application traffic, therefore creating traffic consisting of only alphabetic characters and spaces. Flint has a lower overhead and is much faster than bananaphone.
