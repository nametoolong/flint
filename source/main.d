module flint.main;

import config = flint.config;
import flint.connman;
import flint.enigma;
import flint.listener;
import flint.messages;
import flint.squeue;
import flint.strutils;

import base24;

static import core.exception;
import core.sync.mutex;
import core.thread;

import std.ascii;
import std.container.slist;
import std.exception;
import std.experimental.logger.core;
import std.file;
import std.random;
import std.socket;
import std.string;
import std.typecons;

import botan.block.xtea;
import botan.hash.rmd128;
import botan.hash.sha2_32;
import botan.hash.skein_512;
import botan.libstate.init;
import botan.mac.cbc_mac;
import botan.mac.hmac;
import botan.pk_pad.eme;
import botan.pk_pad.oaep;
import botan.pubkey.pkcs8;
import botan.pubkey.algo.rsa;
import botan.pubkey.x509_key;
import botan.rng.rng;



alias EnigmaSetting = Tuple!(string, "rotors", string, "rings", string, "reflector");

alias ArgOpt = Tuple!(bool, "is_managed", string, "config_filename");

const string CONFIG_FILE_ARG = "--config";

const string MANAGED_FLAG_ARG = "managed";

const string ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

const uint HMAC_BLOCK_SIZE = 64;
const uint HMAC_OUTPUT_BITS = 256;

const uint LEN_AUTH_BLOCK_SIZE = 8;
const uint LEN_AUTH_KEY_SIZE = 16;

const uint RSA_DATA_LENGTH = 256;
const uint ENCODED_RSA_DATA_LENGTH = RSA_DATA_LENGTH * 2;

const size_t HANDSHAKE_MESSAGE_PADDING_LENGTH_MAX = 840;

const size_t HANDSHAKE_INBUF_SIZE = 4096;
const size_t SERVER_INBUF_SIZE = 8192;
const size_t EDGE_INBUF_SIZE = 1024;
const size_t CLIENT_INBUF_SIZE = 8192;
const size_t SERVER_OUTBOUND_MESSAGE_SIZE = 1460;
const size_t MAX_MESSAGE_LENGTH = 1024 * 512;

const uint MAX_LENGTH_BETWEEN_SPACES = 21;
const uint ESTIMATED_SPACES_ADDED = cast(uint)(SERVER_OUTBOUND_MESSAGE_SIZE / (MAX_LENGTH_BETWEEN_SPACES / 3.5));

const Duration SERVER_READ_INTERVAL = dur!("msecs")(1);

const Duration CONNECTION_BLOCKING_TIME = dur!("msecs")(4);

const int MAX_RETRIES = 5;

const Duration RETRY_IN = dur!("seconds")(5);



RandomNumberGenerator cryptoRng;

__gshared RSAOAEPDecryptor globalDecryptor;

shared MonoTime[string] recent_pow;
__gshared Mutex recent_pow_mutex;

__gshared Socket client_socket;
__gshared MessagePacker client_mp;
__gshared SharedQueue!string client_send_queue;
__gshared SharedQueue!string clean_connections;
__gshared SharedQueue!string[string] ob_queues;
__gshared Mutex ob_queue_mutex;

__gshared bool client_shutdown = false;

__gshared EnigmaSetting enigma_setting;



string generate_random_rotors()
{
	return [ALPHABET[uniform(0, 26)], ALPHABET[uniform(0, 26)], ALPHABET[uniform(0, 26)]];
}

immutable(ubyte[]) generate_hmac_key()
{
	ubyte[HMAC_BLOCK_SIZE] key;
	cryptoRng.randomize(key.ptr, HMAC_BLOCK_SIZE);
	return key.idup;
}

immutable(ubyte[]) generate_len_auth_key()
{
	ubyte[LEN_AUTH_KEY_SIZE] key;
	cryptoRng.randomize(key.ptr, LEN_AUTH_KEY_SIZE);
	return key.idup;
}

ubyte[] random_data(size_t length)
{
	ubyte[] data = new ubyte[length];
	cryptoRng.randomize(data.ptr, length);
	return data;
}

ubyte[] random_length_of_random_data(size_t upper_bound)
{
	return random_data(uniform(0, upper_bound));
}

ubyte[] generate_alphabet()
{
	ubyte[] _in = cast(ubyte[])(ALPHABET.dup);
	randomShuffle(_in);
	return _in;
}

ubyte[] random_letters(size_t length)
{
	ubyte[] buf = new ubyte[length];
	for (size_t i = 0; i < length; i++)
	{
		buf[i] = uniform(65, 91) & 0xFF;
	}
	return buf;
}

ubyte[] random_length_of_random_letters(size_t upper_bound)
{
	return random_letters(uniform(0, upper_bound));
}

string add_random_letters(string src, string pool)
{
	char[] buf = new char[src.length + 42]; // assume 42 chars will be added
	size_t i = 0;
	size_t j = 0;
	size_t u = pool.length;
	size_t rand, ol, sl;
	while (i < src.length)
	{
		rand = uniform(15, 25); // so hard encoding

		sl = i + rand;
		if (sl > src.length)
		{
			rand = src.length - i;
			buf.length = j + rand;
			buf[j .. (j + rand)] = src[i .. (i + rand)];
			goto ret;
		}

		ol = j + rand + 1;

		if (ol > buf.length)
		{
			buf.length = ol + 16; // so magic number
		}
		buf[j .. ol] = src[i .. sl] ~ pool[uniform(0, u)];
		i = sl;
		j = ol;
	}
	buf.length = j;

	ret:
	return assumeUnique(buf);
}

string add_spaces(string src)
{
	char[] buf = new char[src.length + ESTIMATED_SPACES_ADDED];
	size_t i = 0;
	size_t j = 0;
	size_t rand, ol, sl;
	while (i < src.length)
	{
		rand = uniform(1, MAX_LENGTH_BETWEEN_SPACES);

		sl = i + rand;
		if (sl > src.length)
		{
			rand = src.length - i;
			buf.length = j + rand;
			buf[j .. (j + rand)] = src[i .. (i + rand)];
			goto ret;
		}

		ol = j + rand + 1;

		if (ol > buf.length)
		{
			buf.length = ol + 12; // yet another magic number
		}
		buf[j .. ol] = src[i .. sl] ~ ' ';
		i = sl;
		j = ol;
	}
	buf.length = j;

	ret:
	return assumeUnique(buf);
}

string random_cased(string src) // input should be uppercase
{
	char[] buf = unsafe_lower(src);
	for (size_t i = uniform(0, 10); i < src.length; i += uniform(0, 10))
	{
		ubyte b = cast(ubyte)buf[i];
		if (b >= 97 && b < 123)
		{
			buf[i] = cast(char)(b - 32);
		}
	}
	return assumeUnique(buf);
}



bool verify_mac(int N)(inout ubyte[] a, inout ubyte[] b) if (N >= 1)
{
	foreach (int i; 0 .. N)
	{
		if (a[i] != b[i])
		{
			return false;
		}
	}

	return true;

	// we close the connection immediately upon receiving an invalid mac
	// so there is no need to mitigate timing attacks
}



bool checkPOW(ref SecureVector!ubyte hash, int leadingZero, int maxNB)
{
	if (leadingZero >= hash.length)
	{
		return false;
	}
	for (int i = 0; i < leadingZero; i++)
	{
		if (hash[i] != 0)
		{
			return false;
		}
	}
	return hash[leadingZero] <= maxNB;
}



void requestConnection()
{
	client_send_queue.put(client_mp.createStreamMessage());
}

void clientSenderThread(string rotors, immutable ubyte[] hmac_key, string base24_alphabet, immutable ubyte[] len_auth_key)
{
	auto enigma = EnigmaMachine.fromKeySheet(enigma_setting.expand);
	enigma.setDisplay(rotors);

	auto hmac = new HMAC(new Skein512(HMAC_OUTPUT_BITS));
	hmac.setKey(hmac_key.ptr, HMAC_BLOCK_SIZE);

	auto len_auth_mac = new CBCMAC(new XTEA);
	len_auth_mac.setKey(len_auth_key.ptr, LEN_AUTH_KEY_SIZE);

	ptrdiff_t len;

	while (true)
	{
		if (client_shutdown)
		{
			return;
		}

		string msg = client_send_queue.get();

		if (msg is null)
		{
			return;
		}

		string packed_body_len = pack_uint(cast(uint)msg.length);

		len_auth_mac.update(packed_body_len ~ packed_body_len);

		SecureVector!ubyte len_auth = len_auth_mac.finished();

		msg = packed_body_len ~ msg;

		hmac.update(msg);
		SecureVector!ubyte mac = hmac.finished();

		msg = enigma.processText(enbase(mac[0 .. 24] ~ len_auth[] ~ cast(ubyte[])msg, base24_alphabet));

		msg = add_spaces(random_cased(msg));

		len = client_socket.send(msg);

		if (len == client_socket.ERROR || len < msg.length)
		{
			trace("Client shutdown, client_socket send error");
			client_shutdown = true;
			return;
		}
	}
}

void clientReceiverThread(string rotors, immutable ubyte[] hmac_key, string base24_alphabet, immutable ubyte[] len_auth_key)
{
	auto enigma = EnigmaMachine.fromKeySheet(enigma_setting.expand);
	enigma.setDisplay(rotors);

	auto hmac = new HMAC(new Skein512(HMAC_OUTPUT_BITS));
	hmac.setKey(hmac_key.ptr, HMAC_BLOCK_SIZE);

	auto len_auth_mac = new CBCMAC(new XTEA);
	len_auth_mac.setKey(len_auth_key.ptr, LEN_AUTH_KEY_SIZE);

	char[] buf = new char[CLIENT_INBUF_SIZE];
	ptrdiff_t len;

	char unmatched = '\0';
	string seg;
	ubyte[] fin_mac = new ubyte[HMAC_OUTPUT_BITS/8];
	ubyte[LEN_AUTH_BLOCK_SIZE] fin_len_auth;

	while (true)
	{
		if (client_shutdown)
		{
			return;
		}

		len = client_socket.receive(buf);

		if (len == 0 || len == client_socket.ERROR)
		{
			trace("Client shutdown, client_socket recv error");
			client_shutdown = true;
			return;
		}

		string msg = remove_spaces_string(buf[0 .. len], len);
		string text;

		try
		{
			msg = toUpper(msg);

			if (unmatched)
			{
				text = unmatched ~ enigma.processText(msg);
				unmatched = '\0';
			}
			else
			{
				text = enigma.processText(msg);
			}

			if (text.length % 2 != 0)
			{
				unmatched = text[$ - 1];
				text = text[0 .. $ - 1];
			}

			seg ~= debase(text, base24_alphabet);
		}
		catch (core.exception.RangeError)
		{
			error("A RangeError was thrown when decoding message");
			goto err_decoding;
		}
		catch (core.exception.AssertError)
		{
			error("An AssertError was thrown when decoding message");
			goto err_decoding;
		}
		catch (Exception)
		{
			err_decoding:
			trace("Client shutdown, error decoding message");
			client_shutdown = true;
			return;
		}

		while (true)
		{
			if (seg.length < 37)
			{
				break;
			}

			ubyte[] len_auth = cast(ubyte[])seg[24 .. 32];

			ubyte[] packed_body_len = cast(ubyte[])seg[32 .. 36];

			len_auth_mac.update(packed_body_len ~ packed_body_len);
			len_auth_mac.flushInto(fin_len_auth.ptr);

			if (!verify_mac!8(fin_len_auth, len_auth))
			{
				trace("Client shutdown, bad length authenticator");
				client_shutdown = true;
				return;
			}

			uint body_len = unpack_uint(packed_body_len);

			if (body_len > MAX_MESSAGE_LENGTH)
			{
				trace("Client shutdown, invalid message length");
				client_shutdown = true;
				return;
			}

			if (seg.length < body_len + 36)
			{
				break;
			}

			ubyte[] mac = cast(ubyte[])seg[0 .. 24];
			string content = seg[32 .. 36 + body_len];
			seg = seg[36 + body_len .. $];

			hmac.update(content);
			hmac.flushInto(fin_mac);

			if (!verify_mac!24(fin_mac, mac))
			{
				trace("Client shutdown, bad hmac");
				client_shutdown = true;
				return;
			}

			try
			{
				final switch(content[4])
				{
					case 'c':
						if (content.length < 9)
						{
							trace("Client shutdown, incorrect message length");
							client_shutdown = true;
							return;
						}

						auto queue = new SharedQueue!string();

						synchronized (ob_queue_mutex)
						{
							ob_queues[content[5 .. 9]] = queue;
						}
						clean_connections.put(content[5 .. 9]);
						break;
					case 'd':
						if (content.length < 9)
						{
							trace("Client shutdown, incorrect message length");
							client_shutdown = true;
							return;
						}

						SharedQueue!string *ptr;

						synchronized (ob_queue_mutex)
						{
							ptr = content[5 .. 9] in ob_queues;
						}

						if (ptr !is null)
						{
							(*ptr).dispose();
						}

						break;
					case 'm':
						if (content.length <= 9)
						{
							trace("Client shutdown, incorrect message length");
							client_shutdown = true;
							return;
						}

						SharedQueue!string *ptr;

						synchronized (ob_queue_mutex)
						{
							ptr = content[5 .. 9] in ob_queues;
						}

						if (ptr !is null)
						{
							(*ptr).put(content[9 .. $]);
						}

						break;
				}
			}
			catch (core.exception.SwitchError)
			{
				trace("Client shutdown, unknown cmd");
				client_shutdown = true;
				return;
			}
		}
	}
}

class ClientConnectionSenderThread : Thread
{
	Socket sock;
	string cid;

	this(Socket socket, string cid)
	{
		super(&run);
		sock = socket;
		this.cid = cid;
	}

	void run()
	{
		SharedQueue!string queue;

		synchronized (ob_queue_mutex)
		{
			queue = ob_queues[cid];
		}

		ptrdiff_t len;

		while (true)
		{
			if (client_shutdown)
			{
				sock.close();
				queue.clear();
				synchronized (ob_queue_mutex)
				{
					ob_queues.remove(cid);
				}
				return;
			}

			auto data = queue.get();

			if (data is null)
			{
				sock.close();
				queue.clear();
				synchronized (ob_queue_mutex)
				{
					ob_queues.remove(cid);
				}
				return;
			}

			len = sock.send(data);

			if (len == sock.ERROR || len < data.length)
			{
				sock.close();
				client_send_queue.put(client_mp.destroyStreamMessage(cid));
				queue.clear();
				synchronized (ob_queue_mutex)
				{
					ob_queues.remove(cid);
				}
				return;
			}
		}
	}
}
class ClientConnectionHandler : Thread
{
	Socket sock;

	this(Socket socket)
	{
		super(&run);
		sock = socket;
	}

	void run()
	{
		trace("Connection from ", sock.remoteAddress);

		requestConnection();

		string cid = clean_connections.get(dur!("seconds")(config.getUnsignedShort("timeout")));

		if (cid is null)
		{
			sock.close();
			return;
		}

		trace("Got connection id " ~ to!string(unpack_uint(cast(ubyte[])cid)));

		Thread.sleep(CONNECTION_BLOCKING_TIME);

		new ClientConnectionSenderThread(sock, cid).start();

		char[] buf = new char[EDGE_INBUF_SIZE];

		ptrdiff_t len;

		while (true)
		{
			if (client_shutdown)
			{
				sock.close();
				return;
			}

			len = sock.receive(buf);

			if (len == sock.ERROR || len == 0)
			{
				sock.close();
				client_send_queue.put(client_mp.destroyStreamMessage(cid));
				return;
			}

			client_send_queue.put(client_mp.dataMessage(cid, buf[0 .. len]));
		}
	}
}

string doProofOfWork()
{
	info("Doing Proof of Work...");

	string pow;
	SecureVector!ubyte pow_hash;

	int leading_zeroes = config.getUnsignedShort("powleadingzero");
	int maxNB = config.getUnsignedShort("powfirstbytemax");
	string pow_salt = config.getString("powsalt");
	if (pow_salt is null)
	{
		pow_salt = "";
	}

	RIPEMD128 pow_hasher = new RIPEMD128;
	do
	{
		pow = random_cased(cast(string)random_letters(32));
		pow_hasher.update(pow);
		pow_hasher.update(pow_salt);
		pow_hash = pow_hasher.finished();
		pow_hasher.clear();
	} while (!checkPOW(pow_hash, leading_zeroes, maxNB));

	return pow;
}

void launchClient()
{
	auto server_address = new InternetAddress(config.getString("remote"), config.getUnsignedShort("rport"));

	try
	{
		auto timeout = dur!"seconds"(config.getUnsignedShort("timeout"));
		client_socket = new Socket(AddressFamily.INET, SocketType.STREAM);
		client_socket.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, timeout);
		client_socket.setOption(SocketOptionLevel.SOCKET, SocketOption.SNDTIMEO, timeout);
	}
	catch (SocketException)
	{
		fatal("Could not create a socket");
	}

	int retry_count = 0;
	Duration sleep_time = RETRY_IN;

	while (true)
	{
		try
		{
			info("Connecting...");

			client_socket.connect(server_address);
			break;
		}
		catch (SocketException)
		{
			if (retry_count >= MAX_RETRIES)
			{
				fatal("Could not connect to server after " ~ to!string(retry_count) ~ " retries, quitting");
			}

			warning("Could not connect to server, retrying in " ~ sleep_time.toString());
			retry_count++;
			Thread.sleep(sleep_time);
			sleep_time = sleep_time * 2;
		}
	}
}

auto handshake(ref PublicKey pubkey, string pow)
{
	scope (failure)
	{
		client_socket.close();
	}

	char[] buf = new char[HANDSHAKE_INBUF_SIZE];
	ptrdiff_t len;

	string first_msg = add_spaces(pow ~ random_cased(cast(string)random_length_of_random_letters(640)));

	len = client_socket.send(first_msg);

	if (len == client_socket.ERROR)
	{
		fatal("Could not write on socket, " ~ client_socket.getErrorText());
	}

	if (len < first_msg.length)
	{
		client_socket.shutdown(SocketShutdown.BOTH);
		fatal("Could not dispose a message immediately");
	}

	info("Handshaking...");

	len = client_socket.receive(buf);

	if (len == 0)
	{
		fatal("Connection closed before cookie is received");
	}

	if (len == client_socket.ERROR)
	{
		fatal("Could not read socket, " ~ client_socket.getErrorText());
	}

	if (len < 34)
	{
		client_socket.shutdown(SocketShutdown.BOTH);
		fatal("Cookie too short");
	}

	string r_msg = remove_spaces_string(buf[0 .. len], 34);

	if (r_msg.length < 34)
	{
		client_socket.shutdown(SocketShutdown.BOTH);
		fatal("Cookie too short");
	}

	string cookie = toUpper(r_msg[0 .. 8]);
	string rotors = generate_random_rotors();
	immutable ubyte[] hmac_key = generate_hmac_key();
	immutable ubyte[] len_auth_key = generate_len_auth_key();

	string alphabet = toUpper(r_msg[8 .. 34]);
	string base24_alphabet = alphabet[0 .. 24];
	string unused_letters = alphabet[24 .. 26];

	immutable ubyte[] keys = cast(immutable ubyte[])cookie ~ cast(immutable ubyte[])rotors ~ hmac_key ~ len_auth_key;

	PKEncryptorEME encryptor = new PKEncryptorEME(pubkey, "EME1(SHA-256)");

	ubyte[] encrypted_keys = encryptor.encrypt(keys.ptr, keys.length, cryptoRng)[] ~ random_length_of_random_data(224);

	string msg = add_spaces(random_cased(add_random_letters(enbase(encrypted_keys, base24_alphabet), unused_letters)));

	len = client_socket.send(msg);

	if (len == client_socket.ERROR)
	{
		fatal("Could not write on socket, " ~ client_socket.getErrorText());
	}

	if (len < msg.length)
	{
		client_socket.shutdown(SocketShutdown.BOTH);
		fatal("Could not dispose a message immediately");
	}

	client_socket.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, dur!"seconds"(0));

	info("Connection established");

	return tuple(rotors, hmac_key, base24_alphabet, len_auth_key);
}

void clientMain(string rotors, immutable ubyte[] hmac_key, string base24_alphabet, immutable ubyte[] len_auth_key)
{
	scope (exit)
	{
		client_socket.close();
	}

	ob_queue_mutex = new Mutex;

	client_mp = new MessagePacker;

	client_send_queue = new SharedQueue!string();
	clean_connections = new SharedQueue!string();

	new Thread({
		clientSenderThread(rotors, hmac_key, base24_alphabet, len_auth_key);
	}).start();
	new Thread({
		clientReceiverThread(rotors, hmac_key, base24_alphabet, len_auth_key);
	}).start();

	auto listener = new SimpleThreadingListener!ClientConnectionHandler(config.getString("listen"), config.getUnsignedShort("port"));
	listener.start();

	info("Listening on " ~ config.getString("listen") ~ ":" ~ to!string(config.getUnsignedShort("port")));

	while (true)
	{
		if (client_shutdown)
		{
			ushort maxDisconnectDelay = config.getUnsignedShort("maxdisconnectdelay");

			if (maxDisconnectDelay != 0)
			{
				Thread.sleep(msecs(uniform(0, maxDisconnectDelay)));
			}

			client_socket.shutdown(SocketShutdown.BOTH);

			client_send_queue.dispose();
			clean_connections.dispose();

			synchronized (ob_queue_mutex)
			{
				foreach (q; ob_queues)
				{
					q.dispose();
				}
			}

			error("Disconnected");
			break;
		}

		Thread.sleep(dur!("seconds")(1));
	}
}



bool serverPOWCheck(string pow)
{
	if (pow.length != 32)
	{
		return false;
	}

	foreach (char ch; pow)
	{
		if (!isAlpha(ch))
		{
			return false;
		}
	}

	synchronized (recent_pow_mutex)
	{
		auto ptr = pow in recent_pow;
		if (ptr !is null)
		{
			*ptr = MonoTime.currTime;
			return false;
		}
	}

	string pow_salt = config.getString("powsalt");

	if (pow_salt is null)
	{
		pow_salt = "";
	}

	RIPEMD128 pow_hasher = new RIPEMD128;
	pow_hasher.update(pow);
	pow_hasher.update(pow_salt);
	auto pow_hash = pow_hasher.finished();

	if (!checkPOW(pow_hash, config.getUnsignedShort("powleadingzero"), config.getUnsignedShort("powfirstbytemax")))
	{
		return false;
	}

	auto pow_lifetime = dur!"minutes"(config.getUnsignedShort("powlife"));

	auto now = MonoTime.currTime;

	synchronized (recent_pow_mutex)
	{
		recent_pow[pow] = now;

		foreach (pow_time; recent_pow.byKeyValue())
		{
			if (now - pow_time.value > pow_lifetime)
			{
				recent_pow.remove(pow_time.key);
			}
		}
	}

	return true;
}

class RSAOAEPDecryptor
{
	this(in PrivateKey key, RandomNumberGenerator rng)
	{
		m_op = new RSAPrivateOperation(key, rng);
		max_input_bits = m_op.maxInputBits();
	}

	SecureVector!ubyte decrypt(const(ubyte)* msg, size_t length)
	{
		auto oaep = scoped!OAEP(new SHA256);

		SecureVector!ubyte decrypted;

		synchronized (m_op)
		{
			decrypted = m_op.decrypt(msg, length);
		}

		return oaep.decode(decrypted, max_input_bits);
	}

private:
	RSAPrivateOperation m_op;
	size_t max_input_bits;
}

immutable(ubyte[]) serverKeyDecrypt(char[] raw_msg, string base24_alphabet)
{
	toUpperInPlace(raw_msg);

	if (raw_msg.length < ENCODED_RSA_DATA_LENGTH)
	{
		return [];
	}

	SecureVector!ubyte decrypted_msg;

	try
	{
		ubyte[] rsa_msg = cast(ubyte[])debase(raw_msg[0 .. ENCODED_RSA_DATA_LENGTH], base24_alphabet);
		decrypted_msg = globalDecryptor.decrypt(rsa_msg.ptr, rsa_msg.length);
	}
	catch (core.exception.RangeError)
	{
		error("A RangeError was thrown when decrypting key");
		goto err_decrypt;
	}
	catch (core.exception.AssertError)
	{
		error("An AssertError was thrown when decrypting key");
		goto err_decrypt;
	}
	catch (Exception)
	{
		err_decrypt:
		return [];
	}

	return decrypted_msg[].idup;
}

class ServerConnectionHandlerWrapper : Thread
{
	Socket sock;

	this(Socket socket)
	{
		super(&run);
		sock = socket;
	}

	void run()
	{
		serverConnectionHandler(sock);
	}
}

void closeConnectionFromClient(Socket sock, bool shutdown, string reason)
{
	trace("Disconnecting " ~ to!string(sock.remoteAddress) ~ ", " ~ reason);

	if (shutdown)
	{
		ushort maxDisconnectDelay = config.getUnsignedShort("maxdisconnectdelay");

		if (maxDisconnectDelay != 0)
		{
			Thread.sleep(msecs(uniform(0, maxDisconnectDelay)));
		}

		sock.shutdown(SocketShutdown.BOTH);
	}

	sock.close();
}

void serverConnectionHandler(Socket sock)
{
	scope LibraryInitializer botan_init;

	trace("Connection from ", sock.remoteAddress);

	char[] buf = new char[HANDSHAKE_INBUF_SIZE];
	ptrdiff_t len;

	Duration timeout_duration = dur!"seconds"(config.getUnsignedShort("timeout"));

	sock.setOption(SocketOptionLevel.SOCKET, SocketOption.SNDTIMEO, dur!"seconds"(2));
	sock.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, timeout_duration);

	len = sock.receive(buf);

	if (len == 0 || len == sock.ERROR)
	{
		return closeConnectionFromClient(sock, false, "socket recv error");
	}

	if (len < 32)
	{
		return closeConnectionFromClient(sock, true, "hello too short");
	}

	bool pow_ok = serverPOWCheck(remove_spaces_string(buf[0 .. len], 32));

	if (!pow_ok)
	{
		return closeConnectionFromClient(sock, true, "bad PoW");
	}

	ubyte[] cookie = random_letters(8);
	ubyte[] alphabet = generate_alphabet();

	string base24_alphabet = cast(string)alphabet[0 .. 24];
	string unused_letters = cast(string)alphabet[24 .. 26];

	string msg = add_spaces(random_cased(cast(string)(cookie ~ alphabet ~
			random_length_of_random_letters(HANDSHAKE_MESSAGE_PADDING_LENGTH_MAX))));

	len = sock.send(msg);

	if (len == sock.ERROR)
	{
		return closeConnectionFromClient(sock, false, "socket send error");
	}

	if (len < msg.length)
	{
		return closeConnectionFromClient(sock, true, "socket send error");
	}

	len = sock.receive(buf);

	if (len == 0 || len == sock.ERROR)
	{
		return closeConnectionFromClient(sock, false, "socket recv error");
	}

	if (len < ENCODED_RSA_DATA_LENGTH)
	{
		return closeConnectionFromClient(sock, true, "key too short");
	}

	immutable ubyte[] decrypted_msg = serverKeyDecrypt(
			strip_all(buf[0 .. len], " " ~ unused_letters ~ unsafe_lower(unused_letters), ENCODED_RSA_DATA_LENGTH),
			base24_alphabet);

	if (decrypted_msg.length < 11 + HMAC_BLOCK_SIZE + LEN_AUTH_KEY_SIZE || decrypted_msg[0 .. 8] != cookie)
	{
		return closeConnectionFromClient(sock, true, "key corrupted");
	}

	string rotors = cast(string)decrypted_msg[8 .. 11];
	immutable ubyte[] hmac_key = decrypted_msg[11 .. 11 + HMAC_BLOCK_SIZE];
	immutable ubyte[] len_auth_key = decrypted_msg[11 + HMAC_BLOCK_SIZE .. 11 + HMAC_BLOCK_SIZE + LEN_AUTH_KEY_SIZE];

	delete cookie;

	auto upstream_enigma = EnigmaMachine.fromKeySheet(enigma_setting.expand); // send
	auto downstream_enigma = EnigmaMachine.fromKeySheet(enigma_setting.expand); // recv
	upstream_enigma.setDisplay(rotors);
	downstream_enigma.setDisplay(rotors);

	auto upstream_hmac = new HMAC(new Skein512(HMAC_OUTPUT_BITS)); // send
	auto downstream_hmac = new HMAC(new Skein512(HMAC_OUTPUT_BITS)); // recv

	auto upstream_len_auth_mac = new CBCMAC(new XTEA); // send
	auto downstream_len_auth_mac = new CBCMAC(new XTEA); // recv

	scope (exit)
	{
		upstream_hmac.clear();
		downstream_hmac.clear();
	}

	upstream_hmac.setKey(hmac_key.ptr, HMAC_BLOCK_SIZE);
	downstream_hmac.setKey(hmac_key.ptr, HMAC_BLOCK_SIZE);

	upstream_len_auth_mac.setKey(len_auth_key.ptr, LEN_AUTH_KEY_SIZE);
	downstream_len_auth_mac.setKey(len_auth_key.ptr, LEN_AUTH_KEY_SIZE);

	MessagePacker mp = new MessagePacker;

	sock.setOption(SocketOptionLevel.SOCKET, SocketOption.SNDTIMEO, dur!"seconds"(0));
	sock.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, dur!"seconds"(0));
	sock.blocking(false);

	ConnectionManager cm = new ConnectionManager(
			config.getString("remote"),
			config.getUnsignedShort("rport"));

	scope (exit)
	{
		cm.destroy();
	}

	ushort idle_timeout = config.getUnsignedShort("idletimeout");

	buf = new char[SERVER_INBUF_SIZE];
	char[] inbuf = new char[EDGE_INBUF_SIZE];
	char[] ib_msg;
	ubyte[] fin_mac = new ubyte[HMAC_OUTPUT_BITS/8];
	ubyte[LEN_AUTH_BLOCK_SIZE] fin_len_auth;
	auto send_queue = SList!string();
	string encrypted_text, text, raw, seg, content;
	string outbuf = "";
	char unmatched = '\0';

	SocketSet read_set = new SocketSet();
	SocketSet write_set = new SocketSet();
	SocketSet except_set = new SocketSet(); // write is not used

	while (true)
	{
		read_set.reset();
		read_set.add(sock);
		except_set.reset();

		cm.addToSet(read_set);
		cm.addToSet(except_set);

		if (outbuf.length)
		{
			len = sock.receive(buf);

			bool closed = len == 0;

			if (closed || len == sock.ERROR)
			{
				if (closed || !wouldHaveBlocked())
				{
					return closeConnectionFromClient(sock, false, "disconnected");
				}
				else
				{
					len = 0;
				}
			}
		}
		else
		{
			if (idle_timeout == 0)
			{
				len = Socket.select(read_set, write_set, except_set);
			}
			else
			{
				len = Socket.select(read_set, write_set, except_set, dur!"minutes"(idle_timeout));
			}


			if (len == -1)
			{
				continue;
			}

			if (read_set.isSet(sock))
			{
				len = sock.receive(buf);

				if (len == 0 || len == sock.ERROR)
				{
					return closeConnectionFromClient(sock, false, "socket recv error");
				}
			}
			else
			{
				if (len == 0)
				{
					return closeConnectionFromClient(sock, true, "inactive");
				}
				len = 0;
			}
		}

		if (len)
		{
			ib_msg = remove_spaces(buf[0 .. len], len);

			try
			{
				toUpperInPlace(ib_msg);

				encrypted_text = assumeUnique(ib_msg);

				if (unmatched)
				{
					text = unmatched ~ downstream_enigma.processText(encrypted_text);
					unmatched = '\0';
				}
				else
				{
					text = downstream_enigma.processText(encrypted_text);
				}

				if (text.length % 2 != 0)
				{
					unmatched = text[$ - 1];
					text = text[0 .. $ - 1];
				}

				raw = debase(text, base24_alphabet);
			}
			catch (core.exception.RangeError)
			{
				error("A RangeError was thrown when decoding message");
				goto err_decoding;
			}
			catch (core.exception.AssertError)
			{
				error("An AssertError was thrown when decoding message");
				goto err_decoding;
			}
			catch (Exception)
			{
				err_decoding:
				return closeConnectionFromClient(sock, true, "error decoding message");
			}
		}
		else
		{
			raw = "";
		}

		seg ~= raw;

		while (true)
		{
			if (seg.length < 37)
			{
				break;
			}

			ubyte[] len_auth = cast(ubyte[])seg[24 .. 32];

			ubyte[] packed_body_len = cast(ubyte[])seg[32 .. 36];

			downstream_len_auth_mac.update(packed_body_len ~ packed_body_len);
			downstream_len_auth_mac.flushInto(fin_len_auth.ptr);

			if (!verify_mac!8(fin_len_auth, len_auth))
			{
				return closeConnectionFromClient(sock, true, "bad length authenticator");
			}

			uint body_len = unpack_uint(packed_body_len);

			if (body_len > MAX_MESSAGE_LENGTH)
			{
				return closeConnectionFromClient(sock, true, "invalid message length");
			}

			if (seg.length < body_len + 36)
			{
				break;
			}

			ubyte[] mac = cast(ubyte[])seg[0 .. 24];
			content = seg[32 .. 36 + body_len];
			seg = seg[36 + body_len .. $];

			downstream_hmac.update(content);
			downstream_hmac.flushInto(fin_mac);

			if (!verify_mac!24(fin_mac, mac))
			{
				return closeConnectionFromClient(sock, true, "bad hmac");
			}

			try
			{
				final switch(content[4])
				{
					case 'c':
						int cid = cm.connect();
						send_queue.insertFront(mp.createStreamSuccessMessage(pack_uint(cid)));
						break;
					case 'd':
						if (content.length < 9)
						{
							return closeConnectionFromClient(sock, true, "incorrect message length");
						}

						uint cid = unpack_uint(cast(ubyte[])content[5 .. 9]);

						Result result = cm.disconnect(cid);

						if (result == Result.CID_NOT_IN_RANGE)
						{
							return closeConnectionFromClient(sock, true, "incorrect cid");
						}

						break;
					case 'm':
						if (content.length <= 9)
						{
							return closeConnectionFromClient(sock, true, "incorrect message length");
						}

						uint cid = unpack_uint(cast(ubyte[])content[5 .. 9]);

						Result result = cm.send(cid, content[9 .. $]);

						if (result == Result.CID_NOT_IN_RANGE)
						{
							return closeConnectionFromClient(sock, true, "incorrect cid");
						}

						if (result == Result.CLOSING_CONNECTION)
						{
							send_queue.insertFront(mp.destroyStreamMessage(content[5 .. 9]));
						}
				}
			}
			catch (core.exception.SwitchError)
			{
				return closeConnectionFromClient(sock, true, "unknown cmd");
			}
		}

		if (!outbuf.length)
		{
			foreach (ref conn; cm.socketsInSets(read_set, except_set))
			{
				len = conn.socket.receive(inbuf);

				bool closed = len == 0;

				if (closed || len == conn.socket.ERROR)
				{
					if (closed || !wouldHaveBlocked())
					{
						cm.remove(conn.id);
						send_queue.insertFront(mp.destroyStreamMessage(pack_uint(conn.id)));
					}
					continue;
				}

				send_queue.insertFront(mp.dataMessage(pack_uint(conn.id), inbuf[0 .. len]));
			}
		}

		static if (SERVER_READ_INTERVAL == dur!("msecs")(0))
		{
			Thread.yield();
		}
		else
		{
			Thread.sleep(SERVER_READ_INTERVAL);
		}

		if (outbuf.length)
		{
			len = sock.send(outbuf);

			if (len == sock.ERROR)
			{
				if (wouldHaveBlocked())
				{
					continue;
				}

				return closeConnectionFromClient(sock, false, "socket send error");
			}

			outbuf = outbuf[len .. $];

			if (outbuf.length)
			{
				continue;
			}
		}

		while (!send_queue.empty)
		{
			msg = "";

			while (msg.length < SERVER_OUTBOUND_MESSAGE_SIZE && !send_queue.empty)
			{
				string msg2 = send_queue.removeAny(); // It should be random, but it just removes the front currently

				string packed_body_len = pack_uint(cast(uint)msg2.length);

				upstream_len_auth_mac.update(packed_body_len ~ packed_body_len);
				SecureVector!ubyte msg2_len_auth = upstream_len_auth_mac.finished();

				msg2 = packed_body_len ~ msg2;

				upstream_hmac.update(msg2);
				SecureVector!ubyte msg2_mac = upstream_hmac.finished();

				msg ~= upstream_enigma.processText(enbase(msg2_mac[0 .. 24] ~ msg2_len_auth[] ~ cast(ubyte[])msg2, base24_alphabet));
			}

			msg = add_spaces(random_cased(msg));

			len = sock.send(msg);

			if (len == sock.ERROR)
			{
				if (wouldHaveBlocked())
				{
					outbuf = msg;
					break;
				}

				return closeConnectionFromClient(sock, false, "socket send error");
			}

			if (len < msg.length)
			{
				outbuf = msg[len .. $];
				break;
			}
		}
	}
}

void launchServer()
{
	recent_pow_mutex = new Mutex;

	info("Initializing listener...");

	auto listener = new SimpleThreadingListener!ServerConnectionHandlerWrapper(config.getString("listen"), config.getUnsignedShort("port"));
	listener.start();

	info("Listening on " ~ config.getString("listen") ~ ":" ~ to!string(config.getUnsignedShort("port")));

	listener.join();
}

void initEnigmaSetting()
{
	enigma_setting.rotors = config.getString("rotors");
	enigma_setting.rings = config.getString("rings");
	enigma_setting.reflector = config.getString("reflector");
}

ArgOpt parseArgs(string[] args, string default_config_file)
{
	ArgOpt options = ArgOpt(false, default_config_file);

	foreach (string arg; args)
	{
		if (arg.startsWith(MANAGED_FLAG_ARG) == true)
		{
			options.is_managed = true;
			parseManagedParameters(arg[MANAGED_FLAG_ARG.length .. $].strip());
		}

		if (arg.startsWith(CONFIG_FILE_ARG) == true)
		{
			options.config_filename = arg[CONFIG_FILE_ARG.length .. $].strip().chompPrefix("=");
		}
	}

	return options;
}

void parseManagedParameters(string param)
{
	import std.algorithm.iteration;
	import std.algorithm.searching;

	foreach (string item; splitter(param, '&'))
	{
		auto pair = item.findSplit("=");
		auto key = strip(pair[0]);
		auto val = strip(pair[2]);

		if (key == "" || val == "")
		{
			continue;
		}

		if (config.isUnsignedShortValue(key))
		{
			config.setUnsignedShort(key, val);
		}
		else
		{
			config.setString(key, val);
		}
	}
}

unittest
{
	auto opt = parseArgs([".//flint", "managed", "--config=a.txt"], "wtf");
	assert(opt.is_managed && opt.config_filename == "a.txt");

	auto opt1 = parseArgs([".//flint", "--configb.txt"], "wtf");
	assert(!opt1.is_managed && opt1.config_filename == "b.txt");

	auto opt2 = parseArgs(["flint"], "a.txt");
	assert(!opt2.is_managed && opt2.config_filename == "a.txt");

	auto opt3 = parseArgs([".//flint", "manageda=b&c=d&port=3965"], "c.txt");
	assert(opt3.is_managed && opt3.config_filename == "c.txt");
	assert(config.getString("a") == "b");
	assert(config.getString("c") == "d");
	assert(config.getUnsignedShort("port") == 3965);

	assertThrown!Error(parseArgs([".//flint", "managedport=-1"], "wtf"));
}

int main(string[] args)
{
	string config_file;

	globalLogLevel(LogLevel.info);

	version (unittest)
	{
		globalLogLevel(LogLevel.trace);
	}

	debug
	{
		globalLogLevel(LogLevel.trace);
	}

	ArgOpt argOptions = parseArgs(args, "flint.config");

	info("Reading configuration file " ~ argOptions.config_filename);

	try
	{
		config_file = cast(string)read(argOptions.config_filename, 1024);
	}
	catch (FileException)
	{
		fatal("Could not read " ~ argOptions.config_filename);
	}

	config.readConfig(config_file);
	delete config_file;
	config.validateConfig(argOptions.is_managed);

	LibraryInitializer botan_init;

	cryptoRng = RandomNumberGenerator.makeRng();

	initEnigmaSetting();

	if (argOptions.is_managed)
	{
		fatal("Managed mode is not implemented");
	}

	switch (config.getString("type"))
	{
		case "client":
			info("Reading " ~ config.getString("keyfile"));
			auto pubkey = loadKey(config.getString("keyfile"));

			string pow = doProofOfWork();

			launchClient();
			auto keys = handshake(pubkey, pow);

			delete pubkey;

			clientMain(keys.expand);

			break;
		case "server":
			info("Reading " ~ config.getString("keyfile"));
			globalDecryptor = new RSAOAEPDecryptor(loadKey(config.getString("keyfile"), cryptoRng), cryptoRng);
			launchServer();

			break;
		default:
			fatal("Unknown running type: should be 'client' or 'server'");
	}

	delete globalDecryptor;
	cryptoRng.clear();
	return 0;
}
