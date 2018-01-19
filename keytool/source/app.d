import botan.pubkey.algo.rsa;
static import botan.pubkey.pkcs8;
import botan.pubkey.pubkey;
static import botan.pubkey.x509_key;
import botan.rng.rng;
import botan.rng.auto_rng;

import std.file;

void main()
{
	RandomNumberGenerator rng = cast(RandomNumberGenerator) new AutoSeededRNG;

	auto privkey = RSAPrivateKey(rng, 2048);
	auto pubkey = RSAPublicKey(privkey);
	
	string privkeyPEM = botan.pubkey.pkcs8.PEM_encode(cast(PrivateKey)privkey);
	string pubkeyPEM = botan.pubkey.x509_key.PEM_encode(cast(PublicKey)pubkey);

	write("pubkey.key", pubkeyPEM);
	write("privkey.key", privkeyPEM);
}
