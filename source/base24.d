module base24;

private import std.string;

string enbase(ubyte[] text, string alphabet) pure
{
	char[] buf = new char[text.length<<1];

	for (size_t i = 0; i < text.length; i++)
	{
		size_t l = i << 1;
		buf[l] = alphabet[text[i] >> 4];
		buf[l + 1] = alphabet[23 - (text[i] & 0x0F)];
	}

	return buf;
}
 
string debase(inout char[] text, string alphabet) pure
{
	assert(!(text.length & 1), "Length of input should be multiple of 2");

	size_t len = text.length >> 1;
	char[] buf = new char[len];

	for (size_t i = 0; i < len; i++)
	{
		size_t l = i << 1;
		long q = alphabet.indexOf(text[l]);
		long d = alphabet.indexOf(text[l + 1]);

		if (q == -1 || d == -1) {
			throw new Exception("Letter not in alphabet");
		}

		buf[i] = cast(char)((q << 4) | (23 - d));
	}

	return buf;
}

unittest
{
	import core.exception;

	import std.exception;

	assert(enbase(cast(ubyte[])"sdfgsfdsfsdgdgdfsgdfsgrhrth", "ABCDEFGHIJKLMNOPQRSTUVWX") == "HUGTGRGQHUGRGTHUGRHUGTGQGTGQGTGRHUGQGTGRHUGQHVGPHVHTGP");
	assert(debase(cast(char[])"HUGTGRGQHUGRGTHUGRHUGTGQGTGQGTGRHUGQGTGRHUGQHVGPHVHTGP", "ABCDEFGHIJKLMNOPQRSTUVWX") == "sdfgsfdsfsdgdgdfsgdfsgrhrth");
	assert(enbase(cast(ubyte[])"4354herg57657&*()@#&$)*(#*$9gd];[l;,l;", "BCDEFGHIJKLMNOPQRSTUVWXZ") == "EUEVETEUHQHTIWHRETERESETERDSDODQDPFZDVDSDUDPDODQDVDODUEPHRHUGLENGNHMENDMHMEN");
	assert(debase(cast(char[])"EUEVETEUHQHTIWHRETERESETERDSDODQDPFZDVDSDUDPDODQDVDODUEPHRHUGLENGNHMENDMHMEN", "BCDEFGHIJKLMNOPQRSTUVWXZ") == "4354herg57657&*()@#&$)*(#*$9gd];[l;,l;");
	assertThrown!AssertError(debase(cast(char[])"ABC", "BCDEFGHIJKLMNOPQRSTUVWXZ"));
	assertThrown!AssertError(debase(cast(char[])"C", "BCDEFGHIJKLMNOPQRSTUVWXZ"));
	assertThrown!AssertError(debase(cast(char[])"BCDEFGHIJKLMNOPQRSTUVWXZQ", "BCDEFGHIJKLMNOPQRSTUVWXZ"));
	assertThrown(debase(cast(char[])"ABCD", "BCDEFGHIJKLMNOPQRSTUVWXZ"));
}
