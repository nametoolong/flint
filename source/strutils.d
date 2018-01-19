module flint.strutils;

private import std.exception : assumeUnique;

@nogc bool containsChar(inout char[] str, char needle) pure nothrow
{
	foreach (ch; str)
	{
		if (ch == needle)
		{
			return true;
		}
	}

	return false;
}

char[] remove_spaces(inout char[] string, size_t length) pure
{
	char[] buf = new char[length];

	size_t i = 0;
	foreach (ch; string)
	{
		if (ch != ' ')
		{
			buf[i++] = ch;
		}
		if (i == length)
		{
			break;
		}
	}

	if (i < length)
	{
		buf.length = i;
	}

	return buf;
}

string remove_spaces_string(inout char[] string, size_t length) pure
{
	return assumeUnique(remove_spaces(string, length));
}

char[] strip_all(char[] string, inout char[] remove, size_t length) pure
{
	char[] buf = new char[length];

	size_t i = 0;
	foreach (ch; string)
	{
		if (!remove.containsChar(ch))
		{
			buf[i++] = ch;
		}
		if (i == length)
		{
			break;
		}
	}

	if (i < length)
	{
		buf.length = i;
	}

	return buf;
}

char[] unsafe_lower(string string) pure
{
	char[] buf = new char[string.length];
	size_t i = 0;
	foreach (ch; string)
	{
		buf[i++] = cast(char)(cast(ubyte)ch + 32);
	}
	return buf;
}

string pack_uint(uint val) pure nothrow
{
	return [val >> 24, (val << 8) >> 24, (val << 16) >> 24, (val << 24) >> 24];
}

uint unpack_uint(inout ubyte[] arr) pure nothrow
{
	return (arr[0] << 24) + (arr[1] << 16) + (arr[2] << 8) + arr[3];
}

unittest
{
	assert(remove_spaces(cast(char[])"ABCDE FGHIJKLMNOP QRSTUVWX YZ", 26) == "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	assert(remove_spaces(cast(char[])"ABCDE FGHIJKLMNOP QRSTUVWX YZ", 60) == "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	assert(remove_spaces(cast(char[])"ABCDE FGHIJKLMNOP QRSTUVWX YZ", 23) == "ABCDEFGHIJKLMNOPQRSTUVW");
	assert(strip_all(cast(char[])"ABCDE FGHIJKLMNOP QRSTUVWX YZ", "Z ", 25) == "ABCDEFGHIJKLMNOPQRSTUVWXY");
	assert(strip_all(cast(char[])"ABCDE FZZZZZZGHIJKLZZZZZZMNOPZZZ QRSTUVWX YZZZZZZ", "YZ ", 26) == "ABCDEFGHIJKLMNOPQRSTUVWX");

	assert(unsafe_lower("ACFDSFJKSSDFSFSDFSLKLKLDFSDFSDFLSFLSFDSFSDF") == "acfdsfjkssdfsfsdfslklkldfsdfsdflsflsfdsfsdf");
	assert(unsafe_lower("ACFDSFJKSSDFSFSDFSLKLKLDFSDFAAABBBLSFDSFSDF") == "acfdsfjkssdfsfsdfslklkldfsdfaaabbblsfdsfsdf");

	assert(unpack_uint(cast(ubyte[])pack_uint(4294967295U)) == 4294967295U);
	assert(unpack_uint(cast(ubyte[])pack_uint(14235635U)) == 14235635U);
	assert(unpack_uint(cast(ubyte[])pack_uint(453453U)) == 453453U);
	assert(unpack_uint(cast(ubyte[])pack_uint(4243U)) == 4243U);
	assert(unpack_uint(cast(ubyte[])pack_uint(0)) == 0);
}
