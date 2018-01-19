module flint.config;

import std.experimental.logger.core;

private:

__gshared string[string] _items_string;
__gshared ushort[string] _items_ushort;

const static string[] mandatory_items_string = ["rotors", "rings", "reflector", "keyfile"];
const static string[] mandatory_items_ushort = ["timeout", "powleadingzero", "powfirstbytemax", "maxdisconnectdelay"];

const static string[] mandatory_items_string_when_unmanaged = ["type", "listen", "remote"];
const static string[] mandatory_items_ushort_when_unmanaged = ["port", "rport"];

const string[] values_ushort = mandatory_items_ushort ~ mandatory_items_ushort_when_unmanaged ~ ["powlife", "idletimeout"];

public:

bool isUnsignedShortValue(string key)
{
	import std.algorithm.searching;
	return canFind(values_ushort, key);
}

void readConfig(string config)
{
	import std.string;

	string key, val;
	ptrdiff_t pos;
	foreach (line; config.lineSplitter())
	{
		if (strip(line) == "")
		{
			continue;
		}
		pos = line.indexOf('=');
		if (pos == -1)
		{
			continue;
		}
		key = strip(line[0 .. pos]);
		val = strip(line[pos+1 .. line.length]);
		if (key == "" || val == "")
		{
			continue;
		}

		if (isUnsignedShortValue(key))
		{
			setUnsignedShort(key, val);
		}
		else
		{
			setString(key, val);
		}
	}
}

void validateConfig(bool is_managed)
{
	checkItem(mandatory_items_string, _items_string);

	checkItem(mandatory_items_ushort, _items_ushort);

	if (!is_managed)
	{
		checkItem(mandatory_items_string_when_unmanaged, _items_string);

		checkItem(mandatory_items_ushort_when_unmanaged, _items_ushort);
	}
}

void checkItem(T)(inout string[] required_fields, T[string] storage)
{
	foreach (string item; required_fields)
	{
		if ((item in storage) is null)
		{
			fatal("Missing item: " ~ item);
		}
	}
}

string getString(string key)
{
	auto ptr = (key in _items_string);

	if (ptr is null)
	{
		return null;
	}
	else
	{
		return *ptr;
	}
}

ushort getUnsignedShort(string key)
{
	auto ptr = (key in _items_ushort);

	if (ptr is null)
	{
		return 0;
	}
	else
	{
		return *ptr;
	}
}

void setString(string key, string value)
{
	_items_string[key] = value;
}

void setUnsignedShort(string key, string value)
{
	import std.conv;

	try
	{
		_items_ushort[key] = to!ushort(value);
	}
	catch (ConvException)
	{
		fatal("Could not convert " ~ key ~ " to ushort");
	}
}
