module flint.enigma;

private:

import flint.strutils : containsChar;

import std.exception : assumeUnique;
import std.string;

const ORD_A = cast(int)'A';

shared static this()
{
	ROTORS["I"] = "EKMFLGDQVZNTOWYHXUSPAIBRCJ" ~ "Q";
	ROTORS["II"] = "AJDKSIRUXBLHWTMCQGZNPYFVOE" ~ "E";
	ROTORS["III"] = "BDFHJLCPRTXVZNYEIWGAKMUSQO" ~ "V";
	ROTORS["IV"] = "ESOVPZJAYQUIRHXLNFTGKDCMWB" ~ "J";
	ROTORS["V"] = "VZBRGITYUPSDNHLXAWMJQOFECK" ~ "Z";
	ROTORS["VI"] = "JPGVOUMFYQBENHZRDKASXLICTW" ~ "ZM";
	ROTORS["VII"] = "NZJHGRCXMYSWBOUFAIVLPEKQDT" ~ "ZM";
	ROTORS["VIII"] = "FKQHTLXOCBJSPDZRAMEWNIUYGV" ~ "ZM";
	REFLECTORS["B"] = "YRUHQSLDPXNGOKMIEBFZCWVJAT";
	REFLECTORS["C"] = "FVPJIAOYEDRZXWGCTKUQSBNMHL";
	REFLECTORS["B-Thin"] = "ENKQAUYWJICOPBLMDXZVFTHRGS";
	REFLECTORS["C-Thin"] = "RDOBJNTKVEHMLFCWZAXGYIPSUQ";
}

immutable(int[26]) make_entry_map(string wiring)
{
	int[26] map;
	for (int i = 0; i < 26; i++)
	{
		map[i] = wiring[i] - ORD_A;
	}
	return map;
}

immutable(int[26]) make_exit_map(int[26] entry_map)
{
	int[26] map;
	for (int i = 0; i < 26; i++)
	{
		map[entry_map[i]] = i;
	}
	return map;
}



public:

__gshared const string[string] ROTORS;
__gshared const string[string] REFLECTORS;

struct Rotor
{
	immutable int[26] entry_map;
	immutable int[26] exit_map;
	char[26] display_map;
	char[] stepping;
	char pos = 0;

	@disable this();

	this(string wiring)
	{
		this(wiring, 0, "");
	}

	this(string wiring, int ring, string stepping)
	{
		entry_map = make_entry_map(wiring);

		exit_map = make_exit_map(entry_map);

		for (int i = 0; i < 26; i++)
		{
			display_map[i] = ((i - ring + 25974) % 26) & 0xFF;
		}

		this.stepping = new char[stepping.length];

		for (int i = 0; i < stepping.length; i++)
		{
			this.stepping[i] = display_map[stepping[i] - ORD_A];
		}

		setDisplay('A');
	}

	public static Rotor createRotor(string model, int ring_setting)
	{
		auto ptr = model in ROTORS;

		if (ptr is null)
		{
			throw new Exception("Could not find rotor settings for " ~ model);
		}

		auto wiring = (*ptr)[0 .. 26];
		auto stepping = (*ptr)[26 .. $];

		return Rotor(wiring, ring_setting, stepping);
	}

	public static Rotor createReflector(string model)
	{
		auto ptr = model in REFLECTORS;

		if (ptr is null)
		{
			throw new Exception("Could not find reflector settings for " ~ model);
		}

		return Rotor(*ptr);
	}

	public void setDisplay(char val)
	{
		pos = display_map[val - ORD_A];
	}

	pure public int signal_in(int n)
	{
		return (entry_map[(n + pos) % 26] - pos + 25974) % 26;
	}

	pure public int signal_out(int n)
	{
		return (exit_map[(n + pos) % 26] - pos + 25974) % 26;
	}

	pure public bool notch_over_pawl()
	{
		return stepping.containsChar(pos);
	}

	public void rotate()
	{
		pos = (pos + 1) % 26;
	}
}

class EnigmaMachine
{
	Rotor[3] rotors;
	Rotor reflector;

	private this(Rotor rotor0, Rotor rotor1, Rotor rotor2, Rotor reflector)
	{
		rotors = [rotor0, rotor1, rotor2];
		this.reflector = reflector;
	}

	public static EnigmaMachine fromKeySheet(string list_rotors, string list_ring_settings, string reflector)
	{
		import std.conv;

		string[] _rotors = split(list_rotors);
		string[] _ring_settings = split(list_ring_settings);

		return new EnigmaMachine(Rotor.createRotor(_rotors[0], to!int(_ring_settings[0])),
								 Rotor.createRotor(_rotors[1], to!int(_ring_settings[1])),
								 Rotor.createRotor(_rotors[2], to!int(_ring_settings[2])),
								 Rotor.createReflector(reflector));
	}

	public void setDisplay(inout char[] val)
	{
		for (int i = 2; i >= 0; --i)
		{
			char b = val[i];
			if (b < 'A' || b > 'Z')
			{
				return;
			}
			rotors[i].setDisplay(val[i]);
		}
	}

	private void step_rotors()
	{
		rotors[2].rotate();
		if (rotors[2].notch_over_pawl() || rotors[1].notch_over_pawl())
		{
			rotors[1].rotate();
		}
		if (rotors[1].notch_over_pawl())
		{
			rotors[0].rotate();
		}
	}

	private int electric_signal(int signal_num)
	{
		int pos = signal_num;

		pos = rotors[2].signal_in(pos);
		pos = rotors[1].signal_in(pos);
		pos = rotors[0].signal_in(pos);

		pos = reflector.signal_in(pos);

		pos = rotors[0].signal_out(pos);
		pos = rotors[1].signal_out(pos);
		pos = rotors[2].signal_out(pos);

		return pos;
	}

	public string processText(string text)
	{
		char[] buf = new char[text.length];
		size_t i = 0;
		foreach (char ch; text)
		{
			int signal_num = cast(int)ch - ORD_A;

			if (signal_num < 0 || signal_num > 25) {
				throw new Exception("Non-uppercase input");
			}

			step_rotors();

			buf[i++] = cast(char)(65 + electric_signal(signal_num));
		}

		return assumeUnique(buf);
	}
}

unittest
{
	auto eni = EnigmaMachine.fromKeySheet("II VI V", "1 16 7", "B-Thin");
	eni.setDisplay("WTF");
	assert(eni.processText("AJSOFDJISODHSFISJCSIPFDFSIPDUSIOPDJFSOIPIDOSDIOPRIEROPS") == "SXMRULHQEYYPVEKYHQQTHEORUOBKIHVEAOLXUSSEWJFWMLAGQRSEEVF");
	assert(eni.processText("DJFADFADFLADKFADSLASKDFLSD") == "TSRSTZNBSCBKAKMRBOJCOXTQTU");
}
