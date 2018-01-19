module flint.messages;

private:

import flint.fastrng;

import std.exception : assumeUnique;
import std.random;

const size_t CONTROL_MESSAGE_PADDING_LENGTH_MAX = 640;

FastXorshiftStar create_fastrng()
{
	char[] s = new char[16];
	for (size_t i = 0; i < 16; i++)
	{
		s[i] = uniform(0, 256) & 0xFF;
	}
	return FastXorshiftStar(s);
}

string fast_random_data(size_t length, ref FastXorshiftStar rng)
{
	char[] buf = new char[length];
	for (size_t i = 0; i < length; i++)
	{
		buf[i] = rng.get();
	}
	return assumeUnique(buf);
}

string fast_random_length_random_data(size_t upper_bound, ref FastXorshiftStar rng)
{
	return fast_random_data(uniform(0, upper_bound), rng);
}

string make_message_padding(ref FastXorshiftStar rng)
{
	return fast_random_length_random_data(CONTROL_MESSAGE_PADDING_LENGTH_MAX, rng);
}

public:

final class MessagePacker
{
	FastXorshiftStar fastrng;

	this()
	{
		fastrng = create_fastrng();
	}

	string createStreamMessage()
	{
		return 'c' ~ fastrng.make_message_padding();
	}

	string createStreamSuccessMessage(string cid)
	{
		return 'c' ~ cid ~ fastrng.make_message_padding();
	}

	string destroyStreamMessage(string cid)
	{
		return 'd' ~ cid ~ fastrng.make_message_padding();
	}

	string dataMessage(string cid, in char[] data) pure
	{
		return 'm' ~ cid ~ data.idup;
	}
}
