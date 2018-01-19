module flint.fastrng;

struct FastXorshiftStar
{
	char[] s;
	size_t p = 0;
	char i = 0;

	@disable this();
	@disable this(this);

	this(char[] arr)
	{
		assert(arr.length == 16, "Seed should be 16 bytes long");

		s = arr.dup;
	}

	char get()
	{
		char s1 = s[p = (p + 1) & 15];
		i = s[(i + s1) & 15];
		s1 ^= s1 << 5;
		i ^= i >> 3;
		return (s[p] = i ^ s1) & 255;
	}
}

unittest
{
	int[256] sp;

	auto fs = FastXorshiftStar([4, 1, 3, 6, 6, 3, 1, 6, 1, 2, 4, 2, 5, 6, 1, 2]);
	// chosen by fair dice roll, guaranteed to be random

	int TIME = 2000000;

	for (int i = 0; i < TIME; i++)
	{
		sp[fs.get()]++;
	}

	foreach (val; sp)
	{
		if (val < (TIME / 300))
		{
			assert(0, "FastXorshiftStar appears to be not random");
		}
	}
}
