module flint.connman;

private:

import std.meta;

const size_t EDGE_CONNECTIONS_INITIAL_LENGTH = 32;

public:

import std.socket;

enum Result
{
	FINISHED,
	CONNECTION_ALREADY_CLOSED,
	CID_NOT_IN_RANGE,
	CLOSING_CONNECTION
}

struct SocketId
{
	Socket socket;
	uint id;
}

final class ConnectionManager
{
	private Socket[] edge_connections;

	private uint curr_cid = 0;

	private Address remote;
	private bool ipv6;

	this(string remote_addr, ushort remote_port)
	{
		edge_connections.length = EDGE_CONNECTIONS_INITIAL_LENGTH;

		ipv6 = isIP6Addr(remote_addr);

		if (ipv6)
		{
			remote = new Internet6Address(remote_addr[1 .. $ - 1], remote_port);
		}
		else
		{
			remote = new InternetAddress(remote_addr, remote_port);
		}
	}

	~this()
	{
		foreach (conn; edge_connections)
		{
			if (conn !is null)
			{
				conn.close();
			}
		}
	}

	bool isIP6Addr(string addr)
	{
		return addr.length >= 4 && addr[0] == '[' && addr[$ - 1] == ']';
	}

	void addToSet(ref SocketSet ss)
	{
		foreach (conn; edge_connections)
		{
			if (conn !is null)
			{
				ss.add(conn);
			}
		}
	}

	uint connect()
	{
		if (curr_cid == edge_connections.length)
		{
			edge_connections.length += EDGE_CONNECTIONS_INITIAL_LENGTH;
		}

		Socket edge_sock;

		if (ipv6)
		{
			edge_sock = new Socket(AddressFamily.INET6, SocketType.STREAM);
		}
		else
		{
			edge_sock = new Socket(AddressFamily.INET, SocketType.STREAM);
		}

		edge_sock.blocking(false);
		edge_sock.connect(remote);
		edge_connections[curr_cid] = edge_sock;

		return curr_cid++;
	}

	Result disconnect(uint cid)
	{
		if (cid >= curr_cid)
		{
			return Result.CID_NOT_IN_RANGE;
		}

		if (edge_connections[cid] is null)
		{
			return Result.CONNECTION_ALREADY_CLOSED;
		}

		edge_connections[cid].shutdown(SocketShutdown.BOTH);
		edge_connections[cid].close();
		edge_connections[cid] = null;

		return Result.FINISHED;
	}

	void remove(uint cid)
	{
		edge_connections[cid].close();
		edge_connections[cid] = null;
	}

	Result send(uint cid, string data)
	{
		if (cid >= curr_cid)
		{
			return Result.CID_NOT_IN_RANGE;
		}

		if (edge_connections[cid] is null)
		{
			return Result.CONNECTION_ALREADY_CLOSED;
		}

		long len = edge_connections[cid].send(data); // close if we couldn't send everything at once; who cares?

		if (len != data.length)
		{
			edge_connections[cid].close();
			edge_connections[cid] = null;

			return Result.CLOSING_CONNECTION;
		}

		return Result.FINISHED;
	}

	SocketId[] socketsInSets(Types...)(Types sss) if (Types.length != 0 && allSatisfy!((T) => is(T : SocketSet), Types))
	{
		SocketId[] arr;
		arr.length = curr_cid;

		size_t ptr = 0;

		find:
		for (uint i = 0; i < curr_cid; i++)
		{
			if (edge_connections[i] is null)
			{
				continue;
			}

			foreach (SocketSet ss; sss)
			{
				if (ss.isSet(edge_connections[i]))
				{
					arr[ptr++] = SocketId(edge_connections[i], i);
					continue find;
				}
			}
		}

		arr.length = ptr;
		return arr;
	}
}
