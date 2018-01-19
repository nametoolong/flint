module flint.listener;

private:

import core.thread;

import std.socket;

public:

class SimpleThreadingListener(T : Thread) : Thread
{
	Socket sock;

	this(string listen, ushort port)
	{
		Socket socket = new Socket(AddressFamily.INET, SocketType.STREAM);
		socket.bind(new InternetAddress(listen, port));
		sock = socket;
		super.isDaemon(true);
		super(&run);
	}

	private void run()
	{
		thread_attachThis();
		try
		{
			sock.listen(5); // magic number for windows
			while (true)
			{
				new T(sock.accept()).start();
			}
		}
		finally
		{
			thread_detachThis();
		}
	}
}
