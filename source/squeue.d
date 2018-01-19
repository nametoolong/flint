module flint.squeue;

private:

import core.sync.semaphore;

import std.container.dlist;

public:

final class SharedQueue(T)
{
	private DList!(T) dlist;
	private Semaphore semaphore;
	private bool destroyed = false;

	this()
	{
		dlist = DList!(T)();
		semaphore = new Semaphore;
	}

	T get()
	{
		if (destroyed)
		{
			if (!semaphore.tryWait())
			{
				return null;
			}
		}
		else
		{
			semaphore.wait();
		}
		
		synchronized (this)
		{
			if (dlist.empty)
			{
				return null;
			}

			auto result = dlist.front;
			dlist.removeFront();
			return result;
		}
	}

	T get(Duration timeout)
	{
		if (destroyed)
		{
			if (!semaphore.tryWait())
			{
				return null;
			}
		}
		else
		{
			if (!semaphore.wait(timeout))
			{
				return null;
			}
		}

		synchronized (this)
		{
			if (dlist.empty)
			{
				return null;
			}

			auto result = dlist.front;
			dlist.removeFront();
			return result;
		}
	}

	bool put(T thing)
	{
		if (destroyed)
		{
			return false;
		}

		synchronized (this)
		{
			dlist.insertBack(thing);
		}
		semaphore.notify();
		return true;
	}

	void dispose()
	{
		synchronized (this)
		{
			destroyed = true;
		}
		semaphore.notify();
	}

	void clear()
	{
		synchronized (this)
		{
			dlist.clear();
		}
		semaphore.notify();
	}
}
