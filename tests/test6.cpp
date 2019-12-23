#include <iostream>
#include <string>
#include <cassert>

#include "sync_queue.hpp"


int main(int, char const**) {
	constexpr auto Q_SIZE = 50;	
	constexpr auto Q_LIMIT = 10;

	{
		SyncQueue<int> q;
		for (int i = 0; i < Q_SIZE; ++i) q.enqueue(i);
		assert(q.size() == Q_SIZE);
		q.dequeue();
		assert(q.size() == Q_SIZE-1);
	}


	{
		SyncQueue<int> q(Q_LIMIT);
		for (int i = 0; i < Q_SIZE; ++i) q.enqueue(i);
		assert(q.size() == Q_LIMIT);
		q.dequeue();
		assert(q.size() == Q_LIMIT-1);
	}


	return EXIT_SUCCESS;
}
