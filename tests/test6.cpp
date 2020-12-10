#include <iostream>
#include <string>

#include <boost/assert.hpp>

#include "sync_queue.hpp"


int main(int, char const**) {
	constexpr auto Q_SIZE {50u};
	constexpr auto Q_LIMIT {10u};

	{
		SyncQueue<int> q;
		for (auto i = 0u; i < Q_SIZE; ++i) q.enqueue(i);
		BOOST_ASSERT(q.size() == Q_SIZE);
		q.dequeue();
		BOOST_ASSERT(q.size() == Q_SIZE-1);
	}


	{
		SyncQueue<int> q {Q_LIMIT};
		for (auto i = 0u; i < Q_SIZE; ++i) q.enqueue(i);
		BOOST_ASSERT(q.size() == Q_LIMIT);
		q.dequeue();
		BOOST_ASSERT(q.size() == Q_LIMIT-1);
	}


	return EXIT_SUCCESS;
}
