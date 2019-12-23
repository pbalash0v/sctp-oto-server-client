#pragma once

#include <queue>
#include <thread>
#include <condition_variable>


template <typename T>
class SyncQueue {
public:
	SyncQueue(size_t max_queued = 0) 
		: max_queued_(max_queued) {};
	~SyncQueue() {};
	SyncQueue(const SyncQueue<T>& other) = delete;
	SyncQueue<T>& operator=(const SyncQueue<T>& oth) = delete;

	T dequeue();

	void enqueue(const T&);
	void enqueue(T&&);

	bool isEmpty();
	size_t size();

private:
	size_t max_queued_;
	std::queue<T> q;
	std::mutex qMutex;
	std::condition_variable cv;
};


template <typename T>
T SyncQueue<T>::dequeue() {
	std::unique_lock<std::mutex> lock(qMutex);

	cv.wait(lock, [&]{ return (not q.empty()); });

	auto ret = std::move(q.front());
   q.pop();
   
   return ret;
}


template <typename T>
void SyncQueue<T>::enqueue(const T& elem) {
	{
		std::lock_guard<std::mutex> _(qMutex);

		if ((max_queued_ > 0) and (q.size() == max_queued_)) q.pop();

		q.push(elem);
	}

	cv.notify_one();
}


template <typename T>
void SyncQueue<T>::enqueue(T&& elem) {
	{
		std::lock_guard<std::mutex> _(qMutex);

		if ((max_queued_ > 0) and (q.size() == max_queued_)) q.pop();

		q.push(std::move(elem));
	}

	cv.notify_one();
}


template <typename T>
bool SyncQueue<T>::isEmpty() {
	std::lock_guard<std::mutex> _ { qMutex };
	return q.empty();
}


template <typename T>
size_t SyncQueue<T>::size() {
	std::lock_guard<std::mutex> _ { qMutex };
	return q.size();
}