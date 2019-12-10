#pragma once

#include <queue>
#include <thread>
#include <condition_variable>


template <typename T>
class SyncQueue {
public:
	SyncQueue() {};
	
	~SyncQueue() {};

	SyncQueue(const SyncQueue<T>& other) = delete;
	
	SyncQueue<T>& operator=(const SyncQueue<T>& oth) = delete;

	T dequeue();
	
	void enqueue(const T& s);

	bool isEmpty();

	size_t size();

private:
	std::queue<T> q;
	std::mutex qMutex;
	std::condition_variable cv;
};



template <typename T>
T SyncQueue<T>::dequeue() {
	std::unique_lock<std::mutex> lock(qMutex);

	cv.wait(lock, [&]{ return (not q.empty()); });

	auto ret = q.front();
   q.pop();
   
   return ret;
}


template <typename T>
void SyncQueue<T>::enqueue(const T& s) {
	{
		std::lock_guard<std::mutex> lock(qMutex);
		q.push(s);
	}

	cv.notify_one();
}


template <typename T>
bool SyncQueue<T>::isEmpty() {
	std::lock_guard<std::mutex> lock(qMutex);
	return q.empty();
}

template <typename T>
size_t SyncQueue<T>::size() {
	std::lock_guard<std::mutex> lock(qMutex);
	return q.size();
}