#pragma once

#include <thread>
#include <memory>
#include <condition_variable>
#include <unordered_map>

#include "sync_queue.hpp"

namespace sctp
{
class Server;
}
class IClient;

class Broadcaster
{
public:
	Broadcaster() = default;
	Broadcaster(const Broadcaster&) = delete;
	Broadcaster& operator=(const Broadcaster&) = delete;
	Broadcaster(Broadcaster&&) = delete;
	Broadcaster& operator=(Broadcaster&&) = delete;

	virtual ~Broadcaster();

	virtual void operator()(sctp::Server&);

	virtual void enqueue(std::vector<char>);

	virtual void add_new_client(std::shared_ptr<IClient>&);
	virtual void drop_client(std::shared_ptr<IClient>&);
	virtual void notify_send_possible(std::shared_ptr<IClient>&);

private:
	std::thread sender_thr_;

	std::unordered_map<std::shared_ptr<IClient>,
	std::unique_ptr<SyncQueue<std::shared_ptr<std::vector<char>>>>> send_qs_;
	std::mutex signals_mutex_;
	std::condition_variable cv_;
	bool signal_send_possible_ { false };
	bool signal_new_data_ { false };
	bool signal_sender_thr_running_ { true };

	std::unordered_map<std::shared_ptr<IClient>, bool> send_flags_;

	std::shared_ptr<IClient> client_send_possible_;	
};