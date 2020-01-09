#pragma once

#include <thread>
#include <memory>
#include <condition_variable>
#include <unordered_map>

#include "sync_queue.hpp"
#include "sctp_data.h"

class SCTPServer;
class IClient;

class Broadcaster
{
public:
	Broadcaster() = default;
	Broadcaster(const Broadcaster&) = delete;
	Broadcaster& operator=(const Broadcaster&) = delete;

	virtual ~Broadcaster();

	virtual void operator()(SCTPServer&);

	virtual void enqueue(std::unique_ptr<sctp::Data>);

	virtual void add_new_client(std::shared_ptr<IClient>&);
	virtual void drop_client(std::shared_ptr<IClient>&);
	virtual void notify_send_possible(std::shared_ptr<IClient>&);

private:
	std::thread sender_thr_;

	std::unordered_map<std::shared_ptr<IClient>,
	std::unique_ptr<SyncQueue<std::shared_ptr<sctp::Data>>>> send_qs_;
	std::mutex signals_mutex_;
	std::condition_variable cv_;
	bool signal_send_possible_ { false };
	bool signal_new_data_ { false };
	bool signal_sender_thr_running_ { true };

	std::unordered_map<std::shared_ptr<IClient>, bool> send_flags_;

	std::shared_ptr<IClient> client_send_possible_;	
};