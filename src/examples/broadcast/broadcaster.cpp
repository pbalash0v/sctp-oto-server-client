#include "spdlog/spdlog.h"
#include "spdlog/fmt/ostr.h"

#include "broadcaster.hpp"
#include "sctp_server.hpp"

Broadcaster::~Broadcaster()
{
	{
	 	std::lock_guard<std::mutex> _ { signals_mutex_ };
		signal_sender_thr_running_ = false;
	}
	cv_.notify_one();
	if (sender_thr_.joinable()) sender_thr_.join();
}

void Broadcaster::operator()(sctp::Server& s)
{
	sender_thr_ = std::thread {[&]()
	{
		spdlog::debug("sender_thr started.");

		while (signal_sender_thr_running_)
		{
			std::unique_lock<std::mutex> lock { signals_mutex_ };

			cv_.wait(lock, [&]
			{
				return signal_new_data_ or signal_send_possible_ or not signal_sender_thr_running_;
 			});

			spdlog::trace("sender_thr notified with send_flag: {}, data_flag: {}, not running: {}.",
				 signal_send_possible_, signal_new_data_, not signal_sender_thr_running_);

			if (signal_send_possible_)
			{
				if (send_qs_[client_send_possible_]->isEmpty()) {
					spdlog::trace("queue for {} is empty.", *client_send_possible_);
					send_flags_[client_send_possible_] = true;
				} else {
					auto data = send_qs_[client_send_possible_]->dequeue();
					spdlog::trace("sending {} bytes of data for {}.", data->size(), *client_send_possible_);
					s.send(client_send_possible_, data->data(), data->size());
					send_flags_[client_send_possible_] = false;
				}
				signal_send_possible_ = false;
			}

			if (signal_new_data_)
			{
				spdlog::trace("signal_new_data");
			 	for (const auto& q : send_qs_) {
			 		if (not send_flags_[q.first]) {
						spdlog::trace("Send flag for {} is false. Can not send data.", *(q.first));
			 			continue;
		 			}
					auto data = send_qs_[q.first]->dequeue();
					spdlog::trace("sending {} bytes of data for {}.", data->size(), *(q.first));
					auto c = q.first;
					s.send(c, data->data(), data->size());
					send_flags_[q.first] = false;
		 		}
		 		signal_new_data_ = false;
			}
		}

		spdlog::debug("sender_thr ended.");
	} };
}

void Broadcaster::enqueue(std::vector<char> d)
{
	std::shared_ptr<std::vector<char>> cli_data = std::make_shared<std::vector<char>>(std::move(d));
	{
		std::lock_guard<std::mutex> _ {signals_mutex_};

		for (const auto& q : send_qs_)
			q.second->enqueue(cli_data);
		signal_new_data_ = true;
	}

	cv_.notify_one();
}

void Broadcaster::add_new_client(std::shared_ptr<IClient> c)
{
	std::lock_guard<std::mutex> _ { signals_mutex_ };
	send_qs_[c] = std::make_unique<SyncQueue<std::shared_ptr<std::vector<char>>>>();
}

void Broadcaster::drop_client(std::shared_ptr<IClient> c)
{
 	std::lock_guard<std::mutex> _ {signals_mutex_};
 	auto& cli_q = *send_qs_[c];

 	if (not cli_q.isEmpty())
 	{
		spdlog::warn("Dropping {} unsent mesages for {}", cli_q.size(), *c);
	 	while (cli_q.size())
	 	{
	 		auto msg = cli_q.dequeue();
			std::string message {static_cast<const char*>(msg->data()), msg->size()};
			spdlog::debug("{}", ((message.size() < 30) ? message : message.substr(0, 30)));
		}
	}

	send_qs_.erase(c);
}

void Broadcaster::notify_send_possible(std::shared_ptr<IClient> c)
{
	{
		std::lock_guard<std::mutex> _ {signals_mutex_};
		client_send_possible_ = c;
		signal_send_possible_ = true;
	}

	cv_.notify_one();
}
