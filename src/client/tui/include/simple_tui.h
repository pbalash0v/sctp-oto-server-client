#pragma once

#include <atomic>
#include <thread>

#include "sync_queue.hpp"
#include "i_tui.h"


class SimpleTUI : public ITUI {
public:
	SimpleTUI();

	SimpleTUI(const SimpleTUI& oth) = delete;
	
	SimpleTUI& operator=(const SimpleTUI& oth) = delete;

	virtual void init(ITUI_cback_t cback) override;

	//does blocking select on stdin and evals input
	virtual void loop() override; 

	//queues to internal string queue
	virtual void put_message(const std::string&) override;

	virtual void stop() override;
	
	virtual ~SimpleTUI();
	
private:
	std::atomic_bool should_handle_input_ { true };
	std::atomic_bool running_ { true };

	ITUI_cback_t cback_;
	std::string message;
	SyncQueue<std::string> q;
	std::thread log_thr;

	int pipefd[2];

	void handle_input();

	//pops item from internal queue and displays it
	void display_func();

};	
