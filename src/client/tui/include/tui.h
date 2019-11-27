#pragma once

#include <string>
#include <atomic>
#include <thread>
#include <functional>
#include <ncurses.h>

#include "sync_queue.hpp"


using TUI_cback_t = std::function<void(const std::string&)>;

class TUI {
public:
	TUI();

	TUI(const TUI& oth) = delete;
	
	TUI& operator=(const TUI& oth) = delete;

 	//initializes ncurses stuff
	void init(TUI_cback_t cback);

	//does blocking select on stdin and evals input
	void loop(); 

	//queues to internal string queue
	void put_message(const std::string&);

	void stop();
	
	virtual ~TUI();
	
private:
	std::atomic_bool should_handle_input_ { true };
	std::atomic_bool running_ { true };

	TUI_cback_t cback_;
	std::string message;
	SyncQueue<std::string> q;
	std::thread log_thr;

	int pipefd[2];

	void handle_input();
	void handle_resize();

	//pops item from internal queue and displays it
	void display_func();

};	
