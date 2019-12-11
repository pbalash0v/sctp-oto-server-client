#pragma once

#include <atomic>
#include <thread>
#include <ncurses.h>


#include "sync_queue.hpp"
#include "i_tui.h"


class TUI : public ITUI
{
public:
	TUI();

	TUI(const TUI& oth) = delete;
	
	TUI& operator=(const TUI& oth) = delete;

 	/* initializes ncurses stuff */
	virtual void init(ITUI_cback_t cback) override;

	/* does blocking select on stdin and evals input */
	virtual void loop() override; 

	/* queues to internal string queue */
	virtual void put_message(const std::string&) override;

	virtual void put_log(LogLevel, const std::string&) override;

	virtual void set_log_level(ITUI::LogLevel) override;

	virtual void stop() override;
	
	virtual ~TUI();
	
private:
	std::atomic_bool should_handle_input_ { true };
	std::atomic_bool running_ { true };

	ITUI_cback_t cback_;
	std::string message;
	SyncQueue<std::string> q;
	std::thread log_thr;

	ITUI::LogLevel verbosity { ITUI::TRACE };

	int pipefd[2];

	void handle_input();
	void handle_resize();

	//pops item from internal queue and displays it
	void display_func();

};	
