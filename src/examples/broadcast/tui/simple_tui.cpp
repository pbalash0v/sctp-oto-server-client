#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <errno.h>
#include <sys/select.h>

#include "spdlog/spdlog.h"

#include "simple_tui.h"


constexpr const char* END_SIGNAL = "e";


SimpleTUI::SimpleTUI()
{

	log_thr = std::thread(&SimpleTUI::display_func, this);

	if (pipe(pipefd) == -1) {
		throw std::runtime_error(strerror(errno));
	}

	spdlog::set_level(spdlog::level::trace);
}

SimpleTUI::~SimpleTUI()
{
	/* wakeup & finish logger thread */
	running_ = false;
	put_message("");
	log_thr.join();

   close(pipefd[0]);
   close(pipefd[1]);
}

/*
	runs in separate thread, dequeues and renders text
*/
void SimpleTUI::display_func()
{
	while (running_) {
		std::cout << q.dequeue();
	}
}

void SimpleTUI::init(ITUI_cback_t cback)
{
	cback_ = cback;
}


void SimpleTUI::loop()
{
	fd_set set;
	int res;
	
	while (should_handle_input_) {
		FD_ZERO(&set);
		FD_SET(STDIN_FILENO, &set);
		FD_SET(pipefd[0], &set);

		res = select(pipefd[0] + 1, /* read */ &set, NULL, NULL, /* no timeout */ NULL);

		if (res < 0) {
			if (errno != EINTR) {
				std::cerr << std::string("select returned error: ") + 
								std::string(strerror(errno)) << std::endl;
				running_ = false;
				continue;
			}
		}

      if (FD_ISSET(pipefd[0], &set)) {
      	char buf[strlen(END_SIGNAL)];

      	int bytes_read = read(pipefd[0], &buf, sizeof buf);

      	if (bytes_read <= 0) {
				if (errno != EINTR) throw std::runtime_error(strerror(errno));
   		}

   		if (bytes_read > 0) {
				should_handle_input_ = false;
				put_message("Received END_SIGNAL on self pipe.\n");
				continue;				
			}
      }

      if (FD_ISSET(STDIN_FILENO, &set)) {
   		handle_input();
      }
	}
}


void SimpleTUI::put_message(const std::string& s)
{
	q.enqueue(s);
}

void SimpleTUI::put_log(ITUI::LogLevel l, const std::string& s)
{
	std::string s_ { s };
	s_.erase(std::remove(s_.begin(), s_.end(), '\n'), s_.end());

	switch (l) {
		case ITUI::LogLevel::TRACE:
			spdlog::trace("{}", s_);
			break;
		case ITUI::LogLevel::DEBUG:
    		spdlog::debug("{}", s_);
    		break;
		case ITUI::LogLevel::INFO:
    		spdlog::info("{}", s_);
    		break;
		case ITUI::LogLevel::WARNING:
    		spdlog::warn("{}", s_);
			break;
		case ITUI::LogLevel::ERROR:
    		spdlog::error("{}", s_);
			break;
		case ITUI::LogLevel::CRITICAL:
    		spdlog::critical("{}", s_);
			break;
		default:
    		spdlog::error("Unknown SCTPClient log level message. {}", s_);
    		break;
	}
}

void SimpleTUI::stop()
{
	int written = write(pipefd[1], END_SIGNAL, strlen(END_SIGNAL));
	if (written <= 0) throw std::runtime_error(strerror(errno));	
}


void SimpleTUI::handle_input()
{
	std::string line;

	if (getline(std::cin, line)) {
		if (line != std::string()) {
			//put_message(line + "\n");
			cback_(line);
		}
	} else {
		stop();
	}
}
