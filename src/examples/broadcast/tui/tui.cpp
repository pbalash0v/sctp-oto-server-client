#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <errno.h>
#include <sys/select.h>

#include "tui.h"


constexpr const char* END_SIGNAL = "e";

//static constexpr size_t BUFFLEN(const char* s) { return strlen(s); };

static constexpr size_t length(const char* str)
{
    return *str ? 1 + length(str + 1) : 0;
}

TUI::TUI()
{
	initscr(); /* initialize the curses library */

	log_thr = std::thread(&TUI::display_func, this);

	if (pipe(pipefd) == -1) {
		throw std::runtime_error(strerror(errno));
	}
}

TUI::~TUI()
{
	/* wakeup & finish logger thread */
	running_ = false;
	put_message("");
	log_thr.join();

   close(pipefd[0]);
   close(pipefd[1]);

	/* finish ncurses */
	endwin();
}

/*
	runs in separate thread, dequeues and renders text
*/
void TUI::display_func()
{
	while (running_) {
		printw(q.dequeue().c_str());
		refresh();
	}
}

void TUI::init(ITUI_cback_t cback)
{
	cback_ = cback;
	
	//nonl();         /* tell curses not to do NL->CR/NL on output */

	/* interrupt, quit, suspend, and flow control characters
  		are all passed through uninterpreted,
		without generating a signal */
	raw();

 	/* 'reduced' raw mode: just takes input chars one at a time, no wait for \n */
	//cbreak();

	noecho(); /* Suppress stdout */

	/* keypad(stdscr, TRUE) enables support for function-key mapping. 
	 	With this feature, the getch() code watches the input stream 
	 	for character sequences that correspond to arrow and function keys. */
	keypad(stdscr, TRUE);

	nodelay(stdscr, TRUE);

	scrollok(stdscr,TRUE); /* autoscroll stdscr window */
}


void TUI::loop()
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
				put_message("select returned error: " + 
								std::string(strerror(errno)));
				running_ = false;
				continue;				
			}
		}

      if (FD_ISSET(pipefd[0], &set)) {
      	char buf[length(END_SIGNAL)];

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


void TUI::put_message(const std::string& s)
{
	q.enqueue(s);
}

void TUI::put_log(ITUI::LogLevel l, const std::string& s)
{
	std::string s_ { s };

	switch (l) {
	case ITUI::LogLevel::TRACE:
		s_ = "[TRACE] " + s_;
		break;
	case ITUI::LogLevel::DEBUG:
		s_ = "[DEBUG] " + s_;
 		break;
	case ITUI::LogLevel::INFO:
		s_ = "[INFO] " + s_;
 		break;
	case ITUI::LogLevel::WARNING:
		s_ = "[WARNING] " + s_;
		break;
	case ITUI::LogLevel::ERROR:
		s_ = "[ERROR] " + s_;
		break;
	case ITUI::LogLevel::CRITICAL:
		s_ = "[CRITICAL] " + s_;
		break;
	default:
		s_ = "Unknown log level message: " + s_;
 		break;
	}

	q.enqueue(s_);
}


void TUI::stop()
{
	int written = write(pipefd[1], END_SIGNAL, strlen(END_SIGNAL));
	if (written <= 0) throw std::runtime_error(strerror(errno));	
}


void TUI::handle_resize()
{
	refresh();
};


void TUI::handle_input()
{
	int c = wgetch(stdscr);

	switch (c) {
		case '`':
			stop();
			break;
		case '\n':
			if (message == "") break;
			put_message(std::string("\n"));
			cback_(message);
			message = std::string();
			break;
		case KEY_RESIZE:
			handle_resize();
			break;
		default:
			addch(c);
			refresh();
			message += (char) c;
			break;
	}
}

