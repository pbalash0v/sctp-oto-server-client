#ifdef HAVE_CONFIG_H
	#include "config.h"
#endif

#include <iostream>
#include <memory>
#include <limits>
#include <algorithm>
#include <string>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"

#include "gopt.h"

#ifdef HAVE_NCURSES
#include "tui.h"
#endif
#include "simple_tui.h"

#include "sctp_client.h"

constexpr uint16_t MAX_IP_PORT = std::numeric_limits<uint16_t>::max();
constexpr const char* DEFAULT_LOG_FILENAME = "client_log.txt";

enum CLIOptions
{
	HELP,
	VERSION_OPT,
	VERBOSITY,
	SERVER_UDP_PORT,
	SERVER_SCTP_PORT,
	SERVER_ADDRESS,
	LOG_TO_FILE,
#ifdef HAVE_NCURSES
	RUN_TUI,
#endif	
	/* do not put any options below this comment */
	OPTIONS_COUNT
};

[[noreturn]] void onTerminate() noexcept
{
	if (auto exc = std::current_exception()) {
		try {
         std::rethrow_exception(exc);
		} catch (const std::runtime_error& exc) {
			std::cerr << "Uncaught exception: " << exc.what() << std::endl;
		}
	}
	//endwin();
	std::_Exit(EXIT_FAILURE);
}

static void parse_args(char* argv[], struct option options[])
{
	options[CLIOptions::HELP].long_name  = "help";
	options[CLIOptions::HELP].short_name = 'h';
	options[CLIOptions::HELP].flags      = GOPT_ARGUMENT_FORBIDDEN;

	options[CLIOptions::VERSION_OPT].long_name  = "version";
	options[CLIOptions::VERSION_OPT].short_name = 'V';
	options[CLIOptions::VERSION_OPT].flags      = GOPT_ARGUMENT_FORBIDDEN;

	options[CLIOptions::VERBOSITY].long_name  = "verbose";
	options[CLIOptions::VERBOSITY].short_name = 'v';
	options[CLIOptions::VERBOSITY].flags      = GOPT_ARGUMENT_FORBIDDEN | GOPT_REPEATABLE;

	options[CLIOptions::SERVER_UDP_PORT].long_name  = "udp-port";
	options[CLIOptions::SERVER_UDP_PORT].short_name = 'u';
	options[CLIOptions::SERVER_UDP_PORT].flags      = GOPT_ARGUMENT_REQUIRED;

	options[CLIOptions::SERVER_SCTP_PORT].long_name  = "sctp-port";
	options[CLIOptions::SERVER_SCTP_PORT].short_name = 'p';
	options[CLIOptions::SERVER_SCTP_PORT].flags      = GOPT_ARGUMENT_REQUIRED;

	options[CLIOptions::SERVER_ADDRESS].long_name  = "server";
	options[CLIOptions::SERVER_ADDRESS].short_name = 's';
	options[CLIOptions::SERVER_ADDRESS].flags      = GOPT_ARGUMENT_REQUIRED;

	options[CLIOptions::LOG_TO_FILE].long_name  = "log";
	options[CLIOptions::LOG_TO_FILE].short_name = 'l';
	options[CLIOptions::LOG_TO_FILE].flags      = GOPT_ARGUMENT_FORBIDDEN;

#ifdef HAVE_NCURSES
	options[CLIOptions::RUN_TUI].long_name  = "tui";
	options[CLIOptions::RUN_TUI].short_name = 't';
	options[CLIOptions::RUN_TUI].flags      = GOPT_ARGUMENT_FORBIDDEN;
#endif

	options[CLIOptions::OPTIONS_COUNT].flags = GOPT_LAST;

	gopt(argv, options);

	gopt_errors(argv[0], options);
}

static std::shared_ptr<SCTPClient::Config> get_cfg_or_die(char* argv[], struct option options[])
{
	/* Pepare Config object for SCTPClient */
	auto cfg = std::make_shared<SCTPClient::Config>();

	if (options[CLIOptions::HELP].count) {
		std::cout <<
		"Usage: " << basename(argv[0]) << " [OPTIONS]" << std::endl <<
		std::endl <<
		"\t-s, --server\t\t -- server address (defaults to " << DEFAULT_SERVER_ADDRESS << ")" << std::endl <<
		"\t-u, --udp-port\t\t -- server UDP encapsulation port (defaults to " << DEFAULT_SERVER_UDP_ENCAPS_PORT << ")" << std::endl <<
		"\t-p, --sctp-port\t\t -- server SCTP port (defaults to " << DEFAULT_SERVER_SCTP_PORT << ")" << std::endl <<
		"\t-l, --log\t\t -- enable rotating log (defaults to " << DEFAULT_LOG_FILENAME << ")" << std::endl <<
#ifdef HAVE_NCURSES
		"\t-t, --tui\t\t -- run TUI (unstable)" << std::endl <<
#endif
		"\t-v, --verbose\t\t -- be verbose" << std::endl <<
		"\t-h, --help\t\t -- this message" << std::endl <<
		"\t-V, --version\t\t -- print the version and exit" << std::endl <<

		std::endl;
		exit(EXIT_SUCCESS);
	}

	/* version */
	if (options[CLIOptions::VERSION_OPT].count) {
		std::cout << VERSION << std::endl;  	
		exit(EXIT_SUCCESS);
	}

	/* file logger */
	if (options[CLIOptions::LOG_TO_FILE].count) {
		try {
			auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(DEFAULT_LOG_FILENAME, true);
			spdlog::default_logger()->sinks().push_back(file_sink);
			spdlog::set_level(spdlog::level::trace);
		} catch (const spdlog::spdlog_ex& ex) {
			std::cout << "Log initialization failed: " << ex.what() << std::endl;
			exit(EXIT_FAILURE);
		}
	}

	cfg->server_udp_port = ([&]
	{
		auto _port = DEFAULT_SERVER_UDP_ENCAPS_PORT;

		if (options[CLIOptions::SERVER_UDP_PORT].count) {
			auto _p = std::strtoul(options[CLIOptions::SERVER_UDP_PORT].argument, NULL, 10);
			if (errno == ERANGE or _p > MAX_IP_PORT or _p == 0) {
				std::cout << "Supplied UDP port " << options[CLIOptions::SERVER_UDP_PORT].argument
							 << " is invalid." << std::endl;
				exit(EXIT_FAILURE);	
			}
			_port = _p;
		}

		return static_cast<uint16_t>(_port);
	})();

	cfg->server_sctp_port = ([&]
	{
		auto _port = DEFAULT_SERVER_SCTP_PORT;

		if (options[CLIOptions::SERVER_SCTP_PORT].count) {
			auto _p = std::strtoul(options[CLIOptions::SERVER_SCTP_PORT].argument, NULL, 10);
			if (errno == ERANGE or _p > MAX_IP_PORT or _p == 0) {
				std::cout << "Supplied SCTP port " << options[CLIOptions::SERVER_SCTP_PORT].argument
							 << " is invalid." << std::endl;
				exit(EXIT_FAILURE);	
			}
			_port = _p;
		}

		return static_cast<uint16_t>(_port);
	})();

	cfg->server_address = ([&]
	{
		std::string serv_addr = DEFAULT_SERVER_ADDRESS;

		if (options[CLIOptions::SERVER_ADDRESS].count) {
			serv_addr = options[CLIOptions::SERVER_ADDRESS].argument;
		}

		return serv_addr;
	})();

	return cfg;
}


int main(int /* argc */, char* argv[])
{
	std::set_terminate(&onTerminate);

	struct option options[CLIOptions::OPTIONS_COUNT];
	parse_args(argv, options);

	auto tui = ([&]() -> std::unique_ptr<ITUI>
	{
		std::unique_ptr<ITUI> tui_;

#ifdef HAVE_NCURSES
		if (options[CLIOptions::RUN_TUI].count)
			tui_ = std::make_unique<TUI>();
		else
#endif
			tui_ = std::make_unique<SimpleTUI>();

		return tui_;
	})();

	/* TUI verbosity */
	tui->set_log_level(([&]()
	{
		ITUI::LogLevel log_lev = ITUI::INFO;

		if (options[CLIOptions::VERBOSITY].count == 1) {
			log_lev = ITUI::DEBUG;
		}
		if (options[CLIOptions::VERBOSITY].count > 1) {
			log_lev = ITUI::TRACE;
		}

		return log_lev;
	})());
	

	/* Client config */
	SCTPClient client { get_cfg_or_die(argv, options) };

	client.cfg()->data_cback_f = [&](const auto& s)
	{ 
		std::string server_message = 
			((s->size < 30) ? 
				std::string(static_cast<char*>(s->buf))
		 		: std::string(static_cast<char*>(s->buf)).substr(0, 30));
		tui->put_message("Server sent: "
				+ std::to_string(s->size)
				+ std::string(" ")
				+ server_message
				+ "\n"); 
	};

	client.cfg()->debug_cback_f = [&](auto level, const auto& s)
	{
		ITUI::LogLevel l = ITUI::LogLevel::TRACE;

		switch (level) {
			case SCTPClient::TRACE:
				l = ITUI::LogLevel::TRACE;
				break;
			case SCTPClient::DEBUG:
				l = ITUI::LogLevel::DEBUG;
	    		break;
			case SCTPClient::INFO:
				l = ITUI::LogLevel::INFO;
	    		break;
			case SCTPClient::WARNING:
				l = ITUI::LogLevel::WARNING;
				break;
			case SCTPClient::ERROR:
				l = ITUI::LogLevel::ERROR;
				break;
			case SCTPClient::CRITICAL:
				l = ITUI::LogLevel::CRITICAL;
				break;
			default:
	    		std::cerr << "Unknown SCTPClient log level message. " <<  s << std::endl;
				l = ITUI::LogLevel::WARNING;
	    		break;
 		}

		tui->put_log(l, s);
	};

	client.cfg()->state_cback_f = [&](auto state)
	{ 
		std::string message;

		switch (state) {
			case SCTPClient::INITIALIZED:
				message += "Initialization done.";
				break;			
			case SCTPClient::SCTP_CONNECTING:
				message += "Connecting...";
				break;
			case SCTPClient::SCTP_CONNECTED:
				message += "Connected.";
				break;
			case SCTPClient::SSL_HANDSHAKING:
				message += "Handshaking SSL...";
				break;
			case SCTPClient::SSL_CONNECTED:
				message += "SSL established.";
				break;
			case SCTPClient::SSL_SHUTDOWN:
				message += "SSL shutdown.";
				break;				
			case SCTPClient::PURGE:
				message += "Terminating...";
				tui->stop();
			default:
				break;
		}

		tui->put_message(message + "\n"); 
	};



	tui->init([&](const auto& s)
	{
		if (client.connected()) {
			try {
				client.send(s.c_str(), s.size());
			} catch (std::runtime_error& exc) {
				tui->put_log(ITUI::LogLevel::WARNING,
						"Send failed: " + std::string(exc.what()));
			}
		} else {
			tui->put_message("\n" + s + " not sent (client not connected).\n");
		}
	});


	try {
		client.init();
		tui->put_log(ITUI::LogLevel::INFO, client.to_string());
		client(); /* this is async, starts separate thread */
	} catch (const std::runtime_error& exc) {
		tui->put_message(std::string(exc.what()) + std::string("\n"));
		return EXIT_FAILURE;
	}


	tui->loop(); /* this blocks main thread */

	/* if we're here means tui input eval loop ended */
	client.stop();

	return EXIT_SUCCESS;
}