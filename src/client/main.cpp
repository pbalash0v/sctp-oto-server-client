#include <iostream>
#include <memory>
#include <cassert>
#include <csignal> 
#include <limits>
#include <algorithm>
#include <string>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"

#include "gopt.h"
#include "tui.h"
#include "simple_tui.h"
#include "sctp_client.h"


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

static void parse_args(char* argv[], struct option options[], size_t opt_count)
{
	options[0].long_name  = "help";
	options[0].short_name = 'h';
	options[0].flags      = GOPT_ARGUMENT_FORBIDDEN;

	options[1].long_name  = "version";
	options[1].short_name = 'V';
	options[1].flags      = GOPT_ARGUMENT_FORBIDDEN;

	options[2].long_name  = "verbose";
	options[2].short_name = 'v';
	options[2].flags      = GOPT_ARGUMENT_FORBIDDEN;

	options[3].long_name  = "port";
	options[3].short_name = 'p';
	options[3].flags      = GOPT_ARGUMENT_REQUIRED;

	options[4].long_name  = "server";
	options[4].short_name = 's';
	options[4].flags      = GOPT_ARGUMENT_REQUIRED;

	options[5].long_name  = "log";
	options[5].short_name = 'l';
	options[5].flags      = GOPT_ARGUMENT_FORBIDDEN;

	options[6].long_name  = "tui";
	options[6].short_name = 't';
	options[6].flags      = GOPT_ARGUMENT_FORBIDDEN;

	options[opt_count-1].flags      = GOPT_LAST;

	gopt(argv, options);
}


constexpr uint16_t MAX_IP_PORT = std::numeric_limits<uint16_t>::max();

#define DEFAULT_LOG_NAME "client_log.txt"

int main(int /* argc */, char* argv[])
{
	std::set_terminate(&onTerminate);

	struct option options[8];
	parse_args(argv, options, sizeof options / sizeof options[0]);

	if (options[0].count) {
		std::cout << \
		"Usage: " << basename(argv[0]) << " [OPTIONS]" << std::endl << \
		std::endl << \
		"\t-s, --server\t\t -- server address" << std::endl << \
		"\t-p, --port\t\t -- server port" << std::endl << \
		"\t-l, --log\t\t -- enable rotating log (defaults to " << DEFAULT_LOG_NAME << ")" << std::endl << \
		"\t-t, --tui\t\t -- run TUI (unstable)" << std::endl << \
		"\t-h, --help\t\t -- this message" << std::endl << \
		"\t-V, --version\t\t -- print the version and exit" << std::endl << \

		std::endl;
		exit(EXIT_SUCCESS);
	}

	/* version */
	if (options[1].count) {
		std::cout << "Version 0.01a" << std::endl;  	
		exit(EXIT_SUCCESS);
	}

	if (options[2].count) {
		std::cout << "Verbosity is not supported atm." << std::endl;  	
		exit(EXIT_SUCCESS);
	}

	/* file logger */
	if (options[5].count) {
		try {
			auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(DEFAULT_LOG_NAME, true);
			spdlog::default_logger()->sinks().push_back(file_sink);
			spdlog::set_level(spdlog::level::trace);
		} catch (const spdlog::spdlog_ex& ex) {
			std::cout << "Log initialization failed: " << ex.what() << std::endl;
			exit(EXIT_FAILURE);
		}
	}

	uint16_t port = DEFAULT_LOCAL_UDP_ENCAPS_PORT;
	if (options[3].count) {
		auto _port = std::strtoul(options[3].argument, NULL, 10);
		if (errno == ERANGE or _port > MAX_IP_PORT) {
			std::cout << "UDP port " << _port << " is invalid." << std::endl;
			exit(EXIT_FAILURE);	
		}
		port = static_cast<uint16_t>(_port);
	}

	std::string server_address = DEFAULT_SERVER_ADDRESS;
	if (options[4].count) {
		server_address = options[4].argument;
	}

	std::unique_ptr<ITUI> tui;
	if (options[6].count) {
		tui = std::make_unique<TUI>();
	} else {
		tui = std::make_unique<SimpleTUI>();
	}

	/* Pepare Config object for SCTPClient */
	auto cfg = std::make_shared<SCTPClient::Config>();
	cfg->udp_encaps_port = port;
	cfg->server_address = server_address;
	cfg->data_cback_f = [&](const auto& s) { 
		tui->put_message("Server sent: " + s + "\n"); 
	};

	cfg->debug_f = [&](auto level, const auto& s) {
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
	    		break;
 		}

		tui->put_log(l, s);
	};

	cfg->state_f = [&](auto state) { 
		std::string message;

		switch (state) {
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

	SCTPClient client { cfg };

	tui->init([&](const auto& s) {
		if (client.connected()) client.sctp_send(s);
		else tui->put_message("\n" + s + " not sent (client not connected).\n");
	});

	tui->put_message("Starting...press ctrl-D to stop.\n");

	try {
		client.init();
		client.run(); /* this is async, starts separate thread */
	} catch (const std::runtime_error& exc) {
		tui->put_message(std::string(exc.what()) + std::string("\n"));
		return EXIT_FAILURE;
	}

	tui->loop(); /* this blocks main thread */

	/* if we're here means tui input eval loop ended */
	client.stop();

	return EXIT_SUCCESS;
}