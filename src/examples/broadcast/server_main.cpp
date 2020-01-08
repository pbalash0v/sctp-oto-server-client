#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <limits>

#include "spdlog/spdlog.h"
#include "spdlog/fmt/ostr.h"

#include "sctp_server.h"
#include "sync_queue.hpp"
#include "gopt.h"
#include "broadcaster.h"


constexpr uint16_t MAX_IP_PORT = std::numeric_limits<uint16_t>::max();

enum CLIOptions
{
	HELP,
	VERSION,
	VERBOSITY,
	UDP_ENCAPS_PORT,
	SCTP_PORT,
	/* do not put any options below this comment */
	OPTIONS_COUNT
};

[[noreturn]] void onTerminate() noexcept
{
	if (auto exc = std::current_exception()) {
		try {
         std::rethrow_exception(exc);
		} catch (const std::runtime_error& exc) {
			std::cout << exc.what() << std::endl;
		} catch (const std::exception& exc) {
			std::cout << exc.what() << std::endl;
		}
	}

	std::_Exit(EXIT_FAILURE);
}


static void parse_args(char* argv[], struct option options[])
{
	options[CLIOptions::HELP].long_name  = "help";
	options[CLIOptions::HELP].short_name = 'h';
	options[CLIOptions::HELP].flags      = GOPT_ARGUMENT_FORBIDDEN;

	options[CLIOptions::VERSION].long_name  = "version";
	options[CLIOptions::VERSION].short_name = 'V';
	options[CLIOptions::VERSION].flags      = GOPT_ARGUMENT_FORBIDDEN;

	options[CLIOptions::VERBOSITY].long_name  = "verbose";
	options[CLIOptions::VERBOSITY].short_name = 'v';
	options[CLIOptions::VERBOSITY].flags      = GOPT_ARGUMENT_FORBIDDEN | GOPT_REPEATABLE;

	options[CLIOptions::UDP_ENCAPS_PORT].long_name  = "udp-port";
	options[CLIOptions::UDP_ENCAPS_PORT].short_name = 'p';
	options[CLIOptions::UDP_ENCAPS_PORT].flags      = GOPT_ARGUMENT_REQUIRED;

	options[CLIOptions::SCTP_PORT].long_name  = "sctp-port";
	options[CLIOptions::SCTP_PORT].short_name = 's';
	options[CLIOptions::SCTP_PORT].flags      = GOPT_ARGUMENT_REQUIRED;

	options[CLIOptions::OPTIONS_COUNT].flags = GOPT_LAST;

	gopt(argv, options);
	gopt_errors(argv[0], options);

	/* verbosity */
	if (options[CLIOptions::VERBOSITY].count) {
		if (options[CLIOptions::VERBOSITY].count == 1) {
			spdlog::set_level(spdlog::level::debug);
		} else {
			spdlog::set_level(spdlog::level::trace);
		}
	}	
}

static std::shared_ptr<SCTPServer::Config> get_cfg_or_die(char* argv[], struct option options[])
{
	auto cfg = std::make_shared<SCTPServer::Config>();

	/* help */
	if (options[CLIOptions::HELP].count) {
		std::cout << \
		"Usage: " << basename(argv[0]) << " [OPTIONS]" << std::endl << \
		std::endl << \
		"\t-p, --udp-port\t\t -- local UDP encapsulation port (default is " << \
			DEFAULT_UDP_ENCAPS_PORT << ")" << std::endl << \
		"\t-s, --sctp-port\t\t -- local SCTP server port (default is " << \
			DEFAULT_SCTP_PORT << ")" << std::endl << \
		"\t-v, --verbose\t\t -- be verbose" << std::endl << \
		"\t-h, --help\t\t -- this message" << std::endl << \
		"\t-V, --version\t\t -- print the version and exit" << std::endl << \

		std::endl;
		exit(EXIT_SUCCESS);
	}

	/* version */
	if (options[CLIOptions::VERSION].count) {
		std::cout << "Version 0.01a" << std::endl;  	
		exit(EXIT_SUCCESS);
	}

	cfg->udp_encaps_port = ([&]
	{
		auto _port = DEFAULT_UDP_ENCAPS_PORT;
	
		if (options[CLIOptions::UDP_ENCAPS_PORT].count) {
			auto _p = std::strtoul(options[CLIOptions::UDP_ENCAPS_PORT].argument, NULL, 10);
			if (errno == ERANGE or _p > MAX_IP_PORT or _p == 0) {
				std::cout << "Supplied UDP port " << options[CLIOptions::UDP_ENCAPS_PORT].argument
							 << " is invalid." << std::endl;
				exit(EXIT_FAILURE);
			}
			_port = _p;
		}

		return static_cast<uint16_t>(_port);
	})();

	cfg->sctp_port = ([&]
	{
		auto _port = DEFAULT_SCTP_PORT;

		if (options[CLIOptions::SCTP_PORT].count) {
			auto _p = std::strtoul(options[CLIOptions::SCTP_PORT].argument, NULL, 10);
			if (errno == ERANGE or _p > MAX_IP_PORT or _p == 0) {
				std::cout << "Supplied SCTP port " << options[CLIOptions::SCTP_PORT].argument
							 << " is invalid." << std::endl;
				exit(EXIT_FAILURE);
			}
			_port = _p;		
		}

		return static_cast<uint16_t>(_port);
	})();

	return cfg;
}



std::unordered_map<std::shared_ptr<IClient>, std::unique_ptr<SyncQueue<std::shared_ptr<Data>>>> send_qs;
std::mutex signals_mutex;
std::condition_variable cv;
bool signal_send_possible = false;
bool signal_new_data = false;
bool signal_sender_thr_running = true;
std::unordered_map<std::shared_ptr<IClient>, bool> send_flags;

std::shared_ptr<IClient> client_send_possible;


int main(int /* argc */, char* argv[]) {
	std::set_terminate(&onTerminate);

	struct option options[CLIOptions::OPTIONS_COUNT];
	parse_args(argv, options);

	Broadcaster bcaster;
	SCTPServer srv { get_cfg_or_die(argv, options) };


	srv.cfg()->event_cback_f = [&](auto evt)
	{
		auto& c = evt->client;

		switch (evt->type) {
		case Event::CLIENT_DATA:
			{	
				std::string message { static_cast<const char*>(evt->client_data->data),
					 evt->client_data->size };

				spdlog::info("{}: {}", c->to_string(),
					 ((message.size() < 30) ? message : message.substr(0, 30)));

				bcaster.enqueue(std::move(evt->client_data));
			}
			break;
		case Event::CLIENT_STATE:
			spdlog::info("{}", c->to_string());

			if (evt->client_state == Client::SSL_CONNECTED) {
				bcaster.add_new_client(c);
			}

			if (evt->client_state == Client::SCTP_SHUTDOWN_CMPLT) {
 				spdlog::info("{} disconnected.", c->to_string());
 				bcaster.drop_client(c);
			}			
			break;
		case Event::CLIENT_SEND_POSSIBLE:
			spdlog::debug("{} send possible.", c->to_string());
			bcaster.notify_send_possible(c);
			break;
		default:
			break;
		}
	};

	srv.cfg()->debug_f = [&](auto level, const auto& s)
	{
		switch (level) {
		case SCTPServer::TRACE:
			spdlog::trace("{}", s);
			break;
		case SCTPServer::DEBUG:
    		spdlog::debug("{}", s);
    		break;
		case SCTPServer::INFO:
    		spdlog::info("{}", s);
    		break;
		case SCTPServer::WARNING:
    		spdlog::warn("{}", s);
			break;
		case SCTPServer::ERROR:
    		spdlog::error("{}", s);
			break;
		case SCTPServer::CRITICAL:
    		spdlog::critical("{}", s);
			break;
		default:
    		spdlog::error("Unknown SCTPServer log level message. {}", s);
    		break;
		}
	};

	bcaster(srv);
	try {
		srv.init();
		srv();
	} catch (const std::runtime_error& ex) {
 		spdlog::critical("{}", ex.what());
		return EXIT_FAILURE;
	}

	spdlog::info("{}", srv);
	spdlog::info("Serving. Press ctrl-D to terminate.");

	while (true) {
		std::string _s;
		if (not getline(std::cin, _s)) break;
	}

	spdlog::info("Shutting down...");
	return EXIT_SUCCESS;
}
