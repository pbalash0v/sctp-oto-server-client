#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <cstring>
#include <limits>

#include "spdlog/spdlog.h"
#include "spdlog/fmt/ostr.h"

#include "sctp_srvr.h"
#include "gopt.h"


[[noreturn]] void onTerminate() noexcept {
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

static void parse_args(char* argv[], struct option options[], size_t opt_count) {
	options[0].long_name  = "help";
	options[0].short_name = 'h';
	options[0].flags      = GOPT_ARGUMENT_FORBIDDEN;

	options[1].long_name  = "version";
	options[1].short_name = 'V';
	options[1].flags      = GOPT_ARGUMENT_FORBIDDEN;

	options[2].long_name  = "verbose";
	options[2].short_name = 'v';
	options[2].flags      = GOPT_ARGUMENT_FORBIDDEN;

	options[3].long_name  = "udp-port";
	options[3].short_name = 'p';
	options[3].flags      = GOPT_ARGUMENT_REQUIRED;

	options[4].long_name  = "sctp-port";
	options[4].short_name = 's';
	options[4].flags      = GOPT_ARGUMENT_REQUIRED;

	options[opt_count-1].flags      = GOPT_LAST;

	gopt(argv, options);
}


constexpr uint16_t MIN_IP_PORT = std::numeric_limits<uint16_t>::min();
constexpr uint16_t MAX_IP_PORT = std::numeric_limits<uint16_t>::max();


int main([[maybe_unused]] int argc, char* argv[]) {
	std::set_terminate(&onTerminate);

	auto cfg = std::make_shared<SCTPServer::Config>();

	struct option options[6];
	parse_args(argv, options, sizeof options / sizeof options[0]);

	/* help */
	if (options[0].count) {
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
	if (options[1].count) {
		std::cout << "Version 0.01a" << std::endl;  	
		exit(EXIT_SUCCESS);
	}

	/* verbosity */
	if (options[2].count) {
		if (options[2].count == 1) {
			spdlog::set_level(spdlog::level::debug);
		} else {
			spdlog::set_level(spdlog::level::trace);
		}
	}

	/* udp encaps port */
	if (options[3].count) {
		auto _port = std::strtoul(options[3].argument, NULL, 10);
		if (_port > MIN_IP_PORT && _port <= MAX_IP_PORT) {
			cfg->udp_encaps_port = (uint16_t) _port;
		} else {
			std::cout << "Error. UDP port " << _port << " is invalid." << std::endl;
			exit(EXIT_FAILURE);
		}		
	}

	/* sctp serving port */
	if (options[4].count) {
		auto _port = std::strtoul(options[4].argument, NULL, 10);
		if (_port > MIN_IP_PORT && _port < MAX_IP_PORT) {
			cfg->sctp_port = (uint16_t) _port;
		} else {
			std::cout << "Error. SCTP port " << _port << " is invalid." << std::endl;
			exit(EXIT_FAILURE);
		}		
	}

	SCTPServer srv { cfg };

	auto cback = [&]([[maybe_unused]] auto client, const auto& s) {
		std::string message { static_cast<const char*> (s->data) };
		spdlog::info("{}", message);
		srv.broadcast(message.c_str(), message.size());
	};

	auto debug_cback = [&](auto level, const auto& s) {
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

	cfg->data_cback_f = cback;
	cfg->debug_f = debug_cback;

	try {
		srv.init();
		srv.run();
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

	return EXIT_SUCCESS;
}
