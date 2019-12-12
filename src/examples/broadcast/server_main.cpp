#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <cstring>
#include <limits>

#include "spdlog/spdlog.h"
#include "spdlog/fmt/ostr.h"

#include "sctp_server.h"
#include "gopt.h"


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
	options[CLIOptions::VERBOSITY].flags      = GOPT_ARGUMENT_FORBIDDEN;

	options[CLIOptions::UDP_ENCAPS_PORT].long_name  = "udp-port";
	options[CLIOptions::UDP_ENCAPS_PORT].short_name = 'p';
	options[CLIOptions::UDP_ENCAPS_PORT].flags      = GOPT_ARGUMENT_REQUIRED;

	options[CLIOptions::SCTP_PORT].long_name  = "sctp-port";
	options[CLIOptions::SCTP_PORT].short_name = 's';
	options[CLIOptions::SCTP_PORT].flags      = GOPT_ARGUMENT_REQUIRED;

	options[CLIOptions::OPTIONS_COUNT].flags = GOPT_LAST;

	gopt(argv, options);
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



int main(int /* argc */, char* argv[]) {
	std::set_terminate(&onTerminate);

	struct option options[CLIOptions::OPTIONS_COUNT];
	parse_args(argv, options);

	/* verbosity */
	if (options[CLIOptions::VERBOSITY].count) {
		if (options[CLIOptions::VERBOSITY].count == 1) {
			spdlog::set_level(spdlog::level::debug);
		} else {
			spdlog::set_level(spdlog::level::trace);
		}
	}

	auto& srv  = SCTPServer::get_instance();
	srv.cfg_ = get_cfg_or_die(argv, options);

	srv.cfg_->data_cback_f = [&](auto /* client */, const auto& s) {
		std::string message { static_cast<const char*> (s->data) };
		spdlog::info("{}", message);
		srv.broadcast(message.c_str(), message.size());
	};

	srv.cfg_->debug_f = [&](auto level, const auto& s) {
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
