#include <iostream>
#include <memory>
#include <limits>
#include <algorithm>
#include <string>
#include <atomic>
#include <thread>

#include "opencv2/opencv.hpp"

#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "gopt.h"

#include "sync_queue.hpp"

#include "sctp_client.h"
#include "video_engine.h"



constexpr uint16_t MAX_IP_PORT = std::numeric_limits<uint16_t>::max();
constexpr const char* DEFAULT_LOG_FILENAME = "client_log.txt";


enum CLIOptions
{
	HELP,
	VERSION,
	VERBOSITY,
	SERVER_UDP_PORT,
	SERVER_SCTP_PORT,
	SERVER_ADDRESS,
	LOG_TO_FILE,
	/* do not put any options below this comment */
	OPTIONS_COUNT
};


[[noreturn]] void onTerminate() noexcept
{
	std::cerr << "onTerminate" << std::endl;

	if (auto exc = std::current_exception()) {
		try {
         std::rethrow_exception(exc);
		} catch (const std::exception& exc) {
			std::cerr << "Uncaught exception: " << exc.what() << std::endl;
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

	options[CLIOptions::OPTIONS_COUNT].flags = GOPT_LAST;

	gopt(argv, options);
	gopt_errors(argv[0], options);
}

static std::shared_ptr<SCTPClient::Config> get_cfg_or_die(char* argv[], struct option options[])
{
	/* Pepare Config object for SCTPClient */
	auto cfg = std::make_shared<SCTPClient::Config>();

	if (options[CLIOptions::HELP].count) {
		std::cout << \
		"Usage: " << basename(argv[0]) << " [OPTIONS]" << std::endl << \
		std::endl << \
		"\t-s, --server\t\t -- server address (defaults to " << DEFAULT_SERVER_ADDRESS << ")" << std::endl << \
		"\t-u, --udp-port\t\t -- server UDP encapsulation port (defaults to " << DEFAULT_SERVER_UDP_ENCAPS_PORT << ")" << std::endl << \
		"\t-p, --sctp-port\t\t -- server SCTP port (defaults to " << DEFAULT_SERVER_SCTP_PORT << ")" << std::endl << \
		"\t-l, --log\t\t -- enable rotating log (defaults to " << DEFAULT_LOG_FILENAME << ")" << std::endl << \
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

	/* verbosity */
	if (options[CLIOptions::VERBOSITY].count) {
		if (options[CLIOptions::VERBOSITY].count == 1) {
			spdlog::set_level(spdlog::level::debug);
		} else {
			spdlog::set_level(spdlog::level::trace);
		}
	}
	
	cfg->cert_filename = "../certs/" + cfg->cert_filename;
	cfg->key_filename = "../certs/" + cfg->key_filename;

	return cfg;
}


int main(int /* argc */, char* argv[])
{
	std::set_terminate(&onTerminate);

	struct option options[CLIOptions::OPTIONS_COUNT];
	parse_args(argv, options);

	int pipefd[2];

	SCTPClient client { get_cfg_or_die(argv, options) };
	
	VideoEngine ve;

	/* init client */
	client.cfg()->data_cback_f = [&](auto s)
	{ 
		spdlog::trace("Server sent: {}", std::to_string(s->size));

		if (s->size == 0) return; //hack !

		ve.put_frame_data(std::move(s));
	};

	client.cfg()->debug_cback_f = [&](const auto& level, const auto& s)
	{
		std::string s_ { s };
		s_.erase(std::remove(s_.begin(), s_.end(), '\n'), s_.end());

		switch (level) {
			case sctp::TRACE:
				spdlog::trace("{}", s_);
				break;
			case sctp::DEBUG:
	    		spdlog::debug("{}", s_);
	    		break;
			case sctp::INFO:
	    		spdlog::info("{}", s_);
	    		break;
			case sctp::WARNING:
	    		spdlog::warn("{}", s_);
				break;
			case sctp::ERROR:
	    		spdlog::error("{}", s_);
				break;
			case sctp::CRITICAL:
	    		spdlog::critical("{}", s_);
				break;
			default:
	    		spdlog::error("Unknown log level message. {}", s_);
	    		break;
		}
	};

	client.cfg()->state_cback_f = [&](const auto& state)
	{ 
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
			ve(client);
			break;
		case SCTPClient::SSL_SHUTDOWN:
			message += "SSL shutdown.";
			break;				
		case SCTPClient::PURGE:
			message += "Terminating...";
			close(pipefd[1]);
		default:
			break;
		}

		spdlog::trace("{}", message); 
	};



	try {
		client.init();
		spdlog::info("{}", client.to_string());
		client(); // this is async, starts separate thread
	} catch (const std::runtime_error& exc) {
		spdlog::error("{}", std::string(exc.what()));
		return EXIT_FAILURE;
	}


	//
	if (pipe(pipefd) == -1) {
		throw std::runtime_error(strerror(errno));
	}

	spdlog::info("Press ctrl-D to terminate.");

	fd_set set;
	int res;
	while (true) {
		FD_ZERO(&set);
		FD_SET(STDIN_FILENO, &set);
		FD_SET(pipefd[0], &set);

		res = select(pipefd[0] + 1, &set, NULL, NULL, NULL);

		if (res < 0) {
			break;
		}

      if (FD_ISSET(pipefd[0], &set)) {
			break;
      }

      if (FD_ISSET(STDIN_FILENO, &set)) {
			char* line = NULL;
			size_t size;
			if (getline(&line, &size, stdin) == -1) {
				break;
			}
      }
	}
   close(pipefd[0]);

	client.stop();
	return EXIT_SUCCESS;
}