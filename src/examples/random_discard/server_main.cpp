#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <limits>

#include <boost/program_options.hpp>

#include "spdlog/spdlog.h"
#include "spdlog/fmt/ostr.h"

#include "sctp_server.hpp"
#include "log_level.hpp"
#include "sync_queue.hpp"


namespace
{

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


std::tuple<std::optional<std::shared_ptr<sctp::Server::Config>>, int> get_cfg(int argc, char* argv[])
{
	namespace po = boost::program_options;

	constexpr auto MAX_IP_PORT {std::numeric_limits<uint16_t>::max()};

	auto cfg = std::make_shared<sctp::Server::Config>();

	uint16_t sctp_port {sctp::Server::Config::DEFAULT_SCTP_PORT};
	uint16_t udp_port {sctp::Server::Config::DEFAULT_UDP_ENCAPS_PORT};

	po::options_description desc {"Allowed options"};
	desc.add_options()
		("version,V", "print version and exit")
		("verbose,v", "be verbose")
		("sctp-port,s", po::value<std::uint16_t>(&sctp_port)->default_value(sctp::Server::Config::DEFAULT_SCTP_PORT), (std::string {"local SCTP server port (default is " + std::to_string(sctp::Server::Config::DEFAULT_SCTP_PORT) + ")"}).c_str())
		("udp-port,u", po::value<std::uint16_t>(&udp_port)->default_value(sctp::Server::Config::DEFAULT_UDP_ENCAPS_PORT), (std::string {"local UDP encapsulation port (default is " + std::to_string(sctp::Server::Config::DEFAULT_UDP_ENCAPS_PORT) + ")"}).c_str())
		("help,h", "produce this help screen");

	po::variables_map vm;

	try
	{
		po::store(po::parse_command_line(argc, argv, desc), vm);
		po::notify(vm);
	}
	catch (const boost::program_options::error& ex)
	{
		std::cerr << ex.what() << '\n';
		return {std::nullopt, EXIT_FAILURE};
	}

	if (vm.count("help"))
	{
		std::cout << desc << '\n';
		return {std::nullopt, EXIT_SUCCESS};
	}
	if (vm.count("version"))
	{
		std::cout << "Version 0.01a" << std::endl;  	
		return {std::nullopt, EXIT_SUCCESS};
	}
	if (vm.count("verbose"))
	{
		spdlog::default_logger_raw()->set_level(spdlog::level::trace);
	}
	if (sctp_port > MAX_IP_PORT or 0 == sctp_port)
	{
		std::cerr << "Invalid SCTP transport port provided" << '\n';
		return {std::nullopt, EXIT_FAILURE};
	}
	cfg->sctp_port = sctp_port;

	if (udp_port > MAX_IP_PORT or 0 == sctp_port)
	{
		std::cerr << "Invalid UDP transport port provided" << '\n';
		return {std::nullopt, EXIT_FAILURE};
	}
	cfg->udp_encaps_port = udp_port;


/*	if (!boost::filesystem::exists(cfg->cert_filename))
	{
		std::cerr << "Can't find certificate file: " << cfg->cert_filename << "\n";
		return {std::nullopt, EXIT_FAILURE};
	}

	if (!boost::filesystem::exists(cfg->key_filename))
	{
		std::cerr << "Can't find key file: " << cfg->key_filename << "\n";
		return {std::nullopt, EXIT_FAILURE};
	}*/

	return {cfg, EXIT_SUCCESS};
}

} //anon namespace

int main(int argc, char* argv[])
{
	std::set_terminate(&onTerminate);

	auto [cfg, res] = get_cfg(argc, argv);
	if (not cfg) return res;

	(*cfg)->event_cback_f = [&](auto evt)
	{
		auto& c = evt.client;

		switch (evt.type) {
		case sctp::ServerEvent::Type::CLIENT_DATA:
			break;
		case sctp::ServerEvent::Type::CLIENT_STATE:
			spdlog::info("{}", *c);
			break;
		case sctp::ServerEvent::Type::CLIENT_SEND_POSSIBLE:
			break;
		default:
			break;
		}
	};
	(*cfg)->debug_cback_f = [&](auto level, const auto& s)
	{
		switch (level) {
		case sctp::LogLevel::TRACE:
			spdlog::trace("{}", s);
			break;
		case sctp::LogLevel::DEBUG:
    		spdlog::debug("{}", s);
    		break;
		case sctp::LogLevel::INFO:
    		spdlog::info("{}", s);
    		break;
		case sctp::LogLevel::WARNING:
    		spdlog::warn("{}", s);
			break;
		case sctp::LogLevel::ERROR:
    		spdlog::error("{}", s);
			break;
		case sctp::LogLevel::CRITICAL:
    		spdlog::critical("{}", s);
			break;
		default:
    		spdlog::error("Unknown log level message. {}", s);
    		break;
		}
	};

	try
	{
		sctp::Server srv{*cfg};
		spdlog::info("{}", srv);
		srv();
		spdlog::info("Serving. Press ctrl-D to terminate.");

		while (true)
		{
			std::string _s;
			if (not getline(std::cin, _s)) break;
		}

		spdlog::info("Shutting down...");
	}
	catch (const std::runtime_error& ex)
	{
 		spdlog::critical("{}", ex.what());
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
