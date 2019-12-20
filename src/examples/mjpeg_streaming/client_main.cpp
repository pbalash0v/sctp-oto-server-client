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
	options[CLIOptions::VERBOSITY].flags      = GOPT_ARGUMENT_FORBIDDEN;

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

	return cfg;
}

SyncQueue<std::shared_ptr<cv::Mat>> local_frames_to_display;
SyncQueue<std::shared_ptr<cv::Mat>> frames_to_encode;
SyncQueue<std::shared_ptr<std::vector<uchar>>> frames_to_send {/*limited*/ true, 5};

SyncQueue<std::unique_ptr<SCTPClient::Data>> recvd_data;
SyncQueue<std::unique_ptr<cv::Mat>> recvd_frames_to_display;

void capture_loop(const std::atomic_bool& running, cv::VideoCapture& camera)
{
	while (running) {
		auto frame_ptr = std::make_shared<cv::Mat>();

		// capture the next frame from the webcam
		camera.read(*frame_ptr);

		local_frames_to_display.enqueue(frame_ptr);
		frames_to_encode.enqueue(frame_ptr);
	}

	auto null_frame_ptr = std::make_shared<cv::Mat>();
	local_frames_to_display.enqueue(null_frame_ptr);
	frames_to_encode.enqueue(null_frame_ptr);

	spdlog::debug("{} finished.", __func__);
}

void local_display_loop(SyncQueue<std::shared_ptr<cv::Mat>>& q)
{
	do {
		auto frame = *(q.dequeue());

		if (frame.empty()) break;

		// show the image on the window
		cv::imshow("Webcam", frame);
		
		// wait (10ms) for a key to be pressed
		cv::waitKey(10);
	} while (true);

	spdlog::debug("{} finished.", __func__);
}

void encode_loop(SyncQueue<std::shared_ptr<cv::Mat>>& q)
{
	do {
		auto frame = *(q.dequeue());

		if (frame.empty()) break;

		auto jpeg_ptr = std::make_shared<std::vector<uchar>>();

		cv::imencode(".jpg", frame, *jpeg_ptr);

		frames_to_send.enqueue(jpeg_ptr);
	} while (true);

	auto empty_jpeg_ptr = std::make_shared<std::vector<uchar>>();
	frames_to_send.enqueue(empty_jpeg_ptr);

	spdlog::debug("{} finished.", __func__);
}

void send_loop(SyncQueue<std::shared_ptr<std::vector<uchar>>>& q, SCTPClient& client)
{
	do {
		auto jpeg = *(q.dequeue());

		if (jpeg.size() == 0) break;

		client.send(jpeg.data(), jpeg.size());
	} while (true);

	spdlog::debug("{} finished.", __func__);
}

void decode_loop(SyncQueue<std::unique_ptr<SCTPClient::Data>>& q)
{
	do {
		auto data = q.dequeue();

		if (data->size == 0) break;

		auto jpeg = cv::Mat(1, data->size, CV_8UC1, data->buf);

		auto mat_ptr = std::make_unique<cv::Mat>(cv::imdecode(jpeg, CV_LOAD_IMAGE_UNCHANGED));
		
		recvd_frames_to_display.enqueue(std::move(mat_ptr));
	} while (true);

	auto empty_frame_ptr = std::make_unique<cv::Mat>();
	recvd_frames_to_display.enqueue(std::move(empty_frame_ptr));

	spdlog::debug("{} finished.", __func__);
}


void recvd_display_loop(SyncQueue<std::unique_ptr<cv::Mat>>& q)
{
	do {
		auto frame = q.dequeue();

		if (frame->empty()) break;

		// show the image on the window
		cv::imshow("Echo", *frame);
		
		// wait (10ms) for a key to be pressed
		cv::waitKey(10);
	} while (true);

	spdlog::debug("{} finished.", __func__);
}



int main(int /* argc */, char* argv[])
{
	std::set_terminate(&onTerminate);

	struct option options[CLIOptions::OPTIONS_COUNT];
	parse_args(argv, options);

	std::atomic_bool running { true };

	/* Client config */
	auto cfg = get_cfg_or_die(argv, options);

	/* init video capturing/display/encoding/send threads */
	cv::VideoCapture camera(0);
	if (!camera.isOpened()) {
		std::cerr << "ERROR: Could not open camera" << std::endl;
		return EXIT_FAILURE;
	}

	std::thread capture_thread;
	std::thread local_display_thread;
	std::thread local_encode_thread;
	std::thread send_thread;

	std::thread recvd_decode_thread;
	std::thread recvd_display_thread;

	cv::namedWindow("Webcam", cv::WINDOW_AUTOSIZE);
	cv::namedWindow("Echo", cv::WINDOW_AUTOSIZE);

	/* init sctp client */
	SCTPClient client { cfg };
	client.cfg()->data_cback_f = [&](auto s)
	{ 
		spdlog::trace("Server sent: {}", std::to_string(s->size));

		if (s->size == 0) return; //hack !

		recvd_data.enqueue(std::move(s));

		//auto jpeg_mat = cv::Mat(1, s->size, CV_8UC1, s->buf);
		//auto frame = cv::imdecode(jpeg_mat, CV_LOAD_IMAGE_UNCHANGED);

		// show the image on the window		
		//cv::imshow("Echo", frame);
		
		// wait (10ms) for a key to be pressed
		//cv::waitKey(10);		
	};

	client.cfg()->debug_cback_f = [&](const auto& level, const auto& s)
	{
		std::string s_ { s };
		s_.erase(std::remove(s_.begin(), s_.end(), '\n'), s_.end());

		switch (level) {
			case SCTPClient::TRACE:
				spdlog::trace("{}", s_);
				break;
			case SCTPClient::DEBUG:
	    		spdlog::debug("{}", s_);
	    		break;
			case SCTPClient::INFO:
	    		spdlog::info("{}", s_);
	    		break;
			case SCTPClient::WARNING:
	    		spdlog::warn("{}", s_);
				break;
			case SCTPClient::ERROR:
	    		spdlog::error("{}", s_);
				break;
			case SCTPClient::CRITICAL:
	    		spdlog::critical("{}", s_);
				break;
			default:
	    		spdlog::error("Unknown SCTPClient log level message. {}", s_);
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
			capture_thread = 
				std::thread(&capture_loop,std::ref(running), std::ref(camera));
			local_display_thread = 
				std::thread(&local_display_loop, std::ref(local_frames_to_display));
			local_encode_thread = 
				std::thread(&encode_loop, std::ref(frames_to_encode));
			send_thread = 
				std::thread(&send_loop, std::ref(frames_to_send), std::ref(client));

			recvd_decode_thread = 
				std::thread(&decode_loop, std::ref(recvd_data));
			recvd_display_thread =
				std::thread(&recvd_display_loop, std::ref(recvd_frames_to_display));
			break;
		case SCTPClient::SSL_SHUTDOWN:
			message += "SSL shutdown.";
			break;				
		case SCTPClient::PURGE:
			message += "Terminating...";
			running = false;
			recvd_data.enqueue(std::make_unique<SCTPClient::Data>());
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

	spdlog::info("Press ctrl-D to terminate.");
	do {
		std::string _s;
		if (not getline(std::cin, _s)) break;
	} while (running);

	running = false;
	recvd_data.enqueue(std::make_unique<SCTPClient::Data>()); //hack !

	capture_thread.join();
	local_display_thread.join();
	local_encode_thread.join();
	send_thread.join();

	recvd_decode_thread.join();
	recvd_display_thread.join();

	client.stop();

	return EXIT_SUCCESS;
}