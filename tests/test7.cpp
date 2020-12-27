#include <string>
#include <atomic>
#include <thread>
#include <memory>
#include <algorithm>
#include <iostream>

#include <string.h>
#include <sys/prctl.h>
#include <signal.h>
#include <unistd.h>

#include <boost/assert.hpp>

#include "sctp_server.h"
#include "sctp_client.h"
#include "helper.hpp"


constexpr const char* TEST_STRING_CLIENT_1 = "HELLO_1";
constexpr const char* TEST_STRING_CLIENT_2 = "HELLO_2";

constexpr const char* START_SIGNAL = "START_SIGNAL";

int main(int, char const**)
{
	/*
		we need two processes since using 
		two instanes of usrsctp in one process 
		seems to be impossible
	*/
	int fd[2];
	if (pipe(fd) != 0) return EXIT_FAILURE;


	pid_t pid = fork();
	if (pid < 0) return EXIT_FAILURE;		/* fork failed */

	if (pid == 0) // child client process
	{
		BOOST_ASSERT(prctl(PR_SET_PDEATHSIG, SIGHUP) >= 0);

		cert_and_key c_and_k;

		std::atomic_bool client1_done { false };
		std::atomic_bool client2_done { false };

		std::mutex cout_mutex;

		auto cli1_cfg = ([&]
		{
			auto cfg = std::make_shared<sctp::Client::Config>();
			cfg->cert_filename = c_and_k.cert().c_str();
			cfg->key_filename = c_and_k.key().c_str();
			return cfg;
		})();

		sctp::Client client1 { cli1_cfg };
		client1.cfg()->state_cback_f = [&](auto state) {
			if (state == sctp::Client::SSL_CONNECTED) {
				client1.send(TEST_STRING_CLIENT_1, strlen(TEST_STRING_CLIENT_1) + 1);
			 	client1_done = true;
			}
		};
		client1.cfg()->debug_cback_f = [&](auto, const auto& s) {
			std::string s_ { s };
			s_.erase(std::remove(s_.begin(), s_.end(), '\n'), s_.end());
			std::lock_guard<std::mutex> _ { cout_mutex };
			std::cout << client1 << ": " + s_ << std::endl;
		};

		auto cli2_cfg = ([&]
		{
			auto cfg = std::make_shared<sctp::Client::Config>();
			cfg->cert_filename = c_and_k.cert().c_str();
			cfg->key_filename = c_and_k.key().c_str();
			return cfg;
		})();
		sctp::Client client2 { cli2_cfg };
		client2.cfg()->state_cback_f = [&](auto state) {
			if (state == sctp::Client::SSL_CONNECTED) {
				client2.send(TEST_STRING_CLIENT_2, strlen(TEST_STRING_CLIENT_2) + 1);
			 	client2_done = true;
			}
		};
		client2.cfg()->debug_cback_f = [&](auto, const auto& s) {
			std::string s_ { s };
			s_.erase(std::remove(s_.begin(), s_.end(), '\n'), s_.end());
			std::lock_guard<std::mutex> _ { cout_mutex };
			std::cout << client2 << ": " + s_ << std::endl;
		};

		client1.init();
		client2.init();

		/* wait for server init */
	   close(fd[1]);
	   char buf[length(START_SIGNAL)];
		BOOST_ASSERT(read(fd[0], buf, strlen(START_SIGNAL)) > 0);

		client1();
		client2();

		while (not (client1_done and client2_done))
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}

	}
	else if (pid > 0) // server process
	{
		cert_and_key c_and_k;

		std::atomic_bool running { true };


		bool client1_done { false };
		bool client2_done { false };

		auto cfg = std::make_shared<SCTPServer::Config>();
		cfg->cert_filename = c_and_k.cert().c_str();
		cfg->key_filename = c_and_k.key().c_str();
		cfg->debug_cback_f = [&](auto, const auto& s)
		{
			std::string s_{s};
			s_.erase(std::remove(s_.begin(), s_.end(), '\n'), s_.end());
			//std::cout << "S:" << s_ << std::endl;
		};
		cfg->event_cback_f = [&](const auto& evt)
		{
			if (evt->type != Event::CLIENT_DATA) return;

			const char* msg = static_cast<const char*>(evt->client_data.data());
			std::string msg_str { msg };

			if (not strcmp(msg, TEST_STRING_CLIENT_1)) {
				std::cout << msg_str << std::endl;
				client1_done = true;
			}
			if (not strcmp(msg, TEST_STRING_CLIENT_2)) {
				std::cout << msg_str << std::endl;
				client2_done = true;
			}
				
	 		running = (client1_done and client2_done) ? false : true;
		};

		try
		{
			SCTPServer server{cfg};
			server();
			/* signal server init to client */
			close(fd[0]);
			BOOST_ASSERT(write(fd[1], START_SIGNAL, strlen(START_SIGNAL)));
			//std::cout << "signalled ready to client" << std::endl;

			while (running)
			{
				std::this_thread::sleep_for(std::chrono::milliseconds(10));
			}
		}
		catch (const std::runtime_error& exc)
		{
			return EXIT_FAILURE;
		}
 	}


	return EXIT_SUCCESS;
}
