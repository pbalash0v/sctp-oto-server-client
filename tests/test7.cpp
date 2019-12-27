#include <string>
#include <atomic>
#include <memory>
#include <cassert>
#include <algorithm>

#include <sys/prctl.h>
#include <signal.h>

#include <unistd.h>

#include "sctp_server.h"
#include "sctp_client.h"


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
	if (pipe(fd) != 0) {
		return EXIT_FAILURE;
	}

	pid_t pid = fork();
 	if (pid < 0) {		/* fork failed */
		return EXIT_FAILURE;
 	}

 	if (pid == 0) { 	// child client process
 		assert(prctl(PR_SET_PDEATHSIG, SIGHUP) >= 0);

		std::atomic_bool running { true };

		auto cli1_cfg = ([]
		{
			auto cfg = std::make_shared<SCTPClient::Config>();
			cfg->cert_filename = "../src/certs/client-cert.pem";
			cfg->key_filename = "../src/certs/client-key.pem";
			return cfg;
		})();

		SCTPClient client1 { cli1_cfg };
		client1.cfg()->state_cback_f = [&](auto state) {
			if (state == SCTPClient::SSL_CONNECTED) {
				std::string _s = std::string(TEST_STRING_CLIENT_1);
				client1.send(_s.c_str(), _s.size());
			 	running = false;
			}
		};
		client1.cfg()->debug_cback_f = [&](auto, const auto& s) {
			std::string s_ { s };
			s_.erase(std::remove(s_.begin(), s_.end(), '\n'), s_.end());
			std::cout << client1 << ": " + s_ << std::endl;
		};

		auto cli2_cfg = ([]
		{
			auto cfg = std::make_shared<SCTPClient::Config>();
			cfg->cert_filename = "../src/certs/client-cert.pem";
			cfg->key_filename = "../src/certs/client-key.pem";
			return cfg;
		})();
		SCTPClient client2 { cli2_cfg };
		client2.cfg()->state_cback_f = [&](auto state) {
			if (state == SCTPClient::SSL_CONNECTED) {
				std::string _s = std::string(TEST_STRING_CLIENT_2);
				client2.send(_s.c_str(), _s.size());
			 	running = false;
			}
		};
		client2.cfg()->debug_cback_f = [&](auto, const auto& s) {
			std::string s_ { s };
			s_.erase(std::remove(s_.begin(), s_.end(), '\n'), s_.end());			
			std::cout << client2 << ": " + s_ << std::endl;
		};

		client1.init();
		client2.init();

		/* wait for server init */
	   close(fd[1]);
	   char buf[strlen(START_SIGNAL)];
		assert(read(fd[0], buf, strlen(START_SIGNAL)) > 0);

		client1();
		client2();

		while (running) {
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
		}
 	} else if (pid > 0) {      // server process
		std::atomic_bool running { true };

		SCTPServer server;

		bool client1_done { false };
		bool client2_done { false };

		server.cfg()->cert_filename = "../src/certs/server-cert.pem";
		server.cfg()->key_filename = "../src/certs/server-key.pem";
		server.cfg()->data_cback_f = [&](auto, const auto& s) {
			auto msg { static_cast<const char*> (s->data) };

			if (msg == TEST_STRING_CLIENT_1) {
				std::cout << msg << std::endl;
				client1_done = true;
			}
			if (msg == TEST_STRING_CLIENT_2) {
				std::cout << msg << std::endl;
				client2_done = true;
			}
				
	 		running = (client1_done && client2_done) ? true : false;
		};
		server.cfg()->debug_f = [&](auto, const auto& s) {
			std::string s_ { s };
			s_.erase(std::remove(s_.begin(), s_.end(), '\n'), s_.end());			
			std::cout << s_ << std::endl;
		};

		try {
			server.init();
			server();
		} catch (const std::runtime_error& exc) {
			return EXIT_FAILURE;
		}

		/* signal server init to client */
	   close(fd[0]);
   	assert(write(fd[1], START_SIGNAL, strlen(START_SIGNAL)));
   	std::cout << "signalled ready to client" << std::endl;

		while (running) {
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
		}
 	}


	return EXIT_SUCCESS;
}
