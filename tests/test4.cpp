#include <string>
#include <atomic>
#include <memory>
#include <algorithm>

#include <cassert>

#include <sys/prctl.h>
#include <signal.h>

#include <unistd.h>

#include "sctp_server.h"
#include "sctp_client.h"


constexpr const char* TEST_STRING = "HELLO";
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

		auto cli_cfg = ([]
		{
			auto cfg = std::make_shared<SCTPClient::Config>();
			cfg->cert_filename = "../src/certs/client-cert.pem";
			cfg->key_filename = "../src/certs/client-key.pem";
			return cfg;
		})();

		SCTPClient client { cli_cfg };
		
		client.cfg()->state_cback_f = [&](auto state) {
			if (state == SCTPClient::SSL_CONNECTED) {
				client.send(TEST_STRING, strlen(TEST_STRING) + 1);
				std::this_thread::sleep_for(std::chrono::milliseconds(510));

			 	running = false;
			}
		};

		client.cfg()->debug_cback_f = [&](auto, const auto& s) {
			std::string s_ { s };
			s_.erase(std::remove(s_.begin(), s_.end(), '\n'), s_.end());			
			std::cout << s_ << std::endl;
		};

		client.init();

		/* wait for server init */
	   close(fd[1]);
	   char buf[strlen(START_SIGNAL)];
		assert(read(fd[0], buf, strlen(START_SIGNAL)) > 0);

		client();

		while (running) {
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
		}

		client.stop();
 	} else if (pid > 0) {      // server process
		std::atomic_bool running { true };

		SCTPServer server;

		server.cfg()->cert_filename = "../src/certs/server-cert.pem";
		server.cfg()->key_filename = "../src/certs/server-key.pem";
		server.cfg()->event_cback_f = [&](const auto& evt) {
			if (evt->type != Event::CLIENT_DATA) return;
			
			const char* msg = static_cast<const char*>(evt->client_data->buf);
			if (strcmp(msg, TEST_STRING)) {
				assert(false);
			} else {
				running = false;
			}
		};
		server.cfg()->debug_cback_f = [&](auto, const auto& s) {
			std::string s_ { s };
			s_.erase(std::remove(s_.begin(), s_.end(), '\n'), s_.end());
			std::cout << "S:" << s_ << std::endl;
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
