#include <string>
#include <atomic>
#include <memory>
#include <cassert>

#include <unistd.h>

#include "sctp_srvr.h"
#include "sctp_client.h"


constexpr const char* TEST_STRING = "HELLO";
constexpr const char* START_SIGNAL = "START_SIGNAL";

int main(int, char const**)
{
	/*
		we need two processes since using 
		two instanes of usrsctp seems to be impossible
	*/
	int fd[2];
	if (pipe(fd) != 0) {
		return EXIT_FAILURE;
	}

	pid_t pid = fork();
 	if (pid < 0) {		/* fork failed */
		return EXIT_FAILURE;
 	}

 	if (pid == 0) { 	// client process
		std::atomic_bool running { true };

		auto cli_cfg = std::make_shared<SCTPClient::Config>();
		cli_cfg->cert_filename = "../src/certs/client-cert.pem";
		cli_cfg->key_filename = "../src/certs/client-key.pem";

		SCTPClient client { cli_cfg };

		cli_cfg->state_f = [&](auto state) {
			if (state == SCTPClient::SSL_CONNECTED) {
				client.sctp_send(TEST_STRING);
			 	running = false;
			}

		};

		client.init();

		/* wait for server init */
	   close(fd[1]);
	   char buf[strlen(START_SIGNAL)];
		assert(read(fd[0], buf, strlen(START_SIGNAL)) > 0);

		client.run();

		while (running) {
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}


 	} else if (pid > 0) {      // server process
		std::atomic_bool running { true };

		auto serv_cfg = std::make_shared<SCTPServer::Config>();
		serv_cfg->cert_filename = "../src/certs/server-cert.pem";
		serv_cfg->key_filename = "../src/certs/server-key.pem";
		serv_cfg->data_cback_f = [&](auto, const auto& s) {
			assert(std::string(static_cast<const char*> (s->data)) == TEST_STRING);
		 	running = false;
		};
		serv_cfg->debug_f = [&](auto, const auto& s) {
			std::cout << s << std::endl;
		};

		SCTPServer server { serv_cfg };

		server.init();
		server.run();

		/* signal server init to client */
	   close(fd[0]);
   	assert(write(fd[1], START_SIGNAL, strlen(START_SIGNAL)));

		while (running) {
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
 	}


	return EXIT_SUCCESS;
}
