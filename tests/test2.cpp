#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <cstring>
#include <memory>
#include <cassert>
#include <limits>
#include <unistd.h>
#include <cstdio>


#include "sctp_srvr.h"
#include "sctp_client.h"

constexpr const char* TEST_STRING = "HELLO";


int main(int, char const**) {

	/*
		we need two processes since using 
		two instanes of usrsctp seems to be impossible
	*/

	pid_t pid = fork();

 	if (pid == 0) { 	// client process
		std::atomic_bool running { true };

		auto cli_cfg = std::make_shared<SCTPClient::Config>();
		cli_cfg->cert_filename = "../src/certs/client-cert.pem";
		cli_cfg->key_filename = "../src/certs/client-key.pem";

		SCTPClient client { cli_cfg };

		cli_cfg->state_f = [&](auto state) {
			if (state == SCTPClient::SSL_CONNECTED) {
				client.sctp_send(TEST_STRING);
				std::this_thread::sleep_for(std::chrono::milliseconds(1000));
			 	running = false;
			}

		};

		client.init();
		client.run();

		while (running) {
			std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		}

		client.stop();

 	} else if (pid > 0) {      // server process
		std::atomic_bool running { true };

		auto serv_cfg = std::make_shared<SCTPServer::Config>();
		serv_cfg->cert_filename = "../src/certs/server-cert.pem";
		serv_cfg->key_filename = "../src/certs/server-key.pem";
		serv_cfg->data_cback_f = [&](auto, const auto& s) {
			assert(s == TEST_STRING);
		 	running = false;
		};

		SCTPServer server { serv_cfg };

		server.init();
		server.run();

		while (running) {
			std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		}
 	} else {		// fork failed
		return 1;
 	}


	return EXIT_SUCCESS;
}
