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

#include <sys/prctl.h>
#include <signal.h>

#include "sctp_srvr.h"
#include "sctp_srvr_client.h"
#include "sctp_client.h"

std::atomic_bool running { true };


class BrokenClient : public Client
{
public:
	BrokenClient(struct socket* sctp_sock, SCTPServer& s)
		: Client(sctp_sock, s) {};

	virtual void set_state(Client::State)
	{
	 	running = false;
		throw std::runtime_error("BrokenClient ");
	};
};


//
class BrokenSCTPServer : public SCTPServer
{
public:
	static BrokenSCTPServer& get_instance()
	{
		static BrokenSCTPServer s;
		return s;
	}

protected:
	std::shared_ptr<IClient>client_factory(struct socket* s) override
	{
		return std::make_shared<BrokenClient>(s, *this);
	};
};


constexpr static const char* TEST_STRING = "HELLO";
constexpr static const char* START_SIGNAL = "START_SIGNAL";

int main(int, char const**) {


	/* 
		we need two processes since simultaneously using 
		two instances of usrsctp seems to be impossible
	*/
	int fd[2];
	if (pipe(fd) != 0) {
		return EXIT_FAILURE;
	}

	pid_t pid = fork();
 	if (pid < 0) {		/* fork failed */
		return EXIT_FAILURE;
 	}

 	/* in child process - run client */
 	if (pid == 0) {
		assert(prctl(PR_SET_PDEATHSIG, SIGHUP) >= 0);
		std::atomic_bool running { true };

		auto cli_cfg = std::make_shared<SCTPClient::Config>();
		cli_cfg->cert_filename = "../src/certs/client-cert.pem";
		cli_cfg->key_filename = "../src/certs/client-key.pem";

		SCTPClient client { cli_cfg };

		cli_cfg->state_f = [&](auto state) {
			if (state == SCTPClient::SSL_CONNECTED) {
				client.sctp_send(TEST_STRING);
				std::this_thread::sleep_for(std::chrono::milliseconds(100));
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
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
		}

		client.stop();

	/* in parent process - run server */
 	} else if (pid > 0) {

		auto& server = BrokenSCTPServer::get_instance();

		server.cfg_->cert_filename = "../src/certs/server-cert.pem";
		server.cfg_->key_filename = "../src/certs/server-key.pem";

		server.cfg_->data_cback_f = [&](auto, const auto& s) {
			assert(std::string(static_cast<const char*> (s->data)) == TEST_STRING);
		 	running = false;
		};

		try {
			server.init();
			server.run();
		} catch (const std::runtime_error& exc) {
			return EXIT_FAILURE;
		}

		/* signal server init to client */
	   close(fd[0]);
   	assert(write(fd[1], START_SIGNAL, strlen(START_SIGNAL)));
   	std::cout << "signalled ready to client" << std::endl;

		while (running) {
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
 	}

	return EXIT_SUCCESS;
}
