#undef NDEBUG

#include <string>
#include <atomic>
#include <memory>
#include <algorithm>
#include <iostream>

#include <sys/prctl.h>
#include <signal.h>

#include <unistd.h>

#include <boost/assert.hpp>

#include "sctp_server.hpp"
#include "sctp_client.hpp"
#include "helper.hpp"


constexpr const auto TEST_STRING = "HELLO";
constexpr const auto START_SIGNAL = "START_SIGNAL";


int main(int, char const**)
{
	/*
		we need two processes since using 
		two instanes of usrsctp in one process 
		seems to be impossible
	*/
	int fd[2];
	if (pipe(fd) != 0)
	{
		return EXIT_FAILURE;
	}

	pid_t pid = fork();
	if (pid < 0) /* fork failed */
	{
		return EXIT_FAILURE;
 	}

	if (pid == 0) // child client process
	{
 		BOOST_ASSERT(prctl(PR_SET_PDEATHSIG, SIGHUP) >= 0);

		std::atomic_bool running { true };

		auto cli_cfg = ([&]
		{
			auto cfg = std::make_shared<sctp::Client::Config>();
			return cfg;
		})();

		sctp::Client client {cli_cfg};
		
		client.cfg()->state_cback_f = [&](auto state)
		{
			if (state == sctp::Client::State::SSL_CONNECTED)
			{
				client.send(TEST_STRING, strlen(TEST_STRING) + 1);
				std::this_thread::sleep_for(std::chrono::milliseconds(510));

			 	running = false;
			}
		};

		client.cfg()->debug_cback_f = [&](auto, const auto& s)
		{
			std::string s_ { s };
			s_.erase(std::remove(s_.begin(), s_.end(), '\n'), s_.end());			
			std::cout << s_ << std::endl;
		};

		/* wait for server init */
		close(fd[1]);
		char buf[length(START_SIGNAL)];
		BOOST_ASSERT(read(fd[0], buf, strlen(START_SIGNAL)) > 0);

		client();

		while (running)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
		}

		client.stop();
 	}
 	else if (pid > 0) // server process
 	{
		std::atomic_bool running {true};
		
		auto cfg = std::make_shared<sctp::Server::Config>();
		cfg->event_cback_f = [&](const auto& evt)
		{
			if (evt.type != sctp::ServerEvent::Type::CLIENT_DATA) return;
			
			const char* msg = static_cast<const char*>(evt.client_data.data());
			if (strcmp(msg, TEST_STRING)) BOOST_ASSERT(false);
			else running = false;
		};
		cfg->debug_cback_f = [&](auto, const auto& s)
		{
			std::string s_{s};
			s_.erase(std::remove(s_.begin(), s_.end(), '\n'), s_.end());
		};

		try
		{
			sctp::Server server{cfg};
			server();
			/* signal server init to client */
			close(fd[0]);

			BOOST_ASSERT(write(fd[1], START_SIGNAL, strlen(START_SIGNAL)));

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
