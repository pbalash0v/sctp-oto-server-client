#include <string>
#include <thread>
#include <memory>

#include <cstring>
#include <cassert>

#include "sctp_srvr.h"

int main(int, char const**)
{		
	auto serv_cfg = std::make_shared<SCTPServer::Config>();
	serv_cfg->cert_filename = "../src/certs/server-cert.pem";
	serv_cfg->key_filename = "../src/certs/server-key.pem";

	/* minimum sanity check */
	{
		SCTPServer s { serv_cfg };
		try {
			s.init();
		} catch (const std::runtime_error& exc) {
			assert(false);
		}
		s.run();
	}

	/* two simultaneous servers, shoudln't run */
	{
		SCTPServer s1 { serv_cfg };
		SCTPServer s2 { serv_cfg };

		try {
			s1.init();
		} catch (const std::runtime_error& exc) {
			assert(false);
		}		
		s1.run();

		try {	
			s2.init();
		} catch (const std::runtime_error& exc) {
			assert(true);
		}
	}

	return EXIT_SUCCESS;
}
