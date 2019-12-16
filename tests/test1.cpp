/* 
	minimum sanity server check test
*/

#include <memory>
#include <cassert>

#include "sctp_server.h"


int main(int, char const**)
{		
	SCTPServer s;

	s.cfg_->cert_filename = "../src/certs/server-cert.pem";
	s.cfg_->key_filename = "../src/certs/server-key.pem";

	try {
		s.init();
		s.run();
	} catch (const std::runtime_error& exc) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
