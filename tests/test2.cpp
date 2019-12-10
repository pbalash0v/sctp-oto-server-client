/* 
	minimum sanity client check
*/

#include <memory>
#include <cassert>
#include <exception>

#include "sctp_client.h"


int main(int, char const**)
{
	auto cli_cfg = std::make_shared<SCTPClient::Config>();
	cli_cfg->cert_filename = "../src/certs/client-cert.pem";
	cli_cfg->key_filename = "../src/certs/client-key.pem";

	SCTPClient client { cli_cfg };

	try {	
		client.init();
		client.run();
	} catch (const std::runtime_error& exc) {
		assert(false);
	}

	return EXIT_SUCCESS;
}
