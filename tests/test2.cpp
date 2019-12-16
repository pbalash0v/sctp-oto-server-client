/* 
	minimum sanity client check
*/

#include <memory>
#include <cassert>
#include <exception>

#include "sctp_client.h"


int main(int, char const**)
{
	auto cli_cfg = ([]
	{
		auto cfg = std::make_shared<SCTPClient::Config>();
		cfg->cert_filename = "../src/certs/client-cert.pem";
		cfg->key_filename = "../src/certs/client-key.pem";
		return cfg;
	})();


	SCTPClient client;
	client.cfg_ = cli_cfg;

	try {	
		client.init();
		client.run();
	} catch (const std::runtime_error& exc) {
		assert(false);
	}

	return EXIT_SUCCESS;
}
