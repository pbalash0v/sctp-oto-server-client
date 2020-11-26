/* 
	minimum sanity client check
*/
#include <boost/assert.hpp>

#include <memory>
#include <iostream>
#include <exception>

#include "sctp_client.h"
#include "helper.hpp"


int main(int, const char**)
{
	cert_and_key c_and_k;

	auto cli_cfg = ([&]
	{
		auto cfg = std::make_shared<sctp::Client::Config>();

		cfg->cert_filename = c_and_k.cert().c_str();
		cfg->key_filename = c_and_k.key().c_str();

		return cfg;
	})();

	sctp::Client client {cli_cfg};

	try
	{
		client.init();
		client();
	}
	catch (const std::runtime_error&)
	{
		BOOST_ASSERT(false);
	}

	return EXIT_SUCCESS;
}
