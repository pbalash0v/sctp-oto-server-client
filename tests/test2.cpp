/* 
	minimum sanity client check
*/
#include <boost/assert.hpp>

#include <memory>
#include <iostream>
#include <exception>

#include "sctp_client.hpp"
#include "helper.hpp"


int main(int, const char**)
{
	auto cli_cfg = ([&]
	{
		auto cfg = std::make_shared<sctp::Client::Config>();

		return cfg;
	})();

	sctp::Client client {cli_cfg};

	try
	{
		client();
	}
	catch (const std::runtime_error&)
	{
		BOOST_ASSERT(false);
	}

	return EXIT_SUCCESS;
}
