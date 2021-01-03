/* 
	minimum sanity server check test
*/
#include <iostream>

#include <boost/assert.hpp>

#include "sctp_server.h"
#include "helper.hpp"


int main(int, char const**)
{
	cert_and_key c_and_k;

	auto cfg = std::make_shared<sctp::Server::Config>();
	cfg->cert_filename = c_and_k.cert().c_str();
	cfg->key_filename = c_and_k.key().c_str();

	try
	{
		sctp::Server s{cfg};
		s();
	}
	catch (const std::runtime_error&)
	{
		BOOST_ASSERT(false);
	}


	try
	{
		sctp::Server s{cfg};
		s();

		try
		{
			sctp::Server _{cfg};
		}
		catch (const std::logic_error&)
		{
		}
	}
	catch (const std::runtime_error&)
	{
		BOOST_ASSERT(false);
	}


	return EXIT_SUCCESS;
}
