/* 
	minimum sanity server check test
*/
#include <iostream>

#include <boost/assert.hpp>

#include "sctp_server.hpp"


int main(int, char const**)
{
	try
	{
		sctp::Server s{std::make_shared<sctp::Server::Config>()};
		s();
	}
	catch (const std::runtime_error&)
	{
		BOOST_ASSERT(false);
	}


	try
	{
		auto cfg = std::make_shared<sctp::Server::Config>();
		
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
