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

	SCTPServer s;

	s.cfg()->cert_filename = c_and_k.cert().c_str();
	s.cfg()->key_filename = c_and_k.key().c_str();

	try
	{
		s.init();
		s();
	}
	catch (const std::runtime_error&)
	{
		BOOST_ASSERT(false);
	}

	return EXIT_SUCCESS;
}
