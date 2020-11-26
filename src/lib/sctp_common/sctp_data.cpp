#include <memory>
#include <cstring>

#include "sctp_data.h"

using namespace sctp;


Data::Data(const void* from, size_t len)
{
	buf = calloc(len, sizeof(char));
	if (not buf) throw std::runtime_error("Calloc failed.");

	memcpy(buf, from, len);
	size = len;
}


Data::Data(Data&& other)
{
	size = other.size;
	buf = other.buf;

	other.size = 0;
	other.buf = nullptr;
}


Data& Data::operator=(Data&& other)
{
	if (this != &other) {
		// release the current object's resources
		std::free(buf);
		size = 0;

		// other's resource
		size = other.size;
		buf = other.buf;

		// reset other
		other.size = 0;
		other.buf = nullptr;
	}

	return *this;
}


Data::~Data()
{
	std::free(buf);
}

