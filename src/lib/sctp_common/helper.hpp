#ifndef __sctp_helper_hpp__
#define __sctp_helper_hpp__

#include <boost/assert.hpp>
#include <boost/filesystem.hpp>
#include <boost/process.hpp>


namespace
{

size_t constexpr length(const char* str)
{
    return *str ? 1 + length(str + 1) : 0;
}

}


namespace sctp
{

namespace bp = boost::process;

class cert_and_key final
{
public:
	cert_and_key()
	{
		std::tie(cert_, key_) = generate_cert_and_key();
	}

	cert_and_key(const cert_and_key&) = delete;
	cert_and_key& operator=(const cert_and_key&) = delete;

	~cert_and_key()
	{
		boost::filesystem::remove(cert_);
		boost::filesystem::remove(key_);
	}

	std::string cert() const noexcept { return cert_.string(); }
	std::string key() const noexcept { return key_.string(); }

private:
	boost::filesystem::path cert_;
	boost::filesystem::path key_;

private:

	std::tuple<boost::filesystem::path, boost::filesystem::path> generate_paths()
	{
		boost::filesystem::path cert = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
		boost::filesystem::path key = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();

		return {std::move(cert), std::move(key)};
	}

	std::tuple<boost::filesystem::path, boost::filesystem::path> generate_cert_and_key()
	{
		auto [cert, key] = generate_paths();

		auto generator_proc = bp::child {boost::process::search_path("openssl")
			,"req", "-batch", "-x509", "-newkey", "rsa:2048"
			, "-days", "3650", "-nodes"
			, "-keyout",  key.string()
			, "-out", cert.string()
			,bp::std_out > bp::null, bp::std_err > bp::null
			};
			
		generator_proc.wait();
		BOOST_ASSERT(generator_proc.exit_code() == 0);

		return {cert, key};
	}
};


} // anon namespace

#endif // __sctp_helper_hpp__
