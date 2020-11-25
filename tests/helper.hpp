#pragma once

#include <boost/assert.hpp>
#include <boost/filesystem.hpp>
#include <boost/process.hpp>


namespace
{
	std::tuple<std::string, std::string> generate_paths()
	{
		boost::filesystem::path cert = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
		boost::filesystem::path key = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();

		return {cert.string(), key.string()};
	}

	std::tuple<std::string, std::string> generate_cert_and_key()
	{
		auto [cert, key] = generate_paths();

		auto generator_proc = boost::process::child {boost::process::search_path("openssl"), "req", "-batch", "-x509", "-newkey",
			"rsa:2048", "-days", "3650", "-nodes", "-keyout",  key, "-out", cert};

		generator_proc.wait();
		BOOST_ASSERT(generator_proc.exit_code() == 0);

		return {cert, key};
	}

	class cert_and_key final
	{
	public:
		cert_and_key()
		{
			std::tie(cert_, key_) = generate_cert_and_key();
		}

		~cert_and_key()
		{
			boost::filesystem::remove(cert_);
			boost::filesystem::remove(key_);
		}

		std::string cert() const noexcept { return cert_; }
		std::string key() const noexcept { return key_; }

	private:
		std::string cert_;
		std::string key_;
	};
}
