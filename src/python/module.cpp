#include <pybind11/pybind11.h>
#include <pybind11/functional.h>

#include <sctp_server.hpp>


namespace py = pybind11;

PYBIND11_MODULE(pysctp, m)
{
    m.doc() = "SCTP OTO";

    py::class_<sctp::Server::Config, std::shared_ptr<sctp::Server::Config>>(m, "ServerConfig")
    	.def(py::init([]() { return std::make_shared<sctp::Server::Config>(); }))
    	.def_readwrite("cert_filename", &sctp::Server::Config::cert_filename)
    	.def_readwrite("key_filename", &sctp::Server::Config::key_filename)
		.def_property("event_cback"
			, [] { return &sctp::Server::Config::event_cback_f; }
			, [] (sctp::Server::Config c, sctp::Server::event_cback_t f) { c.event_cback_f = f; }
			);

    py::class_<sctp::Server>(m, "Server")
        .def(py::init<std::shared_ptr<sctp::Server::Config>>())
        .def("stop", &sctp::Server::stop);

	py::enum_<sctp::LogLevel>(m, "LogLevel")
		.value("TRACE", sctp::LogLevel::TRACE)
		.value("DEBUG", sctp::LogLevel::DEBUG)
		.value("INFO", sctp::LogLevel::INFO)
		.value("WARNING", sctp::LogLevel::WARNING)
		.value("ERROR", sctp::LogLevel::ERROR)
		.value("CRITICAL", sctp::LogLevel::CRITICAL)
		.value("NONE", sctp::LogLevel::NONE);
}
