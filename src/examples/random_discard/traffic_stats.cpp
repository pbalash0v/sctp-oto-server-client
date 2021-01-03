#include <string>
#include <iomanip>

#include "traffic_stats.hpp"

void TrafficStats::update(size_t sent) noexcept
{
	elapsed_seconds = std::chrono::system_clock::now() - start;
	sent_total += sent;
}

std::ostream& operator<<(std::ostream& o, const TrafficStats& ts)
{
	o << std::string { "Total running time: " } 
	<< std::setprecision(3) << ts.elapsed_seconds.count() << " seconds"
	<< ", avg speed: " << std::setprecision(4) << ts.sent_total/(1024*ts.elapsed_seconds.count())
	<< std::string { " Kbytes/sec." };
	return o; 
}