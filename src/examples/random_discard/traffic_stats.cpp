#include <string>
#include <iomanip>

#include "traffic_stats.h"

void TrafficStats::update(size_t sent) noexcept
{
	sent_total += sent;
}

std::ostream& operator<<(std::ostream& o, const TrafficStats& ts)
{
	std::chrono::duration<double> elapsed_seconds = std::chrono::system_clock::now() - ts.start;
	
	o << std::string { "Total running time: " } 
	<< std::setprecision(3) << elapsed_seconds.count() << " seconds"
	<< ", avg speed: " << std::setprecision(4) << ts.sent_total/(1024*elapsed_seconds.count())
	<< std::string { " Kbytes/sec." };
	return o; 
}