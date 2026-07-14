// Adapted from the user-owned AIM TRAINER reference for this project.
#include "platform/QpcClock.h"

QpcClock::QpcClock() {
    QueryPerformanceFrequency(&frequency_);
}

std::int64_t QpcClock::NowTicks() const {
    LARGE_INTEGER now{};
    QueryPerformanceCounter(&now);
    return now.QuadPart;
}

double QpcClock::TicksToMilliseconds(std::int64_t ticks) const {
    return (static_cast<double>(ticks) * 1000.0) / static_cast<double>(frequency_.QuadPart);
}

double QpcClock::MillisecondsBetween(std::int64_t start_ticks, std::int64_t end_ticks) const {
    return TicksToMilliseconds(end_ticks - start_ticks);
}

std::int64_t QpcClock::TicksFromMilliseconds(double milliseconds) const {
    return static_cast<std::int64_t>((milliseconds * static_cast<double>(frequency_.QuadPart)) / 1000.0);
}

