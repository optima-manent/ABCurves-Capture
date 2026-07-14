// Adapted from the user-owned AIM TRAINER reference for this project.
#pragma once

#include <cstdint>
#include <windows.h>

class QpcClock {
public:
    QpcClock();

    [[nodiscard]] std::int64_t NowTicks() const;
    [[nodiscard]] double TicksToMilliseconds(std::int64_t ticks) const;
    [[nodiscard]] double MillisecondsBetween(std::int64_t start_ticks, std::int64_t end_ticks) const;
    [[nodiscard]] std::int64_t TicksFromMilliseconds(double milliseconds) const;
    [[nodiscard]] std::int64_t Frequency() const { return frequency_.QuadPart; }

private:
    LARGE_INTEGER frequency_{};
};

