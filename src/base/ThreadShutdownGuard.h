#pragma once

#include <thread>
#include <utility>

namespace abdc {

// Owns the shutdown obligation for a separately declared std::thread. Declare
// this immediately after the empty thread and before assigning the worker so
// every later exception has a stop-and-join path during stack unwinding.
template <typename StopRequest>
class ThreadShutdownGuard final {
public:
    ThreadShutdownGuard(std::thread& worker, StopRequest stop_request)
        : worker_(&worker), stop_request_(std::move(stop_request)) {}

    ~ThreadShutdownGuard() noexcept {
        if (!worker_->joinable()) return;
        try {
            stop_request_();
        } catch (...) {
            // Joining is still required: the worker captures stack-owned state.
        }
        worker_->join();
    }

    ThreadShutdownGuard(const ThreadShutdownGuard&) = delete;
    ThreadShutdownGuard& operator=(const ThreadShutdownGuard&) = delete;

    void Join() {
        if (worker_->joinable()) worker_->join();
    }

private:
    std::thread* worker_;
    StopRequest stop_request_;
};

}  // namespace abdc
