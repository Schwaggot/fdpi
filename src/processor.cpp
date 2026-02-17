#include <condition_variable>
#include <fdpi/processor.hpp>
#include <queue>
#include <thread>

namespace fdpi {

struct PacketProcessor::Impl {
    struct WorkItem {
        std::vector<uint8_t> data;
        Timestamp timestamp;
        DataLinkType dlt{DataLinkType::DLT_EN10MB};
    };

    struct WorkerThread {
        std::thread thread;
        std::queue<WorkItem> queue;
        std::mutex mutex;
        std::condition_variable cv;
        bool running{false};
        PacketDecoder decoder;

        explicit WorkerThread(const PacketDecoder::Config& config) : decoder(config) {}
    };

    Config config;
    std::vector<std::unique_ptr<WorkerThread>> workers;
    std::shared_ptr<PacketHandler> handler;
    std::atomic<size_t> packetsProcessed{0};
    std::atomic<size_t> packetsDropped{0};
    std::atomic<size_t> roundRobinCounter{0};
    std::atomic<bool> started{false};

    static void workerLoop(WorkerThread& worker,
                           const std::shared_ptr<PacketHandler>& handler,
                           std::atomic<size_t>& processed,
                           std::atomic<size_t>& dropped) {
        while (true) {
            WorkItem item;
            {
                std::unique_lock lock(worker.mutex);
                worker.cv.wait(lock,
                               [&] { return !worker.queue.empty() || !worker.running; });

                if (!worker.running && worker.queue.empty()) {
                    break;
                }

                if (worker.queue.empty()) {
                    continue;
                }

                item = std::move(worker.queue.front());
                worker.queue.pop();
            }

            if (auto result =
                    worker.decoder.decode(item.data, item.timestamp, item.dlt)) {
                if (handler) {
                    handler->onPacket(*result);
                }
                processed.fetch_add(1, std::memory_order_relaxed);
            } else {
                if (handler) {
                    handler->onError(result.error(), item.data);
                }
                dropped.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }
};

PacketProcessor::PacketProcessor(Config config) : mImpl(std::make_unique<Impl>()) {
    mImpl->config = config;

    if (config.numThreads == 0) {
        config.numThreads = 1;
    }

    for (size_t i = 0; i < config.numThreads; i++) {
        mImpl->workers.push_back(
            std::make_unique<Impl::WorkerThread>(config.decoderConfig));
    }
}

PacketProcessor::~PacketProcessor() {
    stop();
}

void PacketProcessor::setHandler(std::shared_ptr<PacketHandler> handler) const {
    mImpl->handler = std::move(handler);
}

void PacketProcessor::submit(std::span<const uint8_t> data,
                             const Timestamp timestamp,
                             const DataLinkType dlt) const {
    if (!mImpl->started)
        return;

    std::vector dataCopy(data.begin(), data.end());
    Impl::WorkItem item{std::move(dataCopy), timestamp, dlt};

    size_t workerIdx = 0;

    if (mImpl->config.strategy == DistributionStrategy::RoundRobin) {
        workerIdx = mImpl->roundRobinCounter.fetch_add(1, std::memory_order_relaxed) %
                    mImpl->workers.size();
    } else {
        // FlowPinned: hash the data to pick a consistent worker
        // A simple hash of the first few bytes for flow affinity
        size_t hash = 0;
        for (size_t i = 0; i < std::min(data.size(), size_t(40)); i++) {
            hash = hash * 31 + data[i];
        }
        workerIdx = hash % mImpl->workers.size();
    }

    auto& worker = *mImpl->workers[workerIdx];
    {
        std::lock_guard<std::mutex> lock(worker.mutex);
        worker.queue.push(std::move(item));
    }
    worker.cv.notify_one();
}

void PacketProcessor::submit(std::vector<uint8_t>&& data,
                             const Timestamp timestamp,
                             const DataLinkType dlt) const {
    submit(std::span<const uint8_t>(data), timestamp, dlt);
}

void PacketProcessor::submitBatch(
    std::span<const std::pair<std::span<const uint8_t>, Timestamp>> packets) const {
    for (const auto& [data, ts] : packets) {
        submit(data, ts);
    }
}

void PacketProcessor::start() const {
    if (mImpl->started.exchange(true))
        return;

    for (auto& worker : mImpl->workers) {
        worker->running = true;
        worker->thread = std::thread(Impl::workerLoop, std::ref(*worker), mImpl->handler,
                                     std::ref(mImpl->packetsProcessed),
                                     std::ref(mImpl->packetsDropped));
    }
}

void PacketProcessor::stop() const {
    if (!mImpl->started.exchange(false))
        return;

    for (const auto& worker : mImpl->workers) {
        {
            std::lock_guard<std::mutex> lock(worker->mutex);
            worker->running = false;
        }
        worker->cv.notify_one();
    }

    for (const auto& worker : mImpl->workers) {
        if (worker->thread.joinable()) {
            worker->thread.join();
        }
    }
}

void PacketProcessor::flush() const {
    // Wait for all queues to drain
    for (const auto& worker : mImpl->workers) {
        while (true) {
            std::lock_guard lock(worker->mutex);
            if (worker->queue.empty())
                break;
        }
    }
}

size_t PacketProcessor::packetsProcessed() const {
    return mImpl->packetsProcessed.load(std::memory_order_relaxed);
}

size_t PacketProcessor::packetsDropped() const {
    return mImpl->packetsDropped.load(std::memory_order_relaxed);
}

} // namespace fdpi
