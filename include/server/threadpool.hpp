#ifndef THREADPOOL_HPP
#define THREADPOOL_HPP

#include <mutex>
#include <queue>
#include <thread>
#include <vector>
#include <stdexcept>
#include <functional>
#include <condition_variable>

/** Executes queued callables on a fixed set of worker threads. */
class ThreadPool
{
private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;

    std::mutex queueMutex;
    std::condition_variable condition;
    bool stop;

public:
    /** Starts the requested number of workers.
     * @param threads Number of worker threads to create.
     * @return No value.
     */
    explicit ThreadPool(size_t threads);

    /** Queues a callable for execution by an available worker.
     * @tparam F Callable type accepted by std::function<void()>.
     * @param f Callable task to enqueue.
     * @return No value; throws std::runtime_error after shutdown begins.
     */
    template<class F>
    void enqueue(F&& f) 
    {
        {
            std::unique_lock<std::mutex> lock(queueMutex);

            if (stop)
                throw std::runtime_error("enqueue on stopped ThreadPool");

            tasks.emplace(std::forward<F>(f));
        }

        condition.notify_one();
    }

    /** Stops accepting work and joins all worker threads. */
    ~ThreadPool();
};

#endif
