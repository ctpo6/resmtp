/*
 * resmtp
 */

#include <execinfo.h>
#include <pthread.h>
#include <signal.h>

#include <cstdlib>
#include <ctime>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>

#include <boost/asio.hpp>
#include <boost/format.hpp>
#include <boost/thread.hpp>

#include "global.h"
#include "ip_options.h"
#include "server.h"


using namespace std;

namespace r = resmtp;

//namespace {
void log_err(r::log prio, string s, bool copy_to_stderr) noexcept
{
    if (copy_to_stderr) {
        cerr << s << endl;
    }
    g::log().msg(prio, std::move(s));
}
//}

void cxx_exception_handler() __attribute__((noreturn));
void cxx_exception_handler()
{
    // TODO it seems using cerr isn't safe here
    // TODO rewrite using raw file IO ???

    // print state
    g::mon().print(cerr);

    // print call stack backtrace
    void * array[20];
    int size = backtrace(array, 20);

#if 0
    // it's get messed with cerr output
    backtrace_symbols_fd(array, size, STDERR_FILENO);
#endif

    if (size > 0) {
        char **s = backtrace_symbols(array, size);
        for (int i = 0; i < size; ++i) {
            cerr << s[i] << endl;
        }
        free(s);
    }

    exit(1);
}


int main(int argc, char* argv[])
{
    std::set_terminate(cxx_exception_handler);

    std::srand(std::time(0));

    bool daemonized = false;
    try {
        if (!g::cfg().parse_config(argc, argv)) {
            return 0;
        }
    } catch (const std::exception &e) {
        log_err(r::log::alert, e.what(), true);
        return 1;
    }

    // init main log
    cout << static_cast<int>(g::cfg().log_level) << endl;
    g::log().init(g::cfg().log_level);

    // init spamhaus log
    try {
        g::logsph().init(g::cfg().spamhaus_log_file.c_str());
    } catch (const std::exception &e) {
        log_err(r::log::err, e.what(), true);
        // continue execution
    }

    // initialize DNS servers settings
    if (!g::cfg().init_dns_settings()) {
        log_err(r::log::alert,
                str(boost::format(
                        "can't obtain DNS settings (cfg: use_system_dns_servers=%1% custom_dns_servers=%2%")
                % (g::cfg().m_use_system_dns_servers ? "yes" : "no")
                % g::cfg().m_custom_dns_servers),
                true);
        return 1;
    }
    for (auto &s: g::cfg().m_dns_servers) {
        g::log().msg(r::log::info,
                     str(boost::format("DNS server: %1%") % s));
    }

    // initialize backend hosts settings
    if (!g::cfg().init_backend_hosts_settings()) {
        log_err(r::log::alert,
                "can't obtain backend hosts settings",
                true);
        return 1;
    }
    for (auto &b: g::cfg().backend_hosts) {
        g::log().msg(r::log::info,
                     str(boost::format("backend host: %1% %2%")
                         % b.host_name
                         % b.weight));
    }

    boost::thread t_log;
    boost::thread t_spamhaus_log;
    int rval = 0;
    try {
        if (!g::cfg().m_ip_config_file.empty()) {
            if (!g_ip_config.load(g::cfg().m_ip_config_file)) {
                throw std::runtime_error(
                            str(boost::format("can't load IP restriction file: %1%")
                                % g::cfg().m_ip_config_file));
            }
        }

        sigset_t new_mask;
        sigfillset(&new_mask);
        sigset_t old_mask;
        pthread_sigmask(SIG_BLOCK, &new_mask, &old_mask);

        resmtp::server server(g::cfg());

        // Daemonize as late as possible, so as to be able to copy fatal error to stderr in case the server can't start
        if (!g::cfg().m_foreground) {
            if (daemon(0, 0) < 0) {
                throw std::runtime_error("failed to daemonize");
            }
            daemonized = true;
        }

        // start main log thread
        t_log = boost::thread( [](){ g::log().run(); } );

        // start spamhaus log thread
        t_spamhaus_log = boost::thread( [](){ g::logsph().run(); } );

        // start server
        server.run();

        if (!g::pid_file().create(g::cfg().m_pid_file)) {
            log_err(r::log::err,
                    str(boost::format("can't create PID file: %1% (%2%)")
                        % g::cfg().m_pid_file
                        % strerror(errno)),
                    !daemonized);
            // continue execution
        }

        log_err(r::log::notice,
                "server successfully started", !daemonized);

        while(true) {
            pthread_sigmask(SIG_SETMASK, &old_mask, 0);
            sigset_t wait_mask;
            sigemptyset(&wait_mask);
            sigaddset(&wait_mask, SIGINT);
            sigaddset(&wait_mask, SIGQUIT);
            sigaddset(&wait_mask, SIGTERM);
            sigaddset(&wait_mask, SIGHUP);
            sigaddset(&wait_mask, SIGSEGV);
            pthread_sigmask(SIG_BLOCK, &wait_mask, 0);
            int sig = 0;
            sigwait(&wait_mask, &sig);

            if (sig == SIGHUP) {
                continue;
            }

            if (sig == SIGSEGV) {
                void * array[10];
                size_t size;

                // get void*'s for all entries on the stack
                size = backtrace(array, 10);

                // print out all the frames to stderr
                std::cerr << "Error: SIGSEGV signal" << std::endl;
                backtrace_symbols_fd(array, size, STDERR_FILENO);
                exit(1);
            }

            log_err(r::log::notice,
                    str(boost::format("received signal: %1%, exiting:") % sig),
                    !daemonized);
            break;
        }

        log_err(r::log::notice, "stopping server...", !daemonized);
        server.gracefully_stop();
    } catch (const std::exception &e) {
        log_err(r::log::alert, e.what(), !daemonized);
        rval = 1;
    }

    g::pid_file().unlink();

    // If an exception occured before the creation of the logging thread we need to create it here to log pending errors
    if (t_log.get_id() == boost::thread::id()) {
        t_log = boost::thread( [](){ g::log().run(); } );
    }

    log_err(r::log::notice, "stopping loggers...", !daemonized);
    g::logsph().stop();
    g::log().stop();
    t_spamhaus_log.join();
    t_log.join();

    return rval;
}
