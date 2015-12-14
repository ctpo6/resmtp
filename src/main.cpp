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

#include "ip_options.h"
#include "log.h"
#include "options.h"
#include "pidfile.h"
#include "server.h"


namespace {
void log_err(int prio, const std::string& what, bool copy_to_stderr) {
    g_log.msg(prio, what);
    if (copy_to_stderr)
        std::cerr << what << std::endl;
}
}

void cxx_exception_handler() __attribute__((noreturn));
void cxx_exception_handler() {
    void * array[20];
    int size = backtrace(array, 20);
    backtrace_symbols_fd(array, size, STDERR_FILENO);
    exit(1);
}


int main(int argc, char* argv[]) {
    std::set_terminate(cxx_exception_handler);

    // used to randomize timeouts
    std::srand(std::time(0));

    bool daemonized = false;
    if (!g_config.parse_config(argc, argv, std::cout)) {
        log_err(MSG_VERY_CRITICAL, "Exit (200)", true);
        return 200;
    }

    uint32_t log_level =
            g_config.m_log_level == 0 ? MSG_CRITICAL :
            g_config.m_log_level == 1 ? MSG_NORMAL : MSG_DEBUG;
    g_log.init("resmtp", log_level);

    // initialize DNS servers settings
    if (!g_config.init_dns_settings()) {
        log_err(MSG_CRITICAL, str(boost::format(
            "Can't obtain DNS settings (cfg: use_system_dns_servers=%1% custom_dns_servers=%2%")
                % (g_config.m_use_system_dns_servers ? "yes" : "no")
                % g_config.m_custom_dns_servers),
                true);
        log_err(MSG_VERY_CRITICAL, "Exit (201)", true);
        return 201;
    }
    for (auto &s: g_config.m_dns_servers) {
        g_log.msg(MSG_DEBUG,
                  str(boost::format("DNS server: %1%") % s));
    }

    // initialize backend hosts settings
    if (!g_config.init_backend_hosts_settings()) {
        log_err(MSG_CRITICAL,
                string("Can't obtain backend hosts settings"),
                true);
        log_err(MSG_VERY_CRITICAL, "Exit (201)", true);
        return 201;
    }
    for (auto &b: g_config.backend_hosts) {
        g_log.msg(MSG_DEBUG,
                  str(boost::format("backend host: %1% %2%")
                      % b.host_name
                      % b.weight));
    }

    boost::thread log;
    int rval = 0;
    try {
        if (!g_config.m_ip_config_file.empty()) {
            if (g_ip_config.load(g_config.m_ip_config_file)) {
                g_log.msg(MSG_NORMAL,
                          str(boost::format("Load IP restriction file: name='%1%'")
                              % g_config.m_ip_config_file));
            } else {
                throw std::logic_error(
                            str(boost::format("Can't load IP restriction file: name='%1%'")
                                % g_config.m_ip_config_file));
            }
        }

        sigset_t new_mask;
        sigfillset(&new_mask);
        sigset_t old_mask;
        pthread_sigmask(SIG_BLOCK, &new_mask, &old_mask);

        g_log.msg(MSG_NORMAL, "Starting server...");
        resmtp::server server(g_config);

        // Daemonize as late as possible, so as to be able to copy fatal error to stderr in case the server can't start
        if (!g_config.m_foreground) {
            if (daemon(0, 0) < 0) {
                throw std::runtime_error("Failed to daemonize!");
            }
            daemonized = true;
        }

        // start logging thread
        log = boost::thread( [](){ g_log.run(); } );

        // start server
        server.run();

        if (!g_pid_file.create(g_config.m_pid_file)) {
            log_err(MSG_CRITICAL,
                    str(boost::format("Can't create PID file: %1% (%2%)")
                        % g_config.m_pid_file
                        % strerror(errno)),
                    !daemonized);
        }

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

            g_log.msg(MSG_CRITICAL,
                      str(boost::format("Received signal: %1%, exiting...") % sig));
            break;
        }

        server.stop();
    } catch (const std::exception &e) {
        log_err(MSG_CRITICAL,
                str(boost::format("Can't start server: %1%") % e.what()),
                !daemonized);
        rval = 202;
    }

    g_pid_file.unlink();

    // If an exception occured before the creation of the logging thread we need to create it here to log pending errors
    if (log.get_id() == boost::thread::id()) {
        log = boost::thread( [](){ g_log.run(); } );
    }

    log_err(rval ? MSG_VERY_CRITICAL : MSG_NORMAL,
            str(boost::format("Exit (%1%)") % rval),
            !daemonized);

    g_log.stop();
    log.join();

    return rval;
}
