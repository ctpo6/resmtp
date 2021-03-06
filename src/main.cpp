/*
 * resmtp
 */

#include <cxxabi.h>
#include <execinfo.h>
#include <pthread.h>
#include <signal.h>
#include <sys/resource.h>

#include <cstdlib>
#include <ctime>
#include <exception>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

#if 0
#include <boost/asio.hpp>
#else
#include "asio/asio.hpp"
#endif
#include <boost/thread.hpp>

#include "global.h"
#include "ip_options.h"
#include "server.h"


using namespace std;

namespace r = resmtp;

namespace {

void log_err(r::log prio, string s, bool copy_to_stderr)
{
  if (copy_to_stderr && r::Log::isEnabled(prio)) {
    cerr << s << endl;
  }
  g::log().msg(prio, std::move(s));
}

void log_err(const std::pair<r::log, string> &p, bool copy_to_stderr)
{
  if (copy_to_stderr && r::Log::isEnabled(p.first)) {
    cerr << p.second << endl;
  }
  g::log().msg(p);
}

void free_deleter(char *ptr)
{
  if (ptr) free(ptr);
}

unique_ptr<char, void (*)(char *) >
get_demangled_symbol_from_backtrace_str(char *str)
{
  unique_ptr<char, void (*)(char *) > result(nullptr, free_deleter);

  char *begin = strchr(str, '(');
  char *end = strchr(str, '+');
  if (begin == nullptr || end == nullptr || begin > end) {
    return result;
  }
  ++begin;

  char save = *end;
  *end = 0;
  int status;
  char *ret = abi::__cxa_demangle(begin, 0, 0, &status);
  *end = save;
  if (status) {
    return result;
  }
  result.reset(ret);
  return result;
}

void print_backtrace()
{
  void * array[20];
  int size = backtrace(array, 20);
  if (!size) return;

  char **s = backtrace_symbols(array, size);

  // start from 1 to skip print_backtrace() itself
  for (int i = 1; i < size; ++i) {
    auto demangled = get_demangled_symbol_from_backtrace_str(s[i]);
    if (demangled) {
      cerr << demangled.get() << endl;
    }
    else {
      cerr << s[i] << endl;
    }
  }

  free(s);
}


void cxx_exception_handler() __attribute__((noreturn));

void cxx_exception_handler()
{
  // TODO it seems using cerr isn't safe here
  // TODO rewrite using raw file IO ???

  // print state
  g::mon().print(cerr);

  // print call stack backtrace
  print_backtrace();

  exit(1);
}

}


int main(int argc, char* argv[])
{
  bool daemonized = false;

  std::set_terminate(cxx_exception_handler);
  std::srand(std::time(nullptr));

  try {
    if (!g::cfg().parse_config(argc, argv)) {
      // user specified one of options requiring to stop further execution
      return 0;
    }
  }
  catch (const std::exception &e) {
    log_err(r::log::err,
            util::strf("config error (%s): %s", g::cfg().config_file_.c_str(), e.what()),
            true);
    return 1;
  }

  // init main log, asap
  g::log().init(g::cfg().log_level);
  
  // init spamhaus log
  try {
    g::logsph().init(g::cfg().spamhaus_log_file.c_str(),
                     g::cfg().m_uid,
                     g::cfg().m_gid);
  }
  catch (const std::exception &e) {
    log_err(r::log::err, e.what(), true);
    // continue execution
  }

  for (const auto &addr : g::cfg().white_ip) {
    g::log().msg(r::Log::pstrf(r::log::info,
                               "white IP: %s",
                               addr.to_string().c_str()));
  }

  for (const auto &addr : g::cfg().dns_ip) {
    g::log().msg(r::Log::pstrf(r::log::info,
                               "DNS server: %s",
                               addr.to_string().c_str()));
  }

  for (auto &b : g::cfg().backend_hosts) {
    g::log().msg(r::Log::pstrf(r::log::info,
                               "backend host: %s %u",
                               b.host_name.c_str(),
                               b.weight));
  }

  boost::thread t_log;
  boost::thread t_spamhaus_log;
  int rval = 0;
  try {
    if (!g::cfg().m_ip_config_file.empty()) {
      if (!g_ip_config.load(g::cfg().m_ip_config_file)) {
        throw std::runtime_error(util::strf("can't load IP restriction file: %s",
                                            g::cfg().m_ip_config_file.c_str()));
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
    t_log = boost::thread([]() { g::log().run(); });

    // start spamhaus log thread
    t_spamhaus_log = boost::thread([]() { g::logsph().run(); });

    // start server
    server.run();

    if (!g::pid_file().create(g::cfg().m_pid_file)) {
      log_err(r::Log::pstrf(r::log::err,
                            "ERROR: can't create PID file: %s",
                            g::cfg().m_pid_file.c_str()),
              !daemonized);
      // continue execution
    }

    log_err(r::log::notice, "successfully started", !daemonized);

    int sig;
    while (true) {
      pthread_sigmask(SIG_SETMASK, &old_mask, 0);
      sigset_t wait_mask;
      sigemptyset(&wait_mask);
      sigaddset(&wait_mask, SIGINT);
      sigaddset(&wait_mask, SIGQUIT);
      sigaddset(&wait_mask, SIGTERM);
      sigaddset(&wait_mask, SIGHUP);
      pthread_sigmask(SIG_BLOCK, &wait_mask, 0);
      sigwait(&wait_mask, &sig);

      if (sig == SIGHUP) {
        log_err(r::log::notice, "received SIGHUP", !daemonized);
        g::logsph().recreate_log_file();
        continue;
      }

      log_err(r::Log::pstrf(r::log::notice,
                            "received signal: %d, stopping server",
                            sig),
              !daemonized);
      break;
    }

    time_t t0 = std::time(nullptr);
#if 0
    // TODO
    // it's a really very graceful stop: allow sessions to finish;
    // now it's needed to be fixed to cancel timeout timers as
    // there are hanging sessions, taking a LOT of time to expire
    if (sig == SIGINT) {
      server.gracefully_stop();
    }
    else
#else
  {
    // not so graceful stop: close sockets immediately
    server.stop();
  }
#endif
      // TODO
      // now there is a problem: this message may not appear in the log on
      // SIGTERM; server seems to be stopped immediately, never reaching this
      // line;
      // SIGINT has the same problem too
      log_err(r::Log::pstrf(r::log::notice,
                            "server stopped in %u seconds",
                            static_cast<unsigned>(std::time(nullptr) - t0)),
              !daemonized);
  }
  catch (const std::exception &e) {
    log_err(r::log::alert, e.what(), !daemonized);
    rval = 1;
  }

  g::pid_file().unlink();

  // If an exception occured before the creation of the logging thread we need to create it here to log pending errors
  if (t_log.get_id() == boost::thread::id()) {
    t_log = boost::thread([]() { g::log().run(); });
  }

  g::logsph().stop();
  g::log().stop();
  t_spamhaus_log.join();

  log_err(r::Log::pstrf(r::log::notice, "exit: %d", rval), !daemonized);
  t_log.join();

  return rval;
}
