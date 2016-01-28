#ifndef _CHECK_H_
#define _CHECK_H_

#include <cstdint>
#include <string>

using std::string;

struct check
{
    typedef enum {
        CHK_ACCEPT = 0,
        CHK_REJECT,
        CHK_TEMPFAIL,
        CHK_DISCARD
    } chk_status;

    chk_status m_result;
    string m_answer;

    string m_session_id;
    // client IP
    string m_remote_ip;
};


struct check_rcpt_t : public check
{
    string m_rcpt;
    uint64_t m_suid;
    string m_uid;
};


struct check_data_t : public check
{
    // resolved from client IP
    string m_remote_host;
    // extracted from HELO/EHLO
    string m_helo_host;
    // needed for logging
    bool tarpit;
};

#endif // _CHECK_H_
