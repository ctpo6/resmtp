#ifndef _CHECK_H_
#define _CHECK_H_

#include <string>

struct check
{
    typedef enum
    {
        CHK_ACCEPT      = 0,
        CHK_REJECT,
        CHK_TEMPFAIL,
        CHK_DISCARD

    } chk_status;

    chk_status m_result;
    std::string m_answer;

    std::string m_session_id;
    std::string m_remote_ip;
};

struct check_rcpt_t : public check {
    std::string m_rcpt;
    long long unsigned m_suid;
    std::string m_uid;
};

struct check_data_t : public check {
    // client IP
    std::string m_remote_ip;
    // resolved from client IP
    std::string m_remote_host;
    // extracted from HELO/EHLO
    std::string m_helo_host;
};

#endif // _CHECK_H_
