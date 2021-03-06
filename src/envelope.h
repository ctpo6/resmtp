#ifndef _ENVELOPE_H_
#define _ENVELOPE_H_

#include <list>
#include <string>
#include <utility>

#include <boost/noncopyable.hpp>

#include "buffers.h"
#include "check.h"
#include "timer.h"

using std::list;
using std::string;

struct envelope : private boost::noncopyable
{
    typedef ystreambuf::mutable_buffers_type ymutable_buffers;
    typedef ystreambuf::const_buffers_type yconst_buffers;
    typedef ybuffers_iterator<yconst_buffers> yconst_buffers_iterator;

    struct rcpt {
        string m_name;
        uint64_t m_suid;
        string m_uid;

        string m_remote_answer;
        check::chk_status m_delivery_status = check::CHK_TEMPFAIL;

        rcpt(string name, uint64_t suid, string uid) :
            m_name(std::move(name)), m_suid(suid), m_uid(std::move(uid))
        {
        }

        inline bool operator==(const rcpt &r) const
        {
            return m_name == r.m_name;
        }
    };
    typedef list<rcpt> rcpt_list_t;

    envelope(bool generate_msg_id);

    void add_recipient(string addr);
    bool has_recipient(uint64_t suid) const;

    void remove_delivered_rcpt();

    void cleanup_answers();

    static string generate_new_id();

    yconst_buffers added_headers_;
    yconst_buffers orig_headers_;
    yconst_buffers altered_message_;
    yconst_buffers orig_message_;
    yconst_buffers_iterator orig_message_body_beg_;
    size_t orig_message_token_marker_size_ = 0;
    size_t orig_message_size_ = 0;

    string m_id;
    string m_sender;
    rcpt_list_t m_rcpt_list;
    timer m_timer;
};

#endif
