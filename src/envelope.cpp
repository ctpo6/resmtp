#include "envelope.h"

#include <cstdio>
#include <cstdlib>
#include <ctime>

#include <pthread.h>

using namespace std;

envelope::envelope()
{
    m_id = generate_new_id();
}


bool envelope::has_recipient(uint64_t suid) const
{
    auto it = find_if(m_rcpt_list.begin(),
                      m_rcpt_list.end(),
                      [suid](const rcpt &a){ return a.m_suid == suid; });
    return it != m_rcpt_list.end();
}


envelope::rcpt_list_t::iterator envelope::add_recipient(string name,
                                                        uint64_t suid,
                                                        string uid)
{
    if (!suid || !has_recipient(suid)) {
        m_rcpt_list.emplace_back(name, suid, uid);
        return --m_rcpt_list.end();
    }
    return m_rcpt_list.end();
}


string envelope::generate_new_id()
{
    static char code_table[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx";
    static_assert(sizeof(code_table) == 61, "code table must be 60 chars length");

    uint32_t pid = static_cast<uint32_t>(getpid());
    uint32_t tid = static_cast<uint32_t>(pthread_self());

    time_t now;
    time(&now);
    struct tm lt;
    localtime_r(&now, &lt);

    return string({code_table[lt.tm_min],
                   code_table[lt.tm_sec],
                   code_table[pid % 60],
                   code_table[tid % 60],
                   code_table[rand() % 60],
                   code_table[rand() % 60],
                   code_table[rand() % 60],
                   code_table[rand() % 60]});
}


void envelope::remove_delivered_rcpt()
{
    m_rcpt_list.erase(
        std::remove_if(m_rcpt_list.begin(), m_rcpt_list.end(),
            [](const rcpt &a)
            {
                return a.m_delivery_status == check::CHK_ACCEPT;
            }),
        m_rcpt_list.end());
}


void envelope::cleanup_answers()
{
    for (auto &r: m_rcpt_list) {
        r.m_remote_answer.clear();
    }
}
