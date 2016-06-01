#if !defined(_IP_OPTIONS_H_)
#define _IP_OPTIONS_H_

#include <list>

#if 0
#include <boost/asio.hpp>
#else
#include "asio/asio.hpp"
#endif


class ip_options_config
{

  public:


    typedef struct
    {
        unsigned int m_rcpt_count;

    } ip_options_t;

    ip_options_config();

    bool load(const std::string _file);

    bool check(const asio::ip::address_v4 _address, ip_options_t &_options);

    typedef struct
    {
        unsigned int m_network;
        unsigned int m_mask;
        ip_options_t m_options;
    } opt_store_t;

  protected:

    typedef std::list<opt_store_t> opt_store_list;

    opt_store_list m_opt_list;
};

extern ip_options_config g_ip_config;

#endif
