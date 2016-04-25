//
// network_array.hpp
// ~~~~~~~~~~~~~~~~~
//
// Copyright (c) 1998-2006 Andreas Haberstroh (softwareace at yahoo dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#pragma once

// Our primary dependency is boost::asio. We can't live without it!
#include <boost/asio/detail/push_options.hpp>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <boost/iterator.hpp>
#include <boost/cstdint.hpp>
#include <boost/scoped_array.hpp>
#include <boost/asio.hpp>
#include <boost/array.hpp>

//using namespace boost;
//using namespace boost::asio;

namespace y {
namespace net {

/**
   The network_array class template provides a static size array of bytes
   that has accessor functions to make getting and setting data network friendly.

   Uses the Endian/Non-Endian transform functions, (i.e. htons,ntohs)

   Derived from boost::array.
*/
template<std::size_t N>
class network_array : public boost::array<uint8_t, N>
{
  using base = boost::array<uint8_t, N>;

    /// Position in memory buffer for get/put
    size_t  nap;  // acronym: network array position

    /// Total size of memory buffer, not necessarily the N size of the buffer
    size_t  nal; // acronym: network array length

  public:
    /// Constructs an empty network_array
    /*

    */
    network_array() : nap(0), nal(0)
    {
        //    array<uint8_t,N>::assign((uint8_t)0x00);
    }

    /// Get & Set the position in the array
    /**
       @param p Sets the current caret position in the array. If left blank, it does not change the position, but only reports the position.
       @return The current caret position in the array
    */
    size_t position(const size_t p=N+1)
    {
        if( p != N + 1 )  nap = p;
        return nap;
    }

    /// Get & Set the length of data in the array
    /**
       This function does not change the size of the array, but only the reporting aspect of the amount of data contained in the array.
       @param l Sets the data length in the array. If left blank, it does not change the length, but only reports the length.
       @return The current length of the array
    */
    size_t length(const size_t l=N+1)
    {
        if( l != N + 1 )  nal = l;
        return nal;
    }

    /// Gets data from the array
    /**
       Gets a char from the array.
       @param d Data to retrieve
       @param p Position to retrieve data from. If left blank, will retrieve from the current caret position
       @param incpos Increments the caret position in the array. If set to false the function acts like a peek
       @return The amount of bytes retrieved from the array
    */
    size_t get(char & d, const size_t p=N+1, const bool incpos=true)
    {
        if( p != N+1 )
        {
            base::rangecheck(p);
            position(p);
        }

        d = (char)base::elems[nap];
        if( incpos ) nap += sizeof(d);

        return sizeof(d);
    }

    /// Puts data into the array
    /**
       Puts a char into the array.
       @param d Data to write into the array
       @param p Position to write data to. If left blank, will write to the current caret position.
       @param incpos Increments the caret position in the array. If set to false the function acts like a poke
       @return The amount of bytes writen from the array
    */
    size_t put(const char d, const size_t p=N+1, const bool incpos=true)
    {
        if( p != N+1 )
        {
            base::rangecheck(p);
            position(p);
        }

        base::elems[nap] = (uint8_t)d;
        if( incpos )
        {
            nap += sizeof(d);
            if( nap > nal )
                nal += sizeof(d);
        }

        return sizeof(d);
    }

    /// Gets data from the array
    /**
       Gets a uint8_t from the array.
       @param d Data to retrieve
       @param p Position to retrieve data from. If left blank, will retrieve from the current caret position
       @param incpos Increments the caret position in the array. If set to false the function acts like a peek
       @return The amount of bytes retrieved from the array
    */
    size_t get(uint8_t & d, const size_t p=N+1, const bool incpos=true)
    {
        if( p != N+1 )
        {
            base::rangecheck(p);
            position(p);
        }

        d = base::elems[nap];

        if( incpos ) nap += sizeof(d);
        return sizeof(d);
    }

    /// Puts data into the array
    /**
       Puts a uint8_t into the array.
       @param d Data to write into the array
       @param p Position to write data to. If left blank, will write to the current caret position.
       @param incpos Increments the caret position in the array. If set to false the function acts like a poke
       @return The amount of bytes writen from the array
    */
    size_t put(const uint8_t d, const size_t p=N+1, const bool incpos=true)
    {
        if( p != N+1 )
        {
            base::rangecheck(p);
            position(p);
        }

        base::elems[nap] = d;

        if( incpos )
        {
            nap += sizeof(d);
            if( nap > nal )
                nal += sizeof(d);
        }

        return sizeof(d);
    }

    /// Gets data from the array
    /**
       Gets a uint16_t from the array. The data returned is host friendly.
       @param d Data to retrieve
       @param p Position to retrieve data from. If left blank, will retrieve from the  current caret position
       @param incpos Increments the caret position in the array. If set to false the function acts like a peek
       @return The amount of bytes retrieved from the array
    */
    size_t get(uint16_t & d, const size_t p=N+1, const bool incpos=true)
    {
        if( p != N+1 )
        {
            base::rangecheck(p);
            position(p);
        }

        memcpy(&d, &base::elems[nap], sizeof(uint16_t));
        d = ntohs(d);

        if( incpos ) nap += sizeof(d);
        return sizeof(d);
    }

    /// Puts data into the array
    /**
       Puts a uint16_t into the array. The data writen is network friendly.
       @param d Data to write into the array
       @param p Position to write data to. If left blank, will write to the  current caret position.
       @param incpos Increments the caret position in the array. If set to false the function acts like a poke
       @return The amount of bytes writen from the array
    */
    size_t put(const uint16_t d, const size_t p=N+1, const bool incpos=true)
    {
        if( p != N+1 )
        {
            base::rangecheck(p);
            position(p);
        }

        uint16_t v = htons(d);
        memcpy(&base::elems[nap], &v, sizeof(v));

        if( incpos )
        {
            nap += sizeof(d);
            if( nap > nal )
                nal += sizeof(d);
        }

        return sizeof(d);
    }

    /// Gets data from the array
    /**
       Gets a uint32_t from the array. The data is host friendly.
       @param d Data to retrieve
       @param p Position to retrieve data from. If left blank, will retrieve from the current caret position
       @param incpos Increments the caret position in the array. If set to false the function acts like a peek
       @return The amount of bytes retrieved from the array
    */
    size_t get(uint32_t & d, const size_t p=N+1, const bool incpos=true)
    {
        if( p != N+1 )
        {
            base::rangecheck(p);
            position(p);
        }

        memcpy(&d, &base::elems[nap], sizeof(uint32_t));
        d = ntohl(d);

        if( incpos ) nap += sizeof(d);
        return sizeof(d);
    }

    /// Puts data into the array
    /**
       Puts a uint32_t into the array. The data writen is network friendly.
       @param d Data to write into the array
       @param p Position to write data to. If left blank, will write to the current caret position.
       @param incpos Increments the caret position in the array. If set to false the function acts like a poke
       @return The amount of bytes writen from the array
    */
    size_t put(const uint32_t d, const size_t p=N+1, const bool incpos=true)
    {
        if( p != N+1 )
        {
            base::rangecheck(p);
            position(p);
        }

        uint32_t v = htonl(d);
        memcpy(&base::elems[nap], &v, sizeof(v));

        if( incpos )
        {
            nap += sizeof(d);
            if( nap > nal )
                nal += sizeof(d);
        }

        return sizeof(d);
    }

    /// Gets data from the array
    /**
       Gets a uint32_t from the array. The data is host friendly.
       @param d Data to retrieve
       @param p Position to retrieve data from. If left blank, will retrieve from the current caret position
       @param incpos Increments the caret position in the array. If set to false the function acts like a peek
       @return The amount of bytes retrieved from the array
    */
    size_t get(boost::asio::ip::address_v4 & d,
		           const size_t p=N+1,
		           const bool incpos=true)
    {
        if( p != N+1 )
        {
            base::rangecheck(p);
            position(p);
        }

        uint32_t v = 0;
        memcpy(&v, &base::elems[nap], sizeof(uint32_t));
        d = boost::asio::ip::address_v4( ntohl(v) );

        if( incpos ) nap += sizeof(uint32_t);
        return sizeof(d);
    }

    /// Puts data into the array
    /**
       Puts a uint32_t into the array. The data writen is network friendly.
       @param d Data to write into the array
       @param p Position to write data to. If left blank, will write to the current caret position.
       @param incpos Increments the caret position in the array. If set to false the function acts like a poke
       @return The amount of bytes writen from the array
    */
    size_t put(const boost::asio::ip::address_v4 & d,
		           const size_t p=N+1,
		           const bool incpos=true)
    {
        if( p != N+1 )
        {
            base::rangecheck(p);
            position(p);
        }

        uint32_t v = htonl(d.to_ulong());
        memcpy(&base::elems[nap], &v, sizeof(uint32_t));

        if( incpos )
        {
            nap += sizeof(uint32_t);
            if( nap > nal )
                nal += sizeof(uint32_t);
        }

        return sizeof(d);
    }

    /// Gets data from the array
    /**
       Gets a uint32_t from the array. The data is host friendly.
       @param d Data to retrieve
       @param p Position to retrieve data from. If left blank, will retrieve from the current caret position
       @param incpos Increments the caret position in the array. If set to false the function acts like a peek
       @return The amount of bytes retrieved from the array
    */
    size_t get(boost::asio::ip::address_v6 & d,
		           const size_t p=N+1,
		           const bool incpos=true)
    {
        if( p != N+1 )
        {
            base::rangecheck(p);
            position(p);
        }

        boost::asio::ip::address_v6::bytes_type  bytes;
        memcpy( bytes.data(), &base::elems[nap], 16);
        d = boost::asio::ip::address_v6(bytes);
        if( incpos )
        {
            nap += 16;
            if( nap > nal ) nal += 16;
        }
        return 16;
    }

    /// Puts data into the array
    /**
       Puts a uint32_t into the array. The data writen is network friendly.
       @param d Data to write into the array
       @param p Position to write data to. If left blank, will write to the current caret position.
       @param incpos Increments the caret position in the array. If set to false the function acts like a poke
       @return The amount of bytes writen from the array
    */
    size_t put(const boost::asio::ip::address_v6 & d,
		           const size_t p=N+1,
		           const bool incpos=true)
    {
        if( p != N+1 )
        {
            base::rangecheck(p);
            position(p);
        }

        memcpy( &base::elems[nap], d.to_bytes().data(), 16);

        if( incpos )
        {
            nap += sizeof(uint32_t);
            if( nap > nal )
                nal += sizeof(uint32_t);
        }

        return sizeof(d);
    }

    /// Gets data from the array
    /**
       Gets a std::string from the array.
       @param d Data to retrieve
       @param len Amount of chars to read.
       @param p Position to retrieve data from. If left blank, will retrieve from the current caret position
       @param incpos Increments the caret position in the array. If set to false the function acts like a peek
       @return The amount of bytes retrieved from the array
    */
    size_t get(std::string & d, const size_t len, const size_t p=N+1, const bool incpos=true)
    {
        if( p != N+1 )
        {
            base::rangecheck(p);
            position(p);
        }

        boost::scoped_array<char> cPtr( new char[len + 1] );
        strncpy( cPtr.get(), (char*)&base::elems[nap], len);
        cPtr.get()[len] = 0x00;
        d = cPtr.get();

        if( incpos )
        {
            nap += len;
            if( nap > nal )
                nal += len;
        }

        return len;
    }

    /// Puts data into the array
    /**
       Puts a std::string into the array.
       @param d Data to write into the array
       @param len Amount of chars to write
       @param p Position to write data to. If left blank, will write to the current caret position.
       @param incpos Increments the caret position in the array. If set to false the function acts like a poke
       @return The amount of bytes writen from the array
    */
    size_t put(const std::string & d, const size_t len, const size_t p=N+1, const bool incpos=true)
    {
        if( p != N+1 )
        {
            base::rangecheck(p);
            position(p);
        }

        // make sure we can memcpy!
        base::rangecheck(nap + len);
        memcpy( &base::elems[nap], d.c_str(), len );

        if( incpos )
        {
            nap += len;
            if( nap > nal )
                nal += len;
        }

        return len;
    }
};

typedef network_array<576>        dns_buffer_t;
typedef boost::shared_ptr<dns_buffer_t>  shared_dns_buffer_t;


} // namespace net
} // namespace y

#include <boost/asio/detail/pop_options.hpp>
