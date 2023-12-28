#pragma once

#include <mw/exceptions/PRCXException.h>
#include <mw/util/StringUtil.h>

#define ThrowCrypto(msg) throw CryptoException(msg, __FUNCTION__)
#define ThrowCrypto_F(msg, ...) throw CryptoException(StringUtil::Format(msg, __VA_ARGS__), __FUNCTION__)

class CryptoException : public PRCXException
{
public:
    CryptoException(const std::string& message, const std::string& function)
        : PRCXException("CryptoException", message, function)
    {

    }
};