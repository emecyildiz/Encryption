#pragma once
#include <openssl/crypto.h>
#include <string>

// Construct in its final allocation and transfer only unique_ptr ownership.
// In particular, do not move short-string inline storage between closures.
class OperationPassword final {
public:
    explicit OperationPassword(const char* text) : value_(text) {}
    OperationPassword(const OperationPassword&) = delete;
    OperationPassword& operator=(const OperationPassword&) = delete;
    OperationPassword(OperationPassword&&) = delete;
    OperationPassword& operator=(OperationPassword&&) = delete;
    ~OperationPassword() { clear(); }
    const std::string& value() const noexcept { return value_; }
    void clear() noexcept {
        if (!value_.empty()) OPENSSL_cleanse(value_.data(), value_.size());
        value_.clear();
    }
private:
    std::string value_;
};
