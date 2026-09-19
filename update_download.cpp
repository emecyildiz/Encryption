#include "update_download.h"
#include <windows.h>
#include <winhttp.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <chrono>
#include <memory>
#include <vector>

namespace kasa::updates {
namespace {
constexpr std::uint64_t maximum = 256ULL * 1024 * 1024;
struct InternetHandle { HINTERNET value; ~InternetHandle() { if(value) WinHttpCloseHandle(value); } };
struct Url { std::wstring host, target; };
std::optional<Url> parse_url(std::wstring_view text) {
    if(text.empty() || text.size()>8192) return std::nullopt;
    for(wchar_t c:text) if(c<=32 || c>=127 || c==L'\\' || c==L'#') return std::nullopt;
    std::wstring value(text);
    URL_COMPONENTS parts{}; parts.dwStructSize=sizeof(parts);
    parts.dwHostNameLength=parts.dwUrlPathLength=parts.dwExtraInfoLength=static_cast<DWORD>(-1);
    parts.dwUserNameLength=parts.dwPasswordLength=static_cast<DWORD>(-1);
    if(!WinHttpCrackUrl(value.c_str(),static_cast<DWORD>(value.size()),0,&parts) ||
        parts.nScheme!=INTERNET_SCHEME_HTTPS || parts.nPort!=443 ||
        parts.dwUserNameLength || parts.dwPasswordLength) return std::nullopt;
    Url result;
    result.host.assign(parts.lpszHostName,parts.dwHostNameLength);
    result.target.assign(parts.lpszUrlPath,parts.dwUrlPathLength);
    if(parts.dwExtraInfoLength) result.target.append(parts.lpszExtraInfo,parts.dwExtraInfoLength);
    return result;
}
bool initial_url(std::wstring_view url) {
    const auto parsed=parse_url(url);
    if(!parsed || parsed->host!=L"github.com") return false;
    constexpr std::wstring_view prefix=L"/emecyildiz/Encryption/releases/download/v";
    if(!parsed->target.starts_with(prefix)) return false;
    const auto remainder=std::wstring_view(parsed->target).substr(prefix.size());
    const auto slash=remainder.find(L'/');
    if(slash==std::wstring_view::npos) return false;
    std::string version(remainder.begin(),remainder.begin()+slash);
    std::string asset(remainder.begin()+slash+1,remainder.end());
    return release_asset_url(version,asset)==url;
}
}
std::wstring release_asset_url(std::string_view version, std::string_view asset) {
    if(!parse_version(version) || version.front()=='v') return {};
    if(asset!="KASA-update.json" && asset!="KASA-update.sig" &&
        asset!="KASA-Setup-"+std::string(version)+".exe") return {};
    const auto url="https://github.com/emecyildiz/Encryption/releases/download/v"+
        std::string(version)+"/"+std::string(asset);
    return {url.begin(),url.end()};
}
bool allowed_asset_redirect(std::wstring_view url) {
    const auto parsed=parse_url(url);
    return parsed && parsed->host==L"release-assets.githubusercontent.com" &&
        parsed->target.starts_with(L"/github-production-release-asset/");
}
DownloadResult fetch_asset_https(std::wstring_view input, std::uint64_t max_bytes,
    const std::atomic<bool>& cancel, const DownloadSink& sink) {
    DownloadResult result;
    auto fail=[&](DownloadError e) { result.error=e; result.system_error=e==DownloadError::Network ? GetLastError():0; return result; };
    if(!initial_url(input) || !max_bytes || max_bytes>maximum || !sink) return fail(DownloadError::InvalidRequest);
    if(cancel) return fail(DownloadError::Cancelled);
    InternetHandle session{WinHttpOpen(L"KASA-AssetDownload/1.0",WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0)};
    if(!session.value || !WinHttpSetTimeouts(session.value,5000,5000,5000,5000)) return fail(DownloadError::Network);
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(120);
    std::wstring url(input);
    try {
        for(unsigned hop=0; hop<4; ++hop) {
            if(cancel) return fail(DownloadError::Cancelled);
            if(std::chrono::steady_clock::now()>deadline) return fail(DownloadError::Timeout);
            const auto parsed=parse_url(url);
            if(!parsed) return fail(DownloadError::RedirectDenied);
            InternetHandle connection{WinHttpConnect(session.value,parsed->host.c_str(),443,0)};
            if(!connection.value) return fail(DownloadError::Network);
            InternetHandle request{WinHttpOpenRequest(connection.value,L"GET",parsed->target.c_str(),nullptr,
                WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE)};
            if(!request.value) return fail(DownloadError::Network);
            DWORD disabled=WINHTTP_DISABLE_REDIRECTS|WINHTTP_DISABLE_COOKIES|WINHTTP_DISABLE_AUTHENTICATION;
            DWORD header_limit=32768;
            if(!WinHttpSetOption(request.value,WINHTTP_OPTION_DISABLE_FEATURE,&disabled,sizeof(disabled)) ||
                !WinHttpSetOption(request.value,WINHTTP_OPTION_MAX_RESPONSE_HEADER_SIZE,&header_limit,sizeof(header_limit)))
                return fail(DownloadError::Network);
            if(!WinHttpSendRequest(request.value,L"Accept: application/octet-stream\r\n",-1L,
                WINHTTP_NO_REQUEST_DATA,0,0,0) || !WinHttpReceiveResponse(request.value,nullptr)) return fail(DownloadError::Network);
            DWORD status=0, bytes=sizeof(status);
            if(!WinHttpQueryHeaders(request.value,WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX,&status,&bytes,WINHTTP_NO_HEADER_INDEX)) return fail(DownloadError::Network);
            result.http_status=status;
            if(status==301 || status==302 || status==303 || status==307 || status==308) {
                bytes=0;
                WinHttpQueryHeaders(request.value,WINHTTP_QUERY_LOCATION,WINHTTP_HEADER_NAME_BY_INDEX,
                    nullptr,&bytes,WINHTTP_NO_HEADER_INDEX);
                if(!bytes || bytes>16384 || bytes%sizeof(wchar_t)) return fail(DownloadError::RedirectDenied);
                std::vector<wchar_t> location(bytes/sizeof(wchar_t)+1,L'\0');
                if(!WinHttpQueryHeaders(request.value,WINHTTP_QUERY_LOCATION,WINHTTP_HEADER_NAME_BY_INDEX,
                    location.data(),&bytes,WINHTTP_NO_HEADER_INDEX)) return fail(DownloadError::Network);
                url.assign(location.data());
                if(!allowed_asset_redirect(url)) return fail(DownloadError::RedirectDenied);
                continue;
            }
            if(status!=200) return fail(DownloadError::HttpStatus);
            std::array<unsigned char,65536> buffer{};
            for(;;) {
                if(cancel) return fail(DownloadError::Cancelled);
                if(std::chrono::steady_clock::now()>deadline) return fail(DownloadError::Timeout);
                DWORD count=0;
                if(!WinHttpReadData(request.value,buffer.data(),static_cast<DWORD>(buffer.size()),&count)) return fail(DownloadError::Network);
                if(!count) return result;
                if(count>max_bytes-result.received) return fail(DownloadError::TooLarge);
                if(!sink(std::span(buffer).first(count))) return fail(DownloadError::SinkFailed);
                result.received+=count;
            }
        }
        return fail(DownloadError::RedirectDenied);
    } catch(...) { return fail(DownloadError::SinkFailed); }
}
DownloadResult download_verified_payload(const VerifiedManifest& manifest,
    const std::atomic<bool>& cancel, const DownloadSink& sink, const DownloadTransport& transport) {
    if(!sink || !transport) return {DownloadError::InvalidRequest};
    if(cancel) return {DownloadError::Cancelled};
    std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)> hash(EVP_MD_CTX_new(),EVP_MD_CTX_free);
    if(!hash || EVP_DigestInit_ex(hash.get(),EVP_sha256(),nullptr)!=1) return {DownloadError::HashMismatch};
    std::uint64_t received=0;
    DownloadError rejection=DownloadError::None;
    const auto consume=[&](std::span<const unsigned char> block) {
        if(rejection!=DownloadError::None) return false;
        if(cancel) { rejection=DownloadError::Cancelled; return false; }
        if(block.size()>manifest.size()-received) { rejection=DownloadError::TooLarge; return false; }
        if(EVP_DigestUpdate(hash.get(),block.data(),block.size())!=1 || !sink(block)) {
            rejection=DownloadError::SinkFailed; return false;
        }
        received+=block.size(); return true;
    };
    DownloadResult result;
    try { result=transport(release_asset_url(manifest.version(),manifest.asset()),manifest.size(),cancel,consume); }
    catch(...) { return {DownloadError::SinkFailed,0,0,received}; }
    result.received=received;
    if(cancel) result.error=DownloadError::Cancelled;
    else if(rejection!=DownloadError::None) result.error=rejection;
    if(!result) return result;
    if(received!=manifest.size()) { result.error=DownloadError::SizeMismatch; return result; }
    std::array<unsigned char,32> digest{}; unsigned int count=0;
    if(EVP_DigestFinal_ex(hash.get(),digest.data(),&count)!=1 || count!=digest.size() ||
        CRYPTO_memcmp(digest.data(),manifest.sha256().data(),digest.size())!=0) result.error=DownloadError::HashMismatch;
    return result;
}
}
