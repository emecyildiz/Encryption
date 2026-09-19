// Publisher utility: never ship this executable or private key with KASA.
#include "update_publisher.h"
#include <windows.h>
#include <wincrypt.h>
#include <sddl.h>
#include <shlobj.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>
#include <chrono>
#include <memory>
#include <stdexcept>
namespace fs=std::filesystem;
using Key=std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)>;
struct Handle{HANDLE h=INVALID_HANDLE_VALUE;explicit Handle(HANDLE v):h(v){}~Handle(){if(h!=INVALID_HANDLE_VALUE)CloseHandle(h);}operator bool()const{return h!=INVALID_HANDLE_VALUE;}};
struct Local{void* p=nullptr;~Local(){if(p)LocalFree(p);}};
struct Secret{std::array<unsigned char,32> bytes{};~Secret(){OPENSSL_cleanse(bytes.data(),bytes.size());}};
struct Security{
    Local descriptor;SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES),nullptr,FALSE};
    Security(){HANDLE t=nullptr;if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&t))throw std::runtime_error("Token unavailable");Handle token(t);
        DWORD n=0;GetTokenInformation(t,TokenUser,nullptr,0,&n);std::vector<unsigned char>b(n);
        if(!n || !GetTokenInformation(t,TokenUser,b.data(),n,&n))throw std::runtime_error("Token unavailable");
        LPWSTR raw=nullptr;if(!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(b.data())->User.Sid,&raw))throw std::runtime_error("SID unavailable");Local sid;sid.p=raw;
        const auto acl=L"D:P(A;OICI;FA;;;"+std::wstring(raw)+L")(A;OICI;FA;;;SY)";
        if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(acl.c_str(),SDDL_REVISION_1,reinterpret_cast<PSECURITY_DESCRIPTOR*>(&descriptor.p),nullptr))throw std::runtime_error("ACL unavailable");attributes.lpSecurityDescriptor=descriptor.p;
    }
};
fs::path key_path(){PWSTR p=nullptr;if(FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData,KF_FLAG_DEFAULT,nullptr,&p)))throw std::runtime_error("LocalAppData unavailable");fs::path base(p);CoTaskMemFree(p);
    Security security;const auto dir=base/L"Emecworks-Publisher";
    if(!CreateDirectoryW(dir.c_str(),&security.attributes) && GetLastError()!=ERROR_ALREADY_EXISTS)throw std::runtime_error("Cannot create private publisher directory");
    const auto attr=GetFileAttributesW(dir.c_str());if(attr==INVALID_FILE_ATTRIBUTES || !(attr&FILE_ATTRIBUTE_DIRECTORY) || (attr&FILE_ATTRIBUTE_REPARSE_POINT))throw std::runtime_error("Unsafe publisher directory");
    return dir/L"KASA-ed25519.dpapi";
}
void write_new(const fs::path& p,const void* data,std::size_t size){Security security;Handle h(CreateFileW(p.c_str(),GENERIC_WRITE,0,&security.attributes,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr));
    if(!h)throw std::runtime_error("Output exists or cannot be created");DWORD written=0;
    if(size>MAXDWORD || !WriteFile(h.h,data,static_cast<DWORD>(size),&written,nullptr) || written!=size || !FlushFileBuffers(h.h))throw std::runtime_error("Output write failed; inspect incomplete output");
}
Key load_key(const fs::path& path){Handle h(CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    BY_HANDLE_FILE_INFORMATION info{};LARGE_INTEGER size{};
    if(!h || !GetFileInformationByHandle(h.h,&info) || (info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)) ||
        !GetFileSizeEx(h.h,&size) || size.QuadPart<=0 || size.QuadPart>16384)throw std::runtime_error("Publisher key unavailable");
    std::vector<unsigned char>b(static_cast<std::size_t>(size.QuadPart));DWORD n=0;if(!ReadFile(h.h,b.data(),static_cast<DWORD>(b.size()),&n,nullptr)||n!=b.size())throw std::runtime_error("Key read failed");
    DATA_BLOB in{n,b.data()},out{};
    if(!CryptUnprotectData(&in,nullptr,nullptr,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&out))throw std::runtime_error("Cannot unlock key for this Windows account");
    Local memory;memory.p=out.pbData;Key key(nullptr,EVP_PKEY_free);
    if(out.cbData==32)key.reset(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519,nullptr,out.pbData,out.cbData));
    OPENSSL_cleanse(out.pbData,out.cbData);if(!key)throw std::runtime_error("Invalid protected key");return key;
}
void print_public(EVP_PKEY* key){std::array<unsigned char,32>b{};std::size_t n=b.size();if(EVP_PKEY_get_raw_public_key(key,b.data(),&n)!=1 || n!=32)throw std::runtime_error("No public key");
    constexpr char hex[]="0123456789abcdef";for(auto c:b)std::cout<<hex[c>>4]<<hex[c&15];std::cout<<'\n';}
int wmain(int argc,wchar_t** argv){try{
    if(argc<2){std::cerr<<"Publisher only: init | public | sign VERSION INSTALLER OUTPUT_DIRECTORY | export ENCRYPTED_PEM | import ENCRYPTED_PEM\n";return 2;}
    const std::wstring command=argv[1];
    if(command!=L"init" && command!=L"public" && command!=L"sign" && command!=L"export" && command!=L"import")throw std::runtime_error("Unknown command");
    const auto path=key_path();
    if(command==L"init"){
        if(argc!=2)throw std::runtime_error("Unexpected arguments");Key key(EVP_PKEY_Q_keygen(nullptr,nullptr,"ED25519"),EVP_PKEY_free);Secret secret;std::size_t n=32;
        if(!key || EVP_PKEY_get_raw_private_key(key.get(),secret.bytes.data(),&n)!=1 || n!=32)throw std::runtime_error("Key generation failed");
        DATA_BLOB input{32,secret.bytes.data()},output{};if(!CryptProtectData(&input,L"KASA publisher Ed25519",nullptr,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&output))throw std::runtime_error("Key protection failed");
        Local memory;memory.p=output.pbData;write_new(path,output.pbData,output.cbData);print_public(key.get());return 0;
    }
    if(command==L"import"){
        if(argc!=3 || fs::exists(path))throw std::runtime_error("Import requires a backup and an empty publisher key slot");
        std::ifstream source(fs::path(argv[2]),std::ios::binary);std::string pem;
        char block[4096];while(source){source.read(block,sizeof(block));pem.append(block,static_cast<std::size_t>(source.gcount()));if(pem.size()>16384)throw std::runtime_error("Backup too large");}
        if(!source.eof() || source.bad() || !pem.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----"))throw std::runtime_error("Encrypted PKCS8 backup required");
        std::unique_ptr<BIO,decltype(&BIO_free)> bio(BIO_new_mem_buf(pem.data(),static_cast<int>(pem.size())),BIO_free);
        Key recovered(PEM_read_bio_PrivateKey(bio.get(),nullptr,nullptr,nullptr),EVP_PKEY_free);Secret raw;std::size_t n=32;
        if(!recovered || EVP_PKEY_is_a(recovered.get(),"ED25519")!=1 || EVP_PKEY_get_raw_private_key(recovered.get(),raw.bytes.data(),&n)!=1 || n!=32)throw std::runtime_error("Backup unlock failed");
        DATA_BLOB in{32,raw.bytes.data()},out{};if(!CryptProtectData(&in,L"KASA publisher Ed25519",nullptr,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&out))throw std::runtime_error("Protection failed");
        Local mem;mem.p=out.pbData;write_new(path,out.pbData,out.cbData);print_public(recovered.get());return 0;
    }
    auto key=load_key(path);
    if(command==L"public"){if(argc!=2)throw std::runtime_error("Unexpected arguments");print_public(key.get());return 0;}
    if(command==L"export"){
        if(argc!=3)throw std::runtime_error("Encrypted PEM destination required");
        std::unique_ptr<BIO,decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()),BIO_free);
        // OpenSSL prompts twice with echo disabled. Never accept a password in argv/logs.
        if(!bio || PEM_write_bio_PKCS8PrivateKey(bio.get(),key.get(),EVP_aes_256_cbc(),nullptr,0,nullptr,nullptr)!=1)throw std::runtime_error("Encrypted export cancelled or failed");
        char* bytes=nullptr;const long length=BIO_get_mem_data(bio.get(),&bytes);if(length<=0)throw std::runtime_error("Export failed");
        write_new(fs::path(argv[2]),bytes,static_cast<std::size_t>(length));std::cout<<"Encrypted backup exported. Store it separately; retain its passphrase.\n";return 0;
    }
    if(argc!=5)throw std::runtime_error("sign requires VERSION INSTALLER OUTPUT_DIRECTORY");
    const std::wstring wide=argv[2];std::string version;for(wchar_t c:wide){if(c>127)throw std::runtime_error("ASCII version required");version+=static_cast<char>(c);}
    const fs::path installer=argv[3],out=argv[4];if(installer.filename()!=fs::path("KASA-Setup-"+version+".exe"))throw std::runtime_error("Installer name does not match version");
    Handle locked(CreateFileW(installer.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));BY_HANDLE_FILE_INFORMATION info{};
    if(!locked || !GetFileInformationByHandle(locked.h,&info) || info.nNumberOfLinks!=1 || (info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)))throw std::runtime_error("Installer cannot be locked");
    if(fs::exists(out/L"KASA-update.json")||fs::exists(out/L"KASA-update.sig"))throw std::runtime_error("Metadata output already exists; use a new directory");
    std::ifstream input(installer,std::ios::binary);
    const auto now=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    const auto result=kasa::updates::sign_release(key.get(),input,version,now,30ULL*86400);
    write_new(out/L"KASA-update.json",result.descriptor.data(),result.descriptor.size());
    write_new(out/L"KASA-update.sig",result.signature.data(),result.signature.size());
    std::cout<<"Signed metadata created. Verify BOTH files before publishing. Expires in 30 days.\n";return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
