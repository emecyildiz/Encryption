#include "update_metadata.h"
#include <iostream>
int main() {
    using namespace kasa::updates;
    int checks = 0, failures = 0;
    const auto check = [&](bool value) { ++checks; if (!value) ++failures; };
    const std::string releases = R"([{"tag_name":"v1.2.0-test.2","draft":false,"prerelease":true},{"tag_name":"v1.1.1","draft":false,"prerelease":false},{"tag_name":"v9.0.0","draft":true,"prerelease":false},{"tag_name":"v1.2.0-test.10","draft":false,"prerelease":true}])";
    check(parse_releases(releases,"1.1.0",Channel::Stable).version == "v1.1.1");
    check(parse_releases(releases,"1.1.0",Channel::Test).version == "v1.2.0-test.10");
    check(parse_releases(releases,"2.0.0",Channel::Test).version.empty());
    check(parse_releases("[]","1.0.0",Channel::Stable).ok);
    check(!parse_releases("[]","1.0.0",static_cast<Channel>(99)).ok);
    check(!parse_releases("{}","1.0.0",Channel::Stable).ok);
    check(!parse_releases("broken","1.0.0",Channel::Stable).ok);
    check(!parse_releases("[null]","1.0.0",Channel::Stable).ok);
    check(!parse_releases("[]","invalid",Channel::Stable).ok);
    check(!parse_releases(std::string(1024*1024+1,' '),"1.0.0",Channel::Stable).ok);
    check(!parse_releases(std::string(30,'[')+std::string(30,']'),"1.0.0",Channel::Stable).ok);
    check(!parse_releases(R"([{"tag_name":"v2.0.0","draft":"false","prerelease":false}])","1.0.0",Channel::Stable).ok);
    check(parse_releases(R"([{"tag_name":"v2.0.0-test.1","draft":false,"prerelease":false}])","1.0.0",Channel::Test).version.empty());
    check(parse_releases(R"([{"tag_name":"v1.0.0","draft":false,"prerelease":false}])","1.0.0",Channel::Stable).version.empty());
    check(parse_releases(R"([{"tag_name":"v1.0.0","draft":false,"prerelease":false}])","1.0.0-test.1",Channel::Test).version == "v1.0.0");
    check(parse_releases(R"([{"tag_name":"<script>","draft":false,"prerelease":false}])","1.0.0",Channel::Test).version.empty());
    std::cout << checks << " checks, " << failures << " failures\n";
    return failures != 0;
}
