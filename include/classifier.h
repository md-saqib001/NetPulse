#pragma once

#include <string>
#include <vector>
#include <utility>

enum class AppType {
    UNKNOWN,
    HTTP_GENERIC,
    HTTPS_GENERIC,
    YOUTUBE,
    INSTAGRAM,
    FACEBOOK,
    TWITTER,
    WHATSAPP,
    GOOGLE,
    GMAIL,
    DRIVE,
    MAPS,
    NETFLIX,
    HOTSTAR,
    AMAZON_PRIME,
    SPOTIFY,
    TELEGRAM,
    DISCORD,
    ZOOM,
    TEAMS,
    GITHUB,
    STACKOVERFLOW,
    LINKEDIN,
    AMAZON,
    FLIPKART,
    SWIGGY,
    ZOMATO,
    DNS_GOOGLE,
    DNS_CLOUDFLARE
};

class Classifier {
public:
    AppType classify(const std::string& sni) const;
    std::string appName(AppType type) const;
    std::string category(AppType type) const;

private:
    static const std::vector<std::pair<std::string, AppType>> PATTERNS;
};
