#include "classifier.h"
#include <algorithm>
#include <cctype>

const std::vector<std::pair<std::string, AppType>> Classifier::PATTERNS = {
    {"googlevideo",        AppType::YOUTUBE},
    {"youtube",            AppType::YOUTUBE},
    {"ytimg",              AppType::YOUTUBE},
    {"yt3.ggpht",          AppType::YOUTUBE},
    {"cdninstagram",       AppType::INSTAGRAM},
    {"instagram",          AppType::INSTAGRAM},
    {"fbcdn",              AppType::FACEBOOK},
    {"facebook",           AppType::FACEBOOK},
    {"whatsapp",           AppType::WHATSAPP},
    {"twimg",              AppType::TWITTER},
    {"twitter",            AppType::TWITTER},
    {"x.com",              AppType::TWITTER},
    {"nflxvideo",          AppType::NETFLIX},
    {"netflix",            AppType::NETFLIX},
    {"hotstar",            AppType::HOTSTAR},
    {"primevideo",         AppType::AMAZON_PRIME},
    {"spotify",            AppType::SPOTIFY},
    {"scdn.co",            AppType::SPOTIFY},
    {"telegram",           AppType::TELEGRAM},
    {"discord",            AppType::DISCORD},
    {"zoom.us",            AppType::ZOOM},
    {"teams.microsoft",    AppType::TEAMS},
    {"github",             AppType::GITHUB},
    {"githubusercontent",  AppType::GITHUB},
    {"stackoverflow",      AppType::STACKOVERFLOW},
    {"linkedin",           AppType::LINKEDIN},
    {"swiggy",             AppType::SWIGGY},
    {"zomato",             AppType::ZOMATO},
    {"flipkart",           AppType::FLIPKART},
    {"amazon",             AppType::AMAZON},
    {"googleapis",         AppType::GOOGLE},
    {"gmail",              AppType::GMAIL},
    {"drive.google",       AppType::DRIVE},
    {"maps.google",        AppType::MAPS},
    {"8.8.8.8",            AppType::DNS_GOOGLE},
    {"1.1.1.1",            AppType::DNS_CLOUDFLARE},
    {"google",             AppType::GOOGLE},
    {"codechef",           AppType::CODECHEF},
    {"codeforces",         AppType::CODEFORCES},
    {"leetcode",           AppType::LEETCODE},
    {"atcoder",            AppType::ATCODER},
    {"snapchat",           AppType::SNAPCHAT},
    {"sc-cdn",             AppType::SNAPCHAT},
    {"brave",              AppType::BRAVE},
    {"microsoft",          AppType::MICROSOFT},
    {"sonyliv",            AppType::SONYLIV},
    {"anthropic",          AppType::ANTHROPIC},
    {"chatgpt",            AppType::CHATGPT},
    {"openai",             AppType::CHATGPT},
    {"gemini",             AppType::GEMINI}
};

AppType Classifier::classify(const std::string& sni) const {
    if (sni.empty()) {
        return AppType::UNKNOWN;
    }
    std::string lower_sni = sni;
    std::transform(lower_sni.begin(), lower_sni.end(), lower_sni.begin(), [](unsigned char c) {
        return std::tolower(c);
    });

    for (const auto& [pattern, type] : PATTERNS) {
        if (lower_sni.find(pattern) != std::string::npos) {
            return type;
        }
    }
    return AppType::UNKNOWN;
}

std::string Classifier::appName(AppType type) const {
    switch (type) {
        case AppType::UNKNOWN:         return "Unknown";
        case AppType::HTTP_GENERIC:    return "HTTP Generic";
        case AppType::HTTPS_GENERIC:   return "HTTPS Generic";
        case AppType::YOUTUBE:         return "YouTube";
        case AppType::INSTAGRAM:       return "Instagram";
        case AppType::FACEBOOK:        return "Facebook";
        case AppType::TWITTER:         return "Twitter";
        case AppType::WHATSAPP:        return "WhatsApp";
        case AppType::GOOGLE:          return "Google";
        case AppType::GMAIL:           return "Gmail";
        case AppType::DRIVE:           return "Google Drive";
        case AppType::MAPS:            return "Google Maps";
        case AppType::NETFLIX:         return "Netflix";
        case AppType::HOTSTAR:         return "Hotstar";
        case AppType::AMAZON_PRIME:    return "Amazon Prime Video";
        case AppType::SPOTIFY:         return "Spotify";
        case AppType::TELEGRAM:        return "Telegram";
        case AppType::DISCORD:         return "Discord";
        case AppType::ZOOM:            return "Zoom";
        case AppType::TEAMS:           return "Microsoft Teams";
        case AppType::GITHUB:          return "GitHub";
        case AppType::STACKOVERFLOW:   return "StackOverflow";
        case AppType::LINKEDIN:        return "LinkedIn";
        case AppType::AMAZON:          return "Amazon";
        case AppType::FLIPKART:        return "Flipkart";
        case AppType::SWIGGY:          return "Swiggy";
        case AppType::ZOMATO:          return "Zomato";
        case AppType::DNS_GOOGLE:      return "Google DNS";
        case AppType::DNS_CLOUDFLARE:  return "Cloudflare DNS";
        case AppType::CODECHEF:        return "CodeChef";
        case AppType::CODEFORCES:      return "Codeforces";
        case AppType::LEETCODE:        return "LeetCode";
        case AppType::ATCODER:         return "AtCoder";
        case AppType::SNAPCHAT:        return "Snapchat";
        case AppType::BRAVE:           return "Brave Browser";
        case AppType::MICROSOFT:       return "Microsoft";
        case AppType::SONYLIV:         return "SonyLIV";
        case AppType::ANTHROPIC:       return "Anthropic";
        case AppType::CHATGPT:         return "ChatGPT";
        case AppType::GEMINI:          return "Gemini";
    }
    return "Unknown";
}

std::string Classifier::category(AppType type) const {
    switch (type) {
        case AppType::YOUTUBE:
        case AppType::NETFLIX:
        case AppType::HOTSTAR:
        case AppType::AMAZON_PRIME:
        case AppType::SPOTIFY:
        case AppType::SONYLIV:
            return "Streaming";
        case AppType::INSTAGRAM:
        case AppType::FACEBOOK:
        case AppType::TWITTER:
        case AppType::LINKEDIN:
        case AppType::SNAPCHAT:
            return "Social Media";
        case AppType::WHATSAPP:
        case AppType::TELEGRAM:
        case AppType::DISCORD:
        case AppType::ZOOM:
        case AppType::TEAMS:
            return "Communication";
        case AppType::GITHUB:
        case AppType::STACKOVERFLOW:
            return "Development";
        case AppType::AMAZON:
        case AppType::FLIPKART:
        case AppType::SWIGGY:
        case AppType::ZOMATO:
            return "Shopping";
        case AppType::GOOGLE:
        case AppType::GMAIL:
        case AppType::DRIVE:
        case AppType::MAPS:
        case AppType::BRAVE:
        case AppType::MICROSOFT:
        case AppType::ANTHROPIC:
        case AppType::CHATGPT:
        case AppType::GEMINI:
        case AppType::CODECHEF:
        case AppType::CODEFORCES:
        case AppType::LEETCODE:
        case AppType::ATCODER:
            return "Productivity";
        default:
            return "Unknown";
    }
}
