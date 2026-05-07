#include "threat_intel/hash_checker.h"
#include "threat_intel/sha256.h"
#include <fstream>
#include <algorithm>
#include <cctype>

HashChecker::HashChecker(const std::string &hash_db_path)
{
    if (!hash_db_path.empty())
        load(hash_db_path);
}

bool HashChecker::load(const std::string &path)
{
    std::ifstream f(path);
    if (!f.is_open()) return false;

    std::unordered_set<std::string> tmp;
    std::string line;
    while (std::getline(f, line)) {
        /* 앞뒤 공백 제거 */
        size_t a = line.find_first_not_of(" \t\r");
        if (a == std::string::npos) continue;
        size_t b = line.find_last_not_of(" \t\r");
        std::string h = line.substr(a, b - a + 1);

        if (h.empty() || h[0] == '#') continue;
        if (h.size() != 64) continue;

        /* 소문자 정규화 */
        std::transform(h.begin(), h.end(), h.begin(),
                       [](unsigned char c){ return std::tolower(c); });

        /* 16진수 문자만 포함하는지 검증 */
        bool valid = true;
        for (char c : h) {
            if (!std::isxdigit((unsigned char)c)) { valid = false; break; }
        }
        if (valid) tmp.insert(std::move(h));
    }

    m_hashes = std::move(tmp);
    return true;
}

bool HashChecker::check_file(const char *path) const
{
    if (!path || !*path || m_hashes.empty()) return false;
    std::string hex = sha256::hash_file(path);
    if (hex.empty()) return false;
    return m_hashes.count(hex) > 0;
}

bool HashChecker::check_hash(const std::string &hex) const
{
    if (hex.size() != 64 || m_hashes.empty()) return false;
    std::string lo = hex;
    std::transform(lo.begin(), lo.end(), lo.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    return m_hashes.count(lo) > 0;
}
