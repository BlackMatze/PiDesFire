#pragma once

#include <map>
#include <string>

struct AppConfig
{
    std::string siteName;
    std::string appAid;
    std::string cardIdFormat;
    std::string nfcDevice;
    std::string haUrl;
    std::string haToken;
    std::string haTagEntityPrefix;
    std::string haTagScannerDeviceId;
    std::string siteKeyHex;
};

class ConfigLoader
{
  public:
    static AppConfig loadFromFile(const std::string& path);

  private:
    static std::map<std::string, std::string> parseSimpleYaml(const std::string& path);
};