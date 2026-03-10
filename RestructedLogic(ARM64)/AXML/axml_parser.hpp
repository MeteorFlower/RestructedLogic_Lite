#pragma once

struct AppInfo {
  std::string package;
  std::string versionName;
  int versionCode = -1;
  int minSdk = -1;
  int targetSdk = -1;
};

AppInfo parse_manifest(uint8_t *data, size_t size);