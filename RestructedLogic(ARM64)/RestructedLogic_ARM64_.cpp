#include "memUtils.hpp"
#include "Unzip/ApkUnzipper.hpp"
#include "Unzip/HashComparer.hpp"
#include "AXML/axml_parser.hpp"
#include "Decrypt/picosha2.hpp"
#include "Decrypt/aes.hpp"
#include "SexyTypes.hpp"
#include "RestructedLogic_ARM64_.hpp"
#include "VersionSwitcher.hpp"

using _DWORD = uint32_t;
using __int64 = int64_t;
using _BYTE = uint8_t;

namespace DirectInstallOBB {
// RSB迁移是否开始判定
std::atomic<bool> thread_applied(false);
// 源安装包路径
std::string apk_path;
// 数据包版本
int app_version;
// OBB名称
std::string ori_rsb_name;
// OBB专属文件夹路径
std::string rsb_path_str;
// OBB路径
std::string rsb_self_path_str;
// AndroidManifest.xml信息
std::vector<uint8_t> manifest;
// 应用信息
AppInfo info;
// 安装包内数据包哈希值
uint64_t apkOBBHash;
// 数据包哈希值
uint64_t OBBHash;

// 获取游戏包名
std::string get_package_name() {
  std::ifstream cmdline("/proc/self/cmdline");
  std::string package_name;
  std::getline(cmdline, package_name, '\0');  // cmdline以\0结尾
  return package_name;
}

// 获取so所在文件夹
std::string get_so_parent_dir() {
  std::ifstream maps("/proc/self/maps");
  std::string line;
  while (std::getline(maps, line)) {
    if (line.find("libRestructedLogic.so") != std::string::npos) {
      size_t path_start = line.find_last_of(' ') + 1;
      std::string full_path = line.substr(path_start);
      // 去掉末尾换行符并返回父目录
      return std::filesystem::path(full_path).parent_path().string();
    }
  }
  return "";
}

// 获取base.apk路径
std::string find_apk_path() {
  return (std::filesystem::path(get_so_parent_dir()).parent_path().parent_path()).string() +
         "/base.apk";
}

// 读取AndroidManifest.axml
std::vector<uint8_t> read_manifest(const std::string &apk) {
  std::vector<uint8_t> result;
  ApkUnzipper::extract_to_memory(apk, "AndroidManifest.xml", result);
  return result;
}

AppInfo get_app_info() {
  apk_path = find_apk_path();
  LOGI("APK LOACTION:%s", apk_path.c_str());
  manifest = read_manifest(apk_path);
  return parse_manifest(manifest.data(), manifest.size());
}

int get_apk_versioncode() {
  info = get_app_info();
  LOGI("package=%s", info.package.c_str());
  LOGI("versionName=%s", info.versionName.c_str());
  LOGI("versionCode=%d", info.versionCode);
  LOGI("minSdk=%d", info.minSdk);
  LOGI("targetSdk=%d", info.targetSdk);
  return info.versionCode;
}

void get_apk_information() {
  app_version = get_apk_versioncode();
  ori_rsb_name = "main." + std::to_string(app_version) + "." + get_package_name() + ".obb";
  rsb_path_str = "/storage/emulated/0/Android/obb/" + get_package_name();
  rsb_self_path_str = rsb_path_str + "/" + ori_rsb_name;
  LOGI("ori_rsb_name = %s,rsb_path_str = %s,rsb_self_path_str = %s", ori_rsb_name.c_str(),
       rsb_path_str.c_str(), rsb_self_path_str.c_str());
}

// OBB文件夹是否存在
bool OBBPathExisted() {
  if (apk_path.empty())
    get_apk_information();
  std::filesystem::path rsb_real_path = std::filesystem::path(rsb_path_str);
  return std::filesystem::exists(rsb_real_path);
}

// OBB是否存在
bool OBBExisted() {
  if (apk_path.empty())
    get_apk_information();
  std::filesystem::path rsb_self_path = std::filesystem::path(rsb_self_path_str);
  return std::filesystem::exists(rsb_self_path);
}

// 验证头部四字节
//  检查文件头是否为特定的四个字符
bool check_magic_number(const char *path, const char *magic) {
  FILE *fp = fopen(path, "rb");
  if (!fp)
    return false;
  char buffer[4];
  size_t count = fread(buffer, 1, 4, fp);
  fclose(fp);
  if (count != 4)
    return false;
  // 对比前 4 字节
  return memcmp(buffer, magic, 4) == 0;
}

// 验证文件是否一致

bool OBBHashEquals() {
  LOGI("Hash Start");
  if (apk_path.empty())
    get_apk_information();
  size_t apkObbSize = ApkUnzipper::get_apk_asset_size(apk_path, "assets/" + ori_rsb_name);
  if (apkObbSize == 0) {
    LOGI("哈希校验：非直装包");
    return true;
  }

  LOGI("Calculating Hash");
  if (check_magic_number(rsb_self_path_str.c_str(), "EBRL")) {
    LOGI("检测到EBRL，读取后续哈希值");
    OBBHash = HashComparer::read_hash_after_header(rsb_self_path_str.c_str());
  } else {
    // 如果大小不一，直接就是不一样
    if (apkObbSize != std::filesystem::file_size(std::filesystem::path(rsb_self_path_str))) {
      LOGI("文件大小不一，必然不同");
      return false;
    }
    OBBHash = HashComparer::compute_file_hash(std::filesystem::path(rsb_self_path_str));
  }

  apkOBBHash = HashComparer::get_asset_hash(apk_path, "assets/" + ori_rsb_name);
  bool result = HashComparer::are_hashes_identical(apkOBBHash, OBBHash);
  LOGI("Hash End");
  return result;
}

#undef USE_HASH_CHECK

// Assets版直装转移
bool AssetsRSBDirectInstall() {
  if (apk_path.empty())
    get_apk_information();
  // 提取并放置OBB
  if (ApkUnzipper::extract_asset(apk_path, "assets/" + ori_rsb_name, rsb_self_path_str)) {
    // 权限修复
    std::filesystem::permissions(
        rsb_self_path_str, std::filesystem::perms::owner_all | std::filesystem::perms::group_read);
    return 1;
  } else {
    LOGI("不是直装包");
    return 0;
  }
}

// 线程监控OBB路径是否存在
void obb_path_monitor() {
  while (true) {
    if (apk_path.empty())
      get_apk_information();
    if (OBBPathExisted()) {
      thread_applied = true;
      LOGI("RSBDirectInstall Start.");
      AssetsRSBDirectInstall();
      LOGI("RSBDirectInstall End.");
      if (OBBExisted() || OBBHashEquals()) {
        // 成功迁移
        thread_applied = false;
      }
      return;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
  }
}

// 让主程序延迟防止数据包迁移期间被读取
void delay_PvZ2() {
  while (thread_applied) {
    LOGI("RSB first loaded, sleeping......");
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
  }
}

inline void process() {
  // 必须留，获取包名和版本号信息
  if (apk_path.empty())
    get_apk_information();
  // 直装包：数据包不存在或者哈希校验不通过则轮询路径是否存在
  if (!OBBExisted() || !OBBHashEquals())
    std::thread(obb_path_monitor).detach();
}
}  // namespace DirectInstallOBB

namespace LogOutput {
typedef int (*LogOutputFunc)(char *, ...);
LogOutputFunc oLogOutputFunc = nullptr;
std::mutex g_logMutex;

int hkLogOutputFunc(char *format, ...) {
  va_list va;
  va_start(va, format);

  std::lock_guard<std::mutex> lock(g_logMutex);
  LOGI("LogOutputFunc: ");
  LOGI(format, va);

  int result = oLogOutputFunc(format, va);
  va_end(va);
  return result;
}

void process() {
  // 输出主日志
  if constexpr (LogOutputFuncAddr != UNKNOWN)
    PVZ2HookFunction(LogOutputFuncAddr, (void *)hkLogOutputFunc, (void **)&oLogOutputFunc,
                     "LogOutputFunc");
}
}  // namespace LogOutput

namespace MaxZoom {

constexpr int TEXTURE_WIDTH = 2048, TEXTURE_LEFT_WIDTH = 556, TEXTURE_RIGHT_WIDTH = 1345;
constexpr int stageRightLine = TEXTURE_WIDTH + TEXTURE_RIGHT_WIDTH;

// 选卡界面与正式游戏视野右边缘（相对于棋盘左侧边缘的距离）
int gameStartRightLine, preGameRightLine;

// 设备分辨率
#ifdef _DEBUG
int mOrigScreenWidth;
#endif
int mOrigScreenHeight;

// 游戏分辨率
int mWidth;
#ifdef _DEBUG
int mHeight;
#endif

// LawnAppScreenWidthHeight 的原函数会随版本变化。目前只知道 8.7.3 的写法。其他版本欢迎补充。
#if GAME_VERSION == 873

typedef __int64 (*LawnAppScreenWidthHeight)(__int64 a1, int a2);
LawnAppScreenWidthHeight oLawnAppScreenWidthHeight = nullptr;

__int64 hkLawnAppScreenWidthHeight(__int64 a1, int a2) {
  // 1. 先执行原函数，让内部逻辑完成内存写入
  __int64 result = oLawnAppScreenWidthHeight(a1, a2);

  if (a1 == NULL)
    return result;

  // 2. 根据偏移直接提取数据
#ifdef _DEBUG
  mOrigScreenWidth = *(unsigned int *)(a1 + 1860);
#endif
  mOrigScreenHeight = *(unsigned int *)(a1 + 1864);

  mWidth = *(unsigned int *)(a1 + 244);
#ifdef _DEBUG
  mHeight = *(unsigned int *)(a1 + 248);
#endif

  // 3. 输出日志
  LOGI(R"(
--- LawnApp::SetWidthHeight Hook ---
mOrigWidth: %d, mOrigHeight: %d
mWidth: %d, mHeight: %d
result: %lld)",
       mOrigScreenWidth, mOrigScreenHeight, mWidth, mHeight, result);

  // 若游戏分辨率宽度大于棋盘和左侧的总宽度（足以让左侧全部显示），则使偏移与左侧宽度相同
  // 否则使偏移等于游戏分辨率宽度减去棋盘宽度（即让右侧边缘与屏幕右侧对齐）
  gameStartRightLine = (mWidth >= TEXTURE_WIDTH + TEXTURE_LEFT_WIDTH)
                           ? (mWidth - TEXTURE_LEFT_WIDTH)
                           : TEXTURE_WIDTH;
  gameStartRightLine = std::min(gameStartRightLine, stageRightLine);
  preGameRightLine = (gameStartRightLine + stageRightLine) / 2;
  preGameRightLine = std::min(preGameRightLine, stageRightLine);

  return result;
}

#endif

typedef __int64 (*OrigBoardZoom)(__int64 a1);
OrigBoardZoom oBoardZoom = nullptr;

__int64 hkBoardZoom(__int64 a1) {
  // 先跑原函数
  __int64 result = oBoardZoom(a1);
  // 改变选卡时视野左边缘与棋盘左边缘的距离
  *(_DWORD *)(a1 + 1140) = preGameRightLine - mWidth;
  // 高度无法调整，只能靠缩放
  return result;
}

typedef void (*OrigBoardZoom2)(__int64 a1);
OrigBoardZoom2 oBoardZoom2 = nullptr;

void hkBoardZoom2(__int64 a1) {
  oBoardZoom2(a1);
  // 缩放系数
  *(float *)(a1 + 1120) = 1.0f;
  // 改变视野左边缘与棋盘左边缘的距离
  *(_DWORD *)(a1 + 1080) = -(gameStartRightLine - mWidth);
  // 顶部基准线
  *(_DWORD *)(a1 + 1128) = (_DWORD)mOrigScreenHeight;
}

inline void process() {
  // 得到缩放前后尺寸
  if constexpr (LawnAppScreenWidthHeightAddr != UNKNOWN)
    PVZ2HookFunction(LawnAppScreenWidthHeightAddr, (void *)hkLawnAppScreenWidthHeight,
                     (void **)&oLawnAppScreenWidthHeight, "LawnApp::SetScreenWidthHeight");
  // 控制屏幕缩放
  if constexpr (BoardZoomAddr != UNKNOWN)
    PVZ2HookFunction(BoardZoomAddr, (void *)hkBoardZoom, (void **)&oBoardZoom, "BoardZoom");
  if constexpr (BoardZoom2Addr != UNKNOWN)
    PVZ2HookFunction(BoardZoom2Addr, (void *)hkBoardZoom2, (void **)&oBoardZoom2, "BoardZoom2");
}
}  // namespace MaxZoom

namespace HookResourceManagerFunc {

#define USE_DIRECT_INSTALL_OBB
// #define USE_RSB_DECRYPT

#ifdef USE_RSB_DECRYPT

// 检测是否ROOT
bool isRooted() {
  // 检查常见的 Root 路径和文件
  const char *paths[] = {"/system/app/Superuser.apk", "/sbin/su", "/system/bin/su",
                         "/system/xbin/su"};
  for (auto path : paths) {
    if (access(path, F_OK) == 0)
      return true;
  }
  return false;
}

#endif

// 直装包卡主进程以及 ROOT 检测
typedef void (*ResourceManagerFunc)(__int64 a1, char a2, int a3);
ResourceManagerFunc oResourceManagerFunc = nullptr;

void hkResourceManagerFunc(__int64 a1, char a2, int a3) {
  LOGI("Hooking ResourcesManagerFunc");

#ifdef USE_DIRECT_INSTALL_OBB
  DirectInstallOBB::delay_PvZ2();
#endif

  oResourceManagerFunc(a1, a2, a3);

#ifdef USE_RSB_DECRYPT
  // 如果检测到ROOT，则进入秒删模式
  if (isRooted()) {
    LOGI("Cleaning up temp files");
    RSBDecrypt::cleanupTempFiles();
  }
#endif

  LOGI("Hooking ResourcesManagerFunc End");
}

inline void process() {
  if constexpr (ResourceManagerFuncAddr != UNKNOWN)
    PVZ2HookFunction(ResourceManagerFuncAddr, (void *)hkResourceManagerFunc,
                     (void **)&oResourceManagerFunc, "ResourceManager::ResourceManagerFunc");
}
}  // namespace HookResourceManagerFunc

__attribute__((constructor)) void libRestructedLogic_ARM64__main() {
  LOGI("Initializing %s", LIB_TAG);

  HookResourceManagerFunc::process();
  DirectInstallOBB::process();  // 直装包

#ifdef _DEBUG
  LogOutput::process();  // 输出日志
#endif
  MaxZoom::process();  // 高视角

  LOGI("Finished initializing");
}
