#include "memUtils.hpp"
#include "Unzip/ApkUnzipper.hpp"
#include "Unzip/HashComparer.hpp"
#include "AXML/axml_parser.hpp"
#include "Decrypt/picosha2.hpp"
#include "Decrypt/aes.hpp"
#include "tinyxml2/tinyxml2.h"
#include "SexyTypes.hpp"
#include "RestructedLogic_ARM32_.hpp"
#include "VersionSwitcher.hpp"

using _DWORD = uint32_t;
using __int64 = int64_t;
using _BYTE = uint8_t;

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

namespace DirectInstallOBB {
bool exit_when_finished = false;
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
XXH64_hash_t apkOBBHash;
// 数据包哈希值
XXH64_hash_t OBBHash;

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
  LOGI("APK location: %s", apk_path.c_str());
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
  LOGI("ori_rsb_name = %s, rsb_path_str = %s, rsb_self_path_str = %s", ori_rsb_name.c_str(),
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
    LOGI("Not a direct-install package, skipping hash check.");
    return true;
  }

  LOGI("Calculating Hash");
  if (check_magic_number(rsb_self_path_str.c_str(), "EBRL")) {
    LOGI("检测到EBRL，读取后续哈希值");
    OBBHash = HashComparer::read_hash_after_header(rsb_self_path_str.c_str());
  } else {
    // 如果大小不一，直接就是不一样
    if (apkObbSize != std::filesystem::file_size(std::filesystem::path(rsb_self_path_str))) {
      LOGI("Size mismatch, hashes must differ.");
      return false;
    }
    OBBHash = HashComparer::compute_file_hash(std::filesystem::path(rsb_self_path_str));
  }
  apkOBBHash = HashComparer::get_asset_hash(apk_path, "assets/" + ori_rsb_name);
  bool result = HashComparer::are_hashes_identical(apkOBBHash, OBBHash);
  LOGI("Hash End");
  return result;
}

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
    LOGI("Not a direct-install package.");
    return 0;
  }
}

// 线程监控OBB路径是否存在
void obb_path_monitor() {
  while (1) {
    if (apk_path.empty())
      get_apk_information();
    if (OBBPathExisted()) {
      thread_applied = true;
      LOGI("RSBDirectInstall Start.");
      AssetsRSBDirectInstall();
      LOGI("RSBDirectInstall End.");
      thread_applied = false;
#if GAME_VERSION < 1031
      if (exit_when_finished)
        kill(getpid(), SIGKILL);
#endif
      return;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
  }
}

// 让主程序延迟防止数据包迁移期间被读取
void delay_PvZ2() {
  while (thread_applied) {
    LOGI("RSB installing, sleep...");
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
  }
}

inline void process() {
  if (!OBBPathExisted())
    exit_when_finished = true;
  // 必须留，获取包名和版本号信息
  if (apk_path.empty())
    get_apk_information();
  // 直装包：数据包不存在或者哈希校验不通过则轮询路径是否存在
  if (!OBBExisted() || !OBBHashEquals())
    std::thread(obb_path_monitor).detach();
}
}  // namespace DirectInstallOBB

namespace MaxZoom {

// 本 namespace 可用的前置条件：用到的地址全部已适配
constexpr bool ENABLE = LawnAppScreenWidthHeightAddr != UNKNOWN && BoardZoomAddr != UNKNOWN &&
                        BoardZoom2Addr != UNKNOWN;

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

// LawnAppScreenWidthHeight 的原函数会随版本变化。目前只知道低版本和高版本的写法。
// 其他版本欢迎补充。
#if GAME_VERSION == 873

typedef int (*LawnAppScreenWidthHeight)(int a1, int a2);
static LawnAppScreenWidthHeight oLawnAppScreenWidthHeight = nullptr;

int hkLawnAppScreenWidthHeight(int a1, int a2) {
  // 1. 先执行原函数，让内部逻辑完成内存写入
  int result = oLawnAppScreenWidthHeight(a1, a2);

  if (a1 == NULL)
    return result;

  // 2. 根据偏移直接提取数据
#ifdef _DEBUG
  mOrigScreenWidth = *(_DWORD *)(a1 + 1512);
#endif
  mOrigScreenHeight = *(_DWORD *)(a1 + 1516);

  // 根据自身
  mWidth = *(_DWORD *)(a1 + 136);
#ifdef _DEBUG
  mHeight = *(_DWORD *)(a1 + 140);
#endif

  // 3. 输出日志
  LOGI(R"(
--- LawnApp::SetWidthHeight Hook ---
mOrigWidth: %d, mOrigHeight: %d
mWidth: %d, mHeight: %d
result: %d)",
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

#elif GAME_VERSION == 1031

typedef int (*LawnAppScreenWidthHeight)(float *a1, int a2);
static LawnAppScreenWidthHeight oLawnAppScreenWidthHeight = nullptr;

int hkLawnAppScreenWidthHeight(float *a1, int a2) {
  // 1. 先执行原函数，让内部逻辑完成内存写入
  int result = oLawnAppScreenWidthHeight(a1, a2);

  if (a1 == nullptr)
    return result;

  // 2. 根据偏移直接提取数据
  // 注意：a1 是 float*，偏移计算需小心转换
  int *iPtr = (int *)a1;

  // 1448字节 = 偏移362, 1452字节 = 偏移363
#ifdef _DEBUG
  mOrigScreenWidth = iPtr[362];
#endif
  mOrigScreenHeight = iPtr[363];

  // 根据自身
  mWidth = iPtr[25];
#ifdef _DEBUG
  mHeight = iPtr[26];
#endif

  // 3. 输出日志
  LOGI(R"(
--- LawnApp::SetWidthHeight Hook ---
mOrigWidth: %d, mOrigHeight: %d
mWidth: %d, mHeight: %d
result: %d)",
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

#else

#error \
    "Unsupported game version for LawnAppScreenWidthHeight hook. You may try the above 2 versions."

#endif

inline bool readMaxZoomButton() {
  // PvZ2 设置文件路径
  static const std::string settings_xml_path = "/data/data/" +
                                               DirectInstallOBB::get_package_name() +
                                               "/shared_prefs/com.popcap.PvZ2.PvZ2GameActivity.xml";

  // 特判边界情况（应该不会出现）
  tinyxml2::XMLDocument doc;
  if (doc.LoadFile(settings_xml_path.c_str()) != tinyxml2::XML_SUCCESS)
    return false;
  tinyxml2::XMLElement *root = doc.FirstChildElement("map");
  if (!root)
    return false;

  // 遍历 XML 元素，查找名为 "HasDisabledUsageSharing" 的属性，并返回其布尔值
  for (tinyxml2::XMLElement *elem = root->FirstChildElement(); elem != nullptr;
       elem = elem->NextSiblingElement()) {
    const char *name = elem->Attribute("name");
    if (name && strcmp(name, "HasDisabledUsageSharing") == 0)
      return elem->BoolAttribute("value");
  }

  // 不存在则为 false
  return false;
}

// 定义原函数的函数原型
typedef int (*BoardZoom)(int a1);
static BoardZoom oBoardZoom = nullptr;

int hkBoardZoom(int a1) {
  if (!a1)
    return 0;
  // 先跑原函数
  int result = oBoardZoom(a1);
  // 改变选卡时视野左边缘与棋盘左边缘的距离
  if (readMaxZoomButton())
    *(_DWORD *)(a1 + 880) = preGameRightLine - mWidth;
  return result;
}

// 定义原函数的函数原型
typedef int (*BoardZoom2)(int a1);
static BoardZoom2 oBoardZoom2 = nullptr;

int hkBoardZoom2(int a1) {
  if (!a1)
    return 0;
  int result = oBoardZoom2(a1);
  if (readMaxZoomButton()) {
    // 缩放系数
    *(float *)(a1 + 860) = 1.0f;
    // 改变视野左边缘与棋盘左边缘的距离
    *(_DWORD *)(a1 + 824) = -(gameStartRightLine - mWidth);
    // 顶部基准线
    *(_DWORD *)(a1 + 868) = (_DWORD)mOrigScreenHeight;
  }
  return result;
}

inline void process() {
  if constexpr (ENABLE) {
    // 得到缩放前后尺寸
    PVZ2HookFunction(LawnAppScreenWidthHeightAddr, (void *)hkLawnAppScreenWidthHeight,
                     (void **)&oLawnAppScreenWidthHeight, "LawnApp::SetScreenWidthHeight");
    // 控制屏幕缩放
    PVZ2HookFunction(BoardZoomAddr, (void *)hkBoardZoom, (void **)&oBoardZoom, "BoardZoom");
    PVZ2HookFunction(BoardZoom2Addr, (void *)hkBoardZoom2, (void **)&oBoardZoom2, "BoardZoom2");
  }
}
}  // namespace MaxZoom

#if GAME_VERSION < 1031

namespace AliasToID {
// 本 namespace 可用的前置条件：用到的地址全部已适配
constexpr bool ENABLE = PlantNameMapperAddr != UNKNOWN && firstFreePlantID != UNKNOWN;

class PlantNameMapper {
 public:
  void *vftable;
  std::map<Sexy::SexyString, uint> m_aliasToId;
};
std::vector<Sexy::SexyString> g_modPlantTypenames;

#define REGISTER_PLANT_TYPENAME(typename) g_modPlantTypenames.push_back(typename);

typedef PlantNameMapper *(*PlantNameMapperCtor)(PlantNameMapper *);
static PlantNameMapperCtor oPlantNameMapperCtor = nullptr;

void *hkCreatePlantNameMapper(PlantNameMapper *self) {
  oPlantNameMapperCtor(self);
  g_modPlantTypenames.clear();
  for (int i = 1; i <= 100; i++) {
    REGISTER_PLANT_TYPENAME(("custom_plant_" + std::to_string(i)));
  }
  LOGI("Extra typenames size = %d", g_modPlantTypenames.size());
  for (int iter = 0; iter < g_modPlantTypenames.size(); iter++) {
    LOGI("Registering plant %s", g_modPlantTypenames[iter].c_str());
    self->m_aliasToId[g_modPlantTypenames[iter]] = firstFreePlantID + iter;
  }
  return self;
}

inline void process() {
  if constexpr (ENABLE)
    PVZ2HookFunction(PlantNameMapperAddr, (void *)hkCreatePlantNameMapper,
                     (void **)&oPlantNameMapperCtor, "PlantNameMapper::PlantNameMapper");
}

#undef REGISTER_PLANT_TYPENAME
}  // namespace AliasToID

#endif

namespace CDNExpansion {
// 在此感谢CZ的技术专栏分享，我将变量名和一些方式进行了小小的改变，但依旧需要对其为技术的分享表达感谢！！！！！
// 本 namespace 可用的前置条件：用到的地址全部已适配
constexpr bool ENABLE = CDNLoadAddr != UNKNOWN;

typedef int (*CDNExpand)(int *a1, const Sexy::SexyString &rtonName, int rtonTable, int a4);
static CDNExpand oCDNLoad = nullptr;

std::atomic<bool> executed(false);

int hkCDNLoad(int *a1, const Sexy::SexyString &rtonName, int rtonTable, int a4) {
  // 至于这个偏移怎么查.........很简单，HEX搜products.rton
  // 然后根据products.rton的"p"的偏移地址，用ida pro跳转到该地址
  // 你会发现一堆的rton（绿色）右侧都用同一个DATA XREF地址跳转（引用偏移地址）
  // 双击那个地址，你就会到达CZ讲的那个大函数，跳转后按F5，然后向下翻就能看到
  // 那些rton下面都有同一个函数，就是那个函数需要hook
  // 然后原理CZ讲过了，我也是直接拿来用，没啥丢脸的，有公开的好东西不用才是固执嘛......
  // 不过，CZ拿64位演示，推荐的bb2和jay krow的32位工程，对于一些萌新来说可不友好哦......
  // 原理很简单（如果这都要拿AI去查什么意思的话，那我可要数落你了啊）
  // executed一开始为false，我们在塞入rton之前的第一步就是检测executed是否为true
  // executed你可以比喻为一个罐子，打开了就是true，没打开就是false，我们只需要打开一次就不需要打开了
  // 所以第一次我们打开之前，罐子是未开封状态，打开了就是开封状态
  // 未开封状态我们要打开罐子拿出东西塞别的里面去，我们塞过之后就不需要再塞重复的了
  // 所以一看到开封的状态我们就知道不需要在这个罐子里面拿东西了
  // 所以executed在我们塞rton之前是false，塞rton时候就已经变true了，就不需要再塞了
  if (!executed.exchange(true)) {
    // 载入各版本RtonTableID
    rtonTableIDsLoader();
    LOGI("Rton Table IDs Load succeed.");
    // 遍历载入
    for (const auto &rtonfile : rtonTableIDs) {
      oCDNLoad(a1, rtonfile.first, rtonfile.second, 1);
      LOGI("%s:%d is loaded", (rtonfile.first).c_str(), rtonfile.second);
    }
  }
  LOGI("%s:%d is loaded", rtonName.c_str(), rtonTable);
  return oCDNLoad(a1, rtonName, rtonTable, a4);
}

inline void process() {
  // CDN读取rton，感谢CZ技术专栏分享技术！！！
  if constexpr (ENABLE)
    PVZ2HookFunction(CDNLoadAddr, (void *)hkCDNLoad, (void **)&oCDNLoad, "CDNLoadExpansion");
}
}  // namespace CDNExpansion

namespace LogOutput {
// 游戏自己的日志输出转发到 logcat：原函数是变参 printf 形，先按格式串格式化再原样转调。

// 本 namespace 可用的前置条件：用到的地址全部已适配
constexpr bool ENABLE = LogOutputFuncAddr != UNKNOWN;

typedef int (*LogOutputFunc)(char *format, ...);
static LogOutputFunc oLogOutputFunc = nullptr;
static std::mutex g_logMutex;

int hkLogOutputFunc(char *format, ...) {
  if (!oLogOutputFunc) {
    LOGI("LogOutputFunc: Original function pointer is null");
    return -1;
  }
  std::lock_guard<std::mutex> lock(g_logMutex);

  va_list va, va_cpy;
  va_start(va, format);
  va_copy(va_cpy, va);

  // 计算所需长度
  va_start(va, format);
  char *buffer, temp[1];
  int len = vsnprintf(temp, 0, format, va);
  va_end(va);

  va_start(va, format);
  buffer = new char[len + 1];
  len = vsnprintf(buffer, len + 1, format, va);
  buffer[len] = '\0';
  LOGI("LogOutputFunc: %s", buffer);

  int result = oLogOutputFunc(format, va_cpy);
  va_end(va_cpy);
  va_end(va);
  delete[] buffer;
  return result;
}

inline void process() {
  // 输出主日志
  if constexpr (ENABLE)
    PVZ2HookFunction(LogOutputFuncAddr, (void *)hkLogOutputFunc, (void **)&oLogOutputFunc,
                     "LogOutputFunc");
}
}  // namespace LogOutput

namespace RSBDecrypt {
// 本 namespace 可用的前置条件：用到的地址全部已适配
constexpr bool ENABLE = RSBPathRecorderAddr != UNKNOWN && ResourceManagerFuncAddr != UNKNOWN;

// C++11 兼容的编译期字符串混淆
template <size_t... Is>
struct index_sequence {};
template <size_t N, size_t... Is>
struct make_index_sequence : make_index_sequence<N - 1, N - 1, Is...> {};
template <size_t... Is>
struct make_index_sequence<0, Is...> : index_sequence<Is...> {};

template <int XorKey, size_t N>
struct ObfuscatedString {
  char encrypted[N];
  template <size_t... Is>
  constexpr ObfuscatedString(const char *str, index_sequence<Is...>)
      : encrypted{static_cast<char>(str[Is] ^ (XorKey + Is))...} {}

  inline std::string decrypt() const {
    std::string s;
    s.resize(N - 1);
    for (size_t i = 0; i < N - 1; ++i)
      s[i] = encrypted[i] ^ (XorKey + i);
    return s;
  }
};
#define HIDE_STR(s) \
  (ObfuscatedString<(0x55 + __LINE__), sizeof(s)>(s, make_index_sequence<sizeof(s)>()).decrypt())

/**
 * 递归创建目录 (模拟 mkdir -p)
 * @param path 目标绝对路径
 * @return 是否创建成功或目录已存在
 */
bool makePath(const std::string &path) {
  std::string tmp_path = path;
  // 确保路径以斜杠结尾，方便统一逻辑处理
  if (tmp_path.empty())
    return false;
  if (tmp_path.back() != '/') {
    tmp_path += '/';
  }
  size_t pos = 0;
  // 找到每一个 '/' 的位置并逐层创建
  // 从 pos+1 开始，跳过根目录的第一个 '/'
  while ((pos = tmp_path.find('/', pos + 1)) != std::string::npos) {
    std::string dir = tmp_path.substr(0, pos);
    // 尝试创建目录
    if (mkdir(dir.c_str(), 0777) != 0) {
      // 如果错误原因不是“目录已存在”，则返回失败
      if (errno != EEXIST) {
        return false;
      }
    }
  }
  return true;
}

/**
 * 纯解密核心：专门适配分块映射。
 * 只做解密，不移动内存，不检测 Header。
 * 核心解密：纯计算，不检测 Magic，不移动内存
 * 确保 decrypt_pure_cbc_internal 接收 key
 */
void decrypt_pure_cbc_internal(uint8_t *data, size_t size, const uint8_t *start_iv,
                               const uint8_t *key) {
  uint32_t num_blocks = (uint32_t)(size / 16);
  unsigned int num_threads = std::thread::hardware_concurrency();
  if (num_threads == 0)
    num_threads = 4;

  uint32_t blocks_per_thread = num_blocks / num_threads;
  std::vector<std::thread> threads;

  for (unsigned int t = 0; t < num_threads; ++t) {
    uint32_t start_block = t * blocks_per_thread;
    uint32_t end_block = (t == num_threads - 1) ? num_blocks : (t + 1) * blocks_per_thread;

    threads.emplace_back([=, &key, &start_iv]() {
      uint32_t t_offset = start_block * 16;
      uint32_t t_len = (end_block - start_block) * 16;
      if (t_len == 0)
        return;

      struct AES_ctx ctx;
      uint8_t thread_iv[16];

      if (start_block == 0) {
        memcpy(thread_iv, start_iv, 16);
      } else {
        memcpy(thread_iv, data + t_offset - 16, 16);
      }

      AES_init_ctx_iv(&ctx, key, thread_iv);
      AES_CBC_decrypt_buffer(&ctx, data + t_offset, t_len);
    });
  }
  for (auto &th : threads)
    th.join();
}

// 将文件头部替换为可识别四字节
bool maskFileHeader(const std::string &filePath, std::string tagstr) {
  // 1. 以读写模式打开文件 (注意不要加 O_TRUNC，否则文件会被清空！)
  int fd = open(filePath.c_str(), O_RDWR);
  if (fd < 0)
    return false;
  // 2. 准备新的 4 字节头
  const char *tag = tagstr.c_str();
  // 3. 使用 pwrite 直接覆盖偏移量为 0 的位置
  // 这一步是原子操作，只改动磁盘上最开始的 4 个字节
  ssize_t bytes = pwrite(fd, tag, 4, 0);
  // 4. 强制将修改刷入磁盘（防止断电丢失）
  fdatasync(fd);
  close(fd);

  return bytes == 4;
}

// 临时文件路径列表
static std::vector<std::string> g_tempFiles;

// 清理临时文件
void cleanupTempFiles() {
  for (const auto &path : g_tempFiles) {
    if (unlink(path.c_str()) == 0) {
      LOGI("Deleted temp file: %s", path.c_str());
    } else {
      LOGI("Failed to delete temp file: %s, errno=%d", path.c_str(), errno);
    }
  }
  g_tempFiles.clear();
}

// Hook 函数
typedef int (*RSBPathRecorder)(uint *a1);
static RSBPathRecorder oRSBPathRecorder = nullptr;

int hkRSBPathRecorder(uint *a1) {
  LOGI("Hooking RSBPathRecorder");
  if (!a1) {
    LOGI("RSBPathRecorder: a1 is null");
    return oRSBPathRecorder(a1);
  }

  // 调用原始函数
  int result = oRSBPathRecorder(a1);
  LOGI("RSBPathRecorder: Original function returned %d, a1[0]=0x%x, a1[1]=0x%x, a1[2]=0x%x", result,
       a1[0], a1[1], a1[2]);

  // 提取路径
  char *path_ptr = nullptr;
  if (a1[0] & 1) {
    path_ptr = (char *)a1[2];  // 动态分配，路径在 a1[2]
  } else {
    path_ptr = (char *)a1[1];  // 非动态分配，路径在 a1[1]
  }
  if (!path_ptr || (size_t)path_ptr < 0x1000) {
    LOGI("RSBPathRecorder: Invalid path pointer 0x%x, a1[0]=0x%x", (size_t)path_ptr, a1[0]);
    return result;
  }
  std::string original_path;
  size_t i;
  for (i = 0; i < 1024; ++i) {
    if (path_ptr[i] == '\0') {
      original_path = std::string(path_ptr, i);
      break;
    }
    if (i == 1023) {
      LOGI("RSBPathRecorder: Path too long or invalid");
      return result;
    }
  }
  if (original_path.empty()) {
    LOGI("RSBPathRecorder: Path is empty");
    return result;
  }
  LOGI("RSBPathRecorder: Original path=%s", original_path.c_str());

  // C++17新增优化
  std::filesystem::path fsOriPath = original_path;
  std::vector<std::string> path_components;
  // 存入路径上各文件夹名称
  for (const auto &part : fsOriPath) {
    if (!part.empty() && part != "/") {
      path_components.push_back(part.string());
    }
  }
  // 获取包名
  std::string pack_name = path_components[path_components.size() - 2];
  // 获取数据包名
  std::string rsb_name = path_components[path_components.size() - 1];

  std::string expected_path = "/storage/emulated/0/Android/obb/" + pack_name + "/" + rsb_name;
  if (original_path != expected_path) {
    LOGI("RSBPathRecorder: Path mismatch, expected %s", expected_path.c_str());
    // 继续处理，允许非预期路径
  }

  LOGI("RSB_TRACE: Starting Hybrid Mmap-Stream Process...");

  std::string cache_dir = "/data/data/" + pack_name + "/files";
  makePath(cache_dir);
  // 这个地方可以随意写，这样别人就认不出来了
  std::string temp_path = cache_dir + "/.cache_file";

  // 2. 检测 1bsr (保持不变)
  int src_fd = open(original_path.c_str(), O_RDONLY);
  // 读不到文件直接切到temp_path
  if (src_fd >= 0) {
    uint8_t magic[4];
    read(src_fd, magic, 4);
    if (memcmp(magic, "1bsr", 4) == 0) {
      LOGI("RSB_TRACE: Detected 1bsr, skipping...");
      return result;
    }
    if (memcmp(magic, "EBRL", 4) == 0 && isRooted()) {
      // 是ROOT重写数据包头
      if (!maskFileHeader(original_path.c_str(), "RSB2")) {
        // 重写失败报错
        LOGI("RSB_TRACE: RSB2 overrides failed.");
        return result;
      } else
        LOGI("RSB_TRACE: RSB2 overrides succeed.");
    }
    if (memcmp(magic, "EBRL", 4) == 0) {
      LOGI("RSB_TRACE: Detected EBRL, using temp_path...");
    } else {
      // 3. 准备 IV 和 Key (使用你的 HIDE_STR)
      uint8_t iv_from_header[16];
      read(src_fd, iv_from_header, 16);

      uint8_t key[32];
      {
        // 此处填写密钥!!!!!!!!!!!!!!!!!!!!!!!!!
        std::string pwd = HIDE_STR("rl_key");
        picosha2::hash256_one_by_one hasher;
        hasher.process(pwd.begin(), pwd.end());
        hasher.finish();
        hasher.get_hash_bytes(key, key + 32);
      }

      // 4. 关键：利用内核 sendfile 完成第一次全量物理拷贝 (这是目前最快的读写方式)
      struct stat st;
      fstat(src_fd, &st);
      size_t file_size = st.st_size;
      int dst_fd = open(temp_path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0666);
      lseek(src_fd, 0, SEEK_SET);
      sendfile(dst_fd, src_fd, nullptr, file_size);
      close(src_fd);

      // 5. 分块映射解密 + 即时覆盖平移
      LOGI("RSB_TRACE: Phase: Mmap Decrypt + Immediate In-place Pwrite...");

      const size_t CHUNK_SIZE = 256 * 1024 * 1024;  // 256MB，平衡 32 位内存压力与效率
      size_t current_cipher_pos = 20;
      size_t total_plain_written = 0;
      uint8_t active_iv[16];
      memcpy(active_iv, iv_from_header, 16);

      while (current_cipher_pos < file_size) {
        // 计算页对齐的映射偏移
        size_t map_offset = (current_cipher_pos / 4096) * 4096;
        size_t in_map_offset = current_cipher_pos - map_offset;

        size_t remaining = file_size - current_cipher_pos;
        size_t decrypt_len = (remaining > CHUNK_SIZE) ? CHUNK_SIZE : remaining;
        decrypt_len &= ~0xF;  // 16字节对齐
        if (decrypt_len == 0)
          break;

        size_t map_size = decrypt_len + in_map_offset;
        void *ptr = mmap(NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, dst_fd, map_offset);
        if (ptr == MAP_FAILED) {
          LOGI("RSB_TRACE: mmap failed, errno=%d", errno);
          break;
        }

        uint8_t *cipher_ptr = (uint8_t *)ptr + in_map_offset;

        // 备份下一块密文 IV
        uint8_t next_iv_backup[16];
        memcpy(next_iv_backup, cipher_ptr + decrypt_len - 16, 16);

        // 调用多线程解密 (直接操作映射内存，极致速度)
        decrypt_pure_cbc_internal(cipher_ptr, decrypt_len, active_iv, key);

        // 更新当前链的 IV
        memcpy(active_iv, next_iv_backup, 16);

        // 处理 Padding (最后一块)
        size_t block_write_len = decrypt_len;
        if (current_cipher_pos + decrypt_len >= file_size - 16) {
          uint8_t pad = cipher_ptr[decrypt_len - 1];
          if (pad > 0 && pad <= 16)
            block_write_len -= pad;
        }

        // 【提速】利用 pwrite 将解密好的明文直接写回到文件开头的正确位置
        // 因为这块内存就在 Page Cache 里，pwrite 此时基本等同于内存拷贝，极快
        pwrite(dst_fd, cipher_ptr, block_write_len, total_plain_written);

        total_plain_written += block_write_len;
        munmap(ptr, map_size);
        current_cipher_pos += decrypt_len;
      }

      // 6. 最终裁剪：一秒搞定
      ftruncate(dst_fd, total_plain_written);
      fdatasync(dst_fd);  // 确保元数据和数据写回
      close(dst_fd);

      LOGI("RSB_TRACE: All Done. Optimized Path Taken.");

      // 重写数据包头部为EBRL
      if (!isRooted()) {
        // 没ROOT重写数据包头
        if (!HashComparer::generate_hash_file_with_header(original_path.c_str(),
                                                          original_path.c_str(), "EBRL")) {
          // 重写失败报错
          LOGI("RSB_TRACE: EBRL overrides failed.");
          return result;
        } else
          LOGI("RSB_TRACE: EBRL overrides succeed.");
      }
      // ROOT警报
      else {
        // 记录需要删除的解密数据包（因为需要防ROOT）
        g_tempFiles.push_back(temp_path);
        LOGI("RSB_TRACE: Warning! Device rooted.");
      }
    }
  }

  // 替换路径
  char *new_path = strdup(temp_path.c_str());
  if (!new_path) {
    LOGI("RSBPathRecorder: Failed to allocate new_path");
    return result;
  }
  size_t new_path_len = strlen(new_path);

  if (a1[0] & 1) {
    // 动态分配
    if (a1[2]) {
      free((void *)a1[2]);  // 释放原始路径
    }
    unsigned int v10 = new_path_len > 20 ? new_path_len : 20;
    unsigned int v8 = (v10 + 16) & 0xFFFFFFF0;  // 分配大小
    a1[0] = v8 | 1;                             // a1[0] = 65 (0x41)
    a1[1] = new_path_len;                       // a1[1] = 47 (0x2F)
    a1[2] = (size_t)new_path;                   // 新路径指针
  } else {
    // 非动态分配
    a1[0] = 2 * new_path_len;  // a1[0] = 2 * 路径长度
    a1[1] = (size_t)new_path;  // a1[1] = 新路径指针
  }
  LOGI("RSBPathRecorder: Replaced path with %s", temp_path.c_str());

  return result;
}

inline void process() {
  if constexpr (ENABLE) {
    // Hook RSB 读取函数
    PVZ2HookFunction(RSBPathRecorderAddr, (void *)hkRSBPathRecorder, (void **)&oRSBPathRecorder,
                     "ResourceManager::RSBPathRecorder");
  }
}
}  // namespace RSBDecrypt

namespace PrimeGlyphCacheLimitation {
// 本 namespace 可用的前置条件：用到的地址全部已适配
constexpr bool ENABLE = PrimeGlyphCacheAddr != UNKNOWN;

// 一路：高端设备缓冲大小为2048，中端设备为1024，低端设备为512。经过测试，缓冲大小最大只能设为2048，设为更高值，会导致进入游戏后文字渲染全为空白，这与设为0的效果一致。
typedef uint *(*PrimeGlyphCacheLimitation)(uint *a1, int a2, int a3, int a4);
static PrimeGlyphCacheLimitation oPrimeGlyphCacheLimitation = nullptr;

uint *hkPrimeGlyphCacheLimitation(uint *a1, int a2, int a3, int a4) {
  uint *result = oPrimeGlyphCacheLimitation(a1, a2, a3, a4);
  a1[22] = 2048;
  LOGI("Hooked PrimeGlyphCacheLimitation: Modified a1[22] to %d", a1[22]);
  return result;
}

inline void process() {
  if constexpr (ENABLE)
    PVZ2HookFunction(PrimeGlyphCacheAddr, (void *)hkPrimeGlyphCacheLimitation,
                     (void **)&oPrimeGlyphCacheLimitation,
                     "PrimeGlyphCache::PrimeGlyphCacheLimitation");
}
}  // namespace PrimeGlyphCacheLimitation

namespace WorldMapVerticalScrolling {
// 本来我完全可以让你们每个版本都去找通用的三个偏移的，但是为了你们旧版本的，我采用条件编译了
// 旧版只需要找一个偏移，而新版则需要找三个

// 本 namespace 可用的前置条件：用到的地址全部已适配
#if GAME_VERSION >= 1001
constexpr bool ENABLE =
    WorldMapScrollAddr != UNKNOWN && KeepCenterAddr != UNKNOWN && ScrollInertanceAddr != UNKNOWN;
#else
constexpr bool ENABLE = WorldMapDoMovementAddr != UNKNOWN;
#endif

#if GAME_VERSION >= 1001

// 新版需要hook三个函数，而且由于该死的内联，不能把函数全反编译了，所以直接暴力扩边界让它们强行切到垂直移动判定
// 拖动函数:
typedef int (*WorldMapScroll)(int, int, int);
static WorldMapScroll oWorldMapScroll = nullptr;

int hkWorldMapScroll(int a1, int a2, int a3) {
  *(int32_t *)(a1 + 312) = -1000000000;
  *(int32_t *)(a1 + 316) = -1000000000;
  *(int32_t *)(a1 + 320) = 2000000000;
  *(int32_t *)(a1 + 324) = 2000000000;
  return oWorldMapScroll(a1, a2, a3);
}

// 居中函数：
typedef int (*KeepCenter)(int, uint *, bool);
static KeepCenter oKeepCenter = nullptr;

int hkKeepCenter(int a1, uint *a2, bool a3) {
  *(int32_t *)(a1 + 312) = -1000000000;
  *(int32_t *)(a1 + 316) = -1000000000;
  *(int32_t *)(a1 + 320) = 2000000000;
  *(int32_t *)(a1 + 324) = 2000000000;
  return oKeepCenter(a1, a2, true);
}

// 惯性函数：
typedef int (*ScrollInertance)(int);
static ScrollInertance oScrollInertance = nullptr;

int hkScrollInertance(int a1) {
  *(int32_t *)(a1 + 312) = -1000000000;
  *(int32_t *)(a1 + 316) = -1000000000;
  *(int32_t *)(a1 + 320) = 2000000000;
  *(int32_t *)(a1 + 324) = 2000000000;
  return oScrollInertance(a1);
}

#else

// 旧函数（10.0版本前有效）
typedef int (*WorldMapDoMovement)(void *, float, float, bool);
static WorldMapDoMovement oWorldMapDoMovement = nullptr;

// 是否移动
bool g_allowVerticalMovement = true;

int hkWorldMapDoMovement(void *map, float fX, float fY, bool allowVerticalMovement) {
  LOGI("Doing map movement: fX - %f, fY - %f", fX, fY);
  return oWorldMapDoMovement(map, fX, fY, g_allowVerticalMovement);
}

#endif

inline void process() {
#if GAME_VERSION >= 1001

  if constexpr (ENABLE) {
    // 拖动函数
    PVZ2HookFunction(WorldMapScrollAddr, (void *)hkWorldMapScroll, (void **)&oWorldMapScroll,
                     "WorldMap::WorldMapScroll");
    // 居中函数
    PVZ2HookFunction(KeepCenterAddr, (void *)hkKeepCenter, (void **)&oKeepCenter,
                     "WorldMap::KeepCenter");
    // 惯性函数
    PVZ2HookFunction(ScrollInertanceAddr, (void *)hkScrollInertance, (void **)&oScrollInertance,
                     "WorldMap::ScrollInertance");
  }

#else

  if constexpr (ENABLE)
    PVZ2HookFunction(WorldMapDoMovementAddr, (void *)hkWorldMapDoMovement,
                     (void **)&oWorldMapDoMovement, "WorldMap::doMovement");

#endif
}
}  // namespace WorldMapVerticalScrolling

namespace HookResourceManagerFunc {

// 本 namespace 可用的前置条件：用到的地址全部已适配
constexpr bool ENABLE = ResourceManagerFuncAddr != UNKNOWN;

#define USE_DIRECT_INSTALL_OBB
#define USE_RSB_DECRYPT

// 直装包卡主进程以及 ROOT 检测
typedef int (*ResourceManagerFunc)(int, int, int);
static ResourceManagerFunc oResourceManagerFunc = nullptr;

int hkResourceManagerFunc(int a1, int a2, int a3) {
  LOGI("ResourceManagerFunc hook entered.");

#ifdef USE_DIRECT_INSTALL_OBB
  DirectInstallOBB::delay_PvZ2();
#endif

  int backdata = oResourceManagerFunc(a1, a2, a3);

#ifdef USE_RSB_DECRYPT
  // 如果检测到ROOT，则进入秒删模式
  if (isRooted()) {
    LOGI("Cleaning up temp files");
    RSBDecrypt::cleanupTempFiles();
  }
#endif

  LOGI("ResourceManagerFunc hook done.");
  return backdata;
}

inline void process() {
  if constexpr (ENABLE)
    PVZ2HookFunction(ResourceManagerFuncAddr, (void *)hkResourceManagerFunc,
                     (void **)&oResourceManagerFunc, "ResourceManager::ResourceManagerFunc");
}
}  // namespace HookResourceManagerFunc

namespace EnableDangerRoomRestart {
// 本 namespace 可用的前置条件：用到的地址全部已适配
constexpr bool ENABLE = PauseMenuShowAddr != UNKNOWN;

typedef int (*ShowPauseMenu)(void *a1, int a2, int a3, int a4, int a5);
static ShowPauseMenu oShowPauseMenu = nullptr;

int hkShowPauseMenu(void *a1, int a2, int a3, int a4, int a5) {
  return oShowPauseMenu(a1, a2, a3, 0, a5);
}

inline void process() {
  if constexpr (ENABLE)
    PVZ2HookFunction(PauseMenuShowAddr, (void *)hkShowPauseMenu, (void **)&oShowPauseMenu,
                     "ShowPauseMenu");
}
}  // namespace EnableDangerRoomRestart

namespace DisableAlmanacTutorial {
// 本 namespace 可用的前置条件：用到的地址全部已适配
constexpr bool ENABLE = AlmanacStateUpdateAddr != UNKNOWN && TutorialCheckAddr != UNKNOWN &&
                        NarrativeCheckAddr != UNKNOWN;

// Hook 1: 阻止图鉴内 FindMore 强制点击
typedef int (*AlmanacStateUpdate)(int a1, int state);
static AlmanacStateUpdate oAlmanacStateUpdate = nullptr;

int hkAlmanacStateUpdate(int a1, int state) {
  if (state > 1)
    state = 1;
  return oAlmanacStateUpdate(a1, state);
}

// Hook 2: 阻止 ALMANAC_INTRO 教程（前半段对话+强制开图鉴）
// (int *result, void *context)
// result+0:  byte  tutorial_active
// result+16: dword tutorial_type (20 or 2 = ALMANAC_INTRO)
typedef int (*TutorialCheck)(void *result, void *context);
static TutorialCheck oTutorialCheck = nullptr;

int hkTutorialCheck(void *result, void *context) {
  int ret = oTutorialCheck(result, context);
  if (result)
    *(char *)result = 0;
  return ret;
}

// Hook 3: 阻止 ALMANAC_INTRO 对话播放
// R0=result, R1=SexyString* context
// SexyString inline: byte0='\n', bytes1-5="egypt"
typedef int (*NarrativeCheck)(void *result, void *context);
static NarrativeCheck oNarrativeCheck = nullptr;

int hkNarrativeCheck(void *result, void *context) {
  int ret = oNarrativeCheck(result, context);
  if (result)
    *(char *)result = 0;
  return ret;
}

inline void process() {
  if constexpr (ENABLE) {
    PVZ2HookFunction(AlmanacStateUpdateAddr, (void *)hkAlmanacStateUpdate,
                     (void **)&oAlmanacStateUpdate, "AlmanacStateUpdate");
    PVZ2HookFunction(TutorialCheckAddr, (void *)hkTutorialCheck, (void **)&oTutorialCheck,
                     "TutorialCheck");
    PVZ2HookFunction(NarrativeCheckAddr, (void *)hkNarrativeCheck, (void **)&oNarrativeCheck,
                     "NarrativeCheck");
  }
}
}  // namespace DisableAlmanacTutorial

namespace GeneralFunction {
// 通用工具（ARM32）：SexyString/句柄解析（弱指针系统）、属性列表、类型系统、实体动画
// 与功能专属解耦：温暖（SnapdragonWarming）/化灰亡语（Ash）复用

typedef int (*CtxGet)(void);
static CtxGet oCtxGet = nullptr;
typedef void (*SexyStringParse)(void *iter, int guard, int list);
static SexyStringParse oSexyStringParse = nullptr;
typedef bool (*SexyStringEmpty)(void *iter);
static SexyStringEmpty oSexyStringEmpty = nullptr;
typedef int (*GetHandle)(void *iter);
static GetHandle oGetHandle = nullptr;
typedef int (*HandleResolve)(int guard, int elem);
static HandleResolve oHandleResolve = nullptr;
typedef int (*CtxResolve)(int obj, void *iter);
static CtxResolve oCtxResolve = nullptr;
typedef int (*SexyStringDtor)(void *iter);
static SexyStringDtor oSexyStringDtor = nullptr;
typedef int (*SexyStringCtor)(void *str);
static SexyStringCtor oSexyStringCtor = nullptr;
typedef int (*SexyStringCopy)(void *dst, int src);
static SexyStringCopy oSexyStringCopy = nullptr;
typedef void (*SexyStringAssign)(void *dst, const void *data, int len);
static SexyStringAssign oSexyStringAssign = nullptr;
typedef int (*EntityListBind)(void *out, int props);
static EntityListBind oEntityListBind = nullptr;
typedef int (*RtClassCtor)(void);
static RtClassCtor oRtClassCtor = nullptr;
typedef int (*RegisterClass)(int rt, const char *name, int parent, int ctor);
static RegisterClass oRegisterClass = nullptr;
typedef int (*RegistryGet)(void);
static RegistryGet oRegistryGet = nullptr;
typedef int (*DirGet)(int registry);
static DirGet oDirGet = nullptr;
typedef void (*DirRegisterHandler)(int dir, void *name, int handler, int offset, int zero);
static DirRegisterHandler oDirRegisterHandler = nullptr;
typedef int (*ZombieAnimRigGet)(int a1);
static ZombieAnimRigGet oZombieAnimRigGet = nullptr;

// 弱指针解析链：src = 弱指针所在地址（槽位或拷贝出来的缓冲）
static int resolveWeak(int *src) {
  if (!src)
    return 0;
  int guard = oCtxGet();
  int it[4] = {0};
  oSexyStringParse(it, guard, (int)src);
  int obj = 0;
  if (!oSexyStringEmpty(it)) {
    int e = oGetHandle(it);
    int r = oHandleResolve(guard, e);
    if (r)
      obj = oCtxResolve(r, it);
  }
  oSexyStringDtor(it);
  return obj;
}

// 实体+104 列表首元素即 AnimRig（SexyString 解析模式）
static int getAnimRig(int dino) {
  if (!dino)
    return 0;
  return resolveWeak((int *)(dino + 104));
}

// SexyString 数据指针（A32 12B：头@0 长度@4 指针@8）
static const char *sexyStrPtr(int p) {
  if (!p)
    return "";
  if (*(uint8_t *)p & 1)
    return *(const char **)(p + 8);
  return (const char *)(p + 1);
}

inline void process() {
  if constexpr (CtxGetAddr != UNKNOWN) {
    GeneralFunction::oCtxGet = (GeneralFunction::CtxGet)getActualOffset(CtxGetAddr);
    GeneralFunction::oSexyStringParse =
        (GeneralFunction::SexyStringParse)getActualOffset(SexyStringParseAddr);
    GeneralFunction::oSexyStringEmpty =
        (GeneralFunction::SexyStringEmpty)getActualOffset(SexyStringEmptyAddr);
    GeneralFunction::oGetHandle = (GeneralFunction::GetHandle)getActualOffset(GetHandleAddr);
    GeneralFunction::oHandleResolve =
        (GeneralFunction::HandleResolve)getActualOffset(HandleResolveAddr);
    GeneralFunction::oCtxResolve = (GeneralFunction::CtxResolve)getActualOffset(CtxResolveAddr);
    GeneralFunction::oSexyStringDtor =
        (GeneralFunction::SexyStringDtor)getActualOffset(SexyStringDtorAddr);
    GeneralFunction::oSexyStringCtor =
        (GeneralFunction::SexyStringCtor)getActualOffset(SexyStringCtorAddr);
    GeneralFunction::oSexyStringCopy =
        (GeneralFunction::SexyStringCopy)getActualOffset(SexyStringCopyAddr);
    GeneralFunction::oSexyStringAssign =
        (GeneralFunction::SexyStringAssign)getActualOffset(SexyStringAssignAddr);
    GeneralFunction::oEntityListBind =
        (GeneralFunction::EntityListBind)getActualOffset(EntityListBindAddr);
    GeneralFunction::oRtClassCtor = (GeneralFunction::RtClassCtor)getActualOffset(RtClassCtorAddr);
    GeneralFunction::oRegistryGet = (GeneralFunction::RegistryGet)getActualOffset(RegistryGetAddr);
    GeneralFunction::oDirGet = (GeneralFunction::DirGet)getActualOffset(DirGetAddr);
    GeneralFunction::oZombieAnimRigGet =
        (GeneralFunction::ZombieAnimRigGet)getActualOffset(ZombieAnimRigGetAddr);
  }
}
}  // namespace GeneralFunction

// 火龙草温暖只对 9.x 之前的版本有意义（高版本游戏自带），9.x 起不参与
#if GAME_VERSION < 900

namespace SnapdragonWarming {
// 本 namespace 可用的前置条件：用到的地址（含 GeneralFunction 的）全部已适配
constexpr bool ENABLE =
    SnapdragonLoadAddr != UNKNOWN && WarmingCompFactoryAddr != UNKNOWN &&
    WarmingSetPropsAddr != UNKNOWN && PowerListFindAddr != UNKNOWN &&
    EntityListBindAddr != UNKNOWN && CtxGetAddr != UNKNOWN && SexyStringParseAddr != UNKNOWN &&
    SexyStringEmptyAddr != UNKNOWN && GetHandleAddr != UNKNOWN && HandleResolveAddr != UNKNOWN &&
    CtxResolveAddr != UNKNOWN && SexyStringDtorAddr != UNKNOWN && SexyStringCtorAddr != UNKNOWN &&
    SexyStringCopyAddr != UNKNOWN && SexyStringAssignAddr != UNKNOWN;

// 低版本火龙草（Snapdragon）温暖功能（WarmingRadius）
// 根因：Snapdragon loader（vtable 槽 7）只解析 "BreathBurst"，不解析 WarmingRadius；
// PlantSnapdragon props 也没有 m_warmingRadius 成员（16 字节只有 m_breathBurst@+8）。
// 共享温暖系统完好（Pepperpult 等 9 个植物正常）。
// 修法：hook 后模仿 Pepperpult loader，创建 ComponentWarmingRadius（经附加工厂加入 ctx+44
// 组件列表，与呼吸火柱同机制被驱动），再从 animRig 的 PowerPropsWarmingRadius (type=2)
// 拷配置。注意不把组件弱指针写进 a1+8（那是 m_breathBurst 槽位）；组件已进组件列表，
// 直接用附加工厂的返回值。配置中无此项则跳过。

// ==== 内部函数（ARM32 偏移，经 getActualOffset 解析，o 前缀 = 原函数指针）====
typedef int (*WarmingCompFactory)(int ctx, int mainlist, int name);
static WarmingCompFactory oWarmingCompFactory = nullptr;
typedef int (*WarmingSetProps)(int comp, int props);
static WarmingSetProps oWarmingSetProps = nullptr;
typedef int (*PowerListFind)(void *out, int list, int type, int sub);
static PowerListFind oPowerListFind = nullptr;

typedef int (*SnapdragonLoad)(int a1);
static SnapdragonLoad oSnapdragonLoad = nullptr;

// 遍历列表取第一个解析上下文（模仿 SexyString 解析系列），返回上下文或 0
static int listFirst(int list) {
  int guard = GeneralFunction::oCtxGet();
  int it[4] = {0};
  GeneralFunction::oSexyStringParse(it, guard, list);
  int ctx = 0;
  if (!GeneralFunction::oSexyStringEmpty(it)) {
    int v5 = GeneralFunction::oGetHandle(it);
    int v6 = GeneralFunction::oHandleResolve(guard, v5);
    if (v6)
      ctx = GeneralFunction::oCtxResolve(v6, it);
  }
  GeneralFunction::oSexyStringDtor(it);
  return ctx;
}

int hkSnapdragonLoad(int a1) {
  if (!a1)
    return 0;
  LOGI("[SnapWarm] Load enter a1=%p", (void *)a1);
  // 先执行原函数（BreathBurst 呼吸火柱正常解析，含尾部虚调用）
  int ret = oSnapdragonLoad(a1);
  LOGI("[SnapWarm] OrigLoad done");

  // a1 = PlantSnapdragon；a1+4 = 植物属性表(props)；a1+8 = m_breathBurst 槽（不能写！）
  int props = *(_DWORD *)(a1 + 4);
  if (!props)
    return ret;

  // 1. 取 powers[0] 上下文（组件容器，与原函数 BreathBurst 相同）
  int ctx = listFirst(props + 72);
  if (!ctx)
    return ret;

  // 2. 主属性列表 SexyString（props+8，模仿 Pepperpult loader 的 v36）
  int v36[3] = {0};
  GeneralFunction::oSexyStringCtor(v36);
  GeneralFunction::oSexyStringCopy(v36, props + 8);

  // 3. "WarmingRadius" SexyString（长度 13 超过内联容量 11，引擎内部走堆）
  int name[3] = {0};
  GeneralFunction::oSexyStringAssign(name, "WarmingRadius", sizeof("WarmingRadius") - 1);

  // 4. 创建温暖组件并附加（内部: 名字/列表写入组件 + 初始化/激活 + 加入 ctx+44 列表）
  int comp = oWarmingCompFactory(ctx, (int)v36, (int)name);
  LOGI("[SnapWarm] comp=%p", (void *)comp);

  // 5. 清理 SexyString
  if (name[0] & 1)
    operator delete((void *)name[2]);
  GeneralFunction::oSexyStringDtor(v36);

  if (!comp)
    return ret;

  // 6. 从 props+248 取实体列表，遍历取实体，再按 (type=2, sub=0) 从 animRig powers 找 PowerProps
  int v24 = 0;
  {
    int v30[2] = {0};
    GeneralFunction::oEntityListBind(v30, props);
    int v18 = listFirst((int)v30);

    if (v18) {
      int v31[2] = {0};
      oPowerListFind(v31, v18 + 116, 2, 0);
      v24 = listFirst((int)v31);
      LOGI("[SnapWarm] v24=%p", (void *)v24);
    }

    // 配置字段验证（不调用 IsA 虚函数——vtable 槽 4 不可靠会崩）
    LOGI("[SnapWarm] IsA check");
    if (v24) {
      float radius = *(float *)(v24 + 40);
      LOGI("[SnapWarm] radius=%f", radius);
      if (!(radius > 0.0f && radius < 50.0f))
        v24 = 0;
    }
  }
  LOGI("[SnapWarm] v24b=%p", (void *)v24);

  // 7. 配置里有 WarmingRadius 才拷贝温暖参数（PowerPropsWarmingRadius.WarmingRadius@40）
  if (v24) {
    LOGI("[SnapWarm] SetProps enter r=%f c=%f t=%f d=%f g=%f", *(float *)(v24 + 40),
         *(float *)(v24 + 44), *(float *)(v24 + 48), *(float *)(v24 + 176), *(float *)(v24 + 184));
    oWarmingSetProps(comp, v24 + 40);
    LOGI("[SnapWarm] SetProps done");
    LOGI("[SnapdragonWarm] WarmingRadius applied (comp=%p)", (void *)comp);
  } else {
    LOGI("[SnapdragonWarm] WarmingRadius power not found in config, skip");
  }
  return ret;
}

inline void process() {
  if constexpr (ENABLE) {
    oWarmingCompFactory = (WarmingCompFactory)getActualOffset(WarmingCompFactoryAddr);
    oPowerListFind = (PowerListFind)getActualOffset(PowerListFindAddr);
    oWarmingSetProps = (WarmingSetProps)getActualOffset(WarmingSetPropsAddr);
    PVZ2HookFunction(SnapdragonLoadAddr, (void *)hkSnapdragonLoad, (void **)&oSnapdragonLoad,
                     "Snapdragon::Load");
  }
}

}  // namespace SnapdragonWarming

#endif

namespace AshDeathrattleFix {
// 本 namespace 可用的前置条件（只列入口依赖：vtable 名单是**动态表**，运行时逐条遍历、逐条跳过
// UNKNOWN，不能塞进 constexpr）
constexpr bool ENABLE = ZombieAnimRigGetAddr != UNKNOWN && ZombieAnimPauseAddr != UNKNOWN;

// 化灰亡语修复：僵尸 vtable 槽 183 = 死亡收尾——化灰致命伤害（a2+8 标志 0x840，火/电）后
// 原动画只被渲染禁用、时钟不停，指令帧（扔小鬼/砸植物）照常触发，死后仍执行。
// 修法：化灰时解析 AnimRig 并暂停动画（mPaused=1），特效由伤害系统照常播。
// 1. 巨人基类（5 个 vtable 共享）：hook 槽 183 实现函数
// 2. 继承僵尸（槽 183 = nullsub，不能 hook）：patch 各自 vtable 槽 183 数据
// 加僵尸只补配置表行。

typedef int (*ZombieAnimPause)(int rig, char paused);
static ZombieAnimPause oZombieAnimPause = nullptr;

// ===== 1. 巨人基类：hook 死亡收尾函数（槽 183 实现，5 个巨人 vtable 共享）=====
// 配置表：每僵尸一行（槽 183 死亡收尾函数地址 + 化灰标志掩码）
struct AshDeathrattleEntry {
  size_t deathFuncAddr;   // 槽 183 死亡收尾（hook 点）
  unsigned int ashFlags;  // 化灰标志（a2+8 & ashFlags != 0 = 化灰死亡）
};

constexpr AshDeathrattleEntry kAshEntries[] = {
    {GargantuarDeathAddr, 0x840},  // 巨人基类

    // 新僵尸：{ 槽183死亡收尾函数地址, 化灰标志掩码 }
};
constexpr size_t kAshEntryCount = sizeof(kAshEntries) / sizeof(kAshEntries[0]);
static void *oDeathFuncs[kAshEntryCount];

template <size_t I>
int hkDeath(int a1, int a2) {  // a1 = 僵尸实体, a2 = 伤害对象
  if (a2 && (*(unsigned int *)(a2 + 8) & kAshEntries[I].ashFlags) != 0) {
    int rig = a1 ? GeneralFunction::oZombieAnimRigGet(a1) : 0;
    if (rig) {
      oZombieAnimPause(rig, 1);  // 官方暂停动画（mPaused=1），指令帧不再触发
      LOGI("[AshFix] entry[%d] paused anim on ash death zombie=%p rig=%p", (int)I, (void *)a1,
           (void *)rig);
    }
  }
  return ((int (*)(int, int))oDeathFuncs[I])(a1, a2);
}

template <size_t I>
inline void hookDeathFinishFuncs() {
  if constexpr (I < kAshEntryCount) {
    PVZ2HookFunction(kAshEntries[I].deathFuncAddr, (void *)hkDeath<I>, (void **)&oDeathFuncs[I],
                     "ZombieAshDeath");
    hookDeathFinishFuncs<I + 1>();
  }
}

// ===== 2. 继承自基类：patch vtable 槽 183（nullsub 空函数不能 hook，改 vtable 数据）=====
// 配置表：每僵尸一行（vtable 起始地址 + 化灰标志掩码）
struct AshDeathrattleVtableEntry {
  size_t vtableAddr;      // 僵尸 vtable 起始（槽 183 = 死亡收尾，patch 该槽）
  unsigned int ashFlags;  // 化灰标志（a2+8 & ashFlags != 0 = 化灰死亡）
};

constexpr size_t kDeathSlotOffset = 183 * 4;  // 槽 183（ARM32 指针 4 字节）

constexpr AshDeathrattleVtableEntry kVtableEntries[] = {
    {BullVtableAddr, 0x840},              // ZombieBull
    {ZCorpImpVtableAddr, 0x840},          // ZombieZCorpImp
    {BullVeteranVtableAddr, 0x840},       // ZombieBullVeteran（专属 vtable）
    {DinoBullyVeteranVtableAddr, 0x840},  // ZombieDinoBullyVeteran（专属 vtable）

    // 新僵尸：{ vtable 起始地址, 化灰标志掩码 },
};
constexpr size_t kVtableEntryCount = sizeof(kVtableEntries) / sizeof(kVtableEntries[0]);
static void *oSlotFuncs[kVtableEntryCount];

template <size_t I>
int hkDeathSlot(int a1, int a2) {  // 槽 183 虚调：a1 = 僵尸实体, a2 = 伤害对象
  if (a2 && (*(unsigned int *)(a2 + 8) & kVtableEntries[I].ashFlags) != 0) {
    int rig = a1 ? GeneralFunction::oZombieAnimRigGet(a1) : 0;
    if (rig) {
      oZombieAnimPause(rig, 1);  // 官方暂停动画（mPaused=1），指令帧不再触发
      LOGI("[AshFix] vtbl[%d] paused anim on ash death zombie=%p rig=%p", (int)I, (void *)a1,
           (void *)rig);
    }
  }
  return ((int (*)(int, int))oSlotFuncs[I])(a1, a2);  // 原槽函数（nullsub，空操作）
}

template <size_t I>
inline void patchDeathSlot() {
  if constexpr (I < kVtableEntryCount) {
    size_t vtableActual =
        getActualOffset(kVtableEntries[I].vtableAddr);  // 运行时地址（libBase + 偏移）
    void **slot = (void **)(vtableActual + kDeathSlotOffset);
    oSlotFuncs[I] = *slot;  // 保存原槽函数（nullsub）
    patchVFTable((void *)vtableActual, (void *)hkDeathSlot<I>,
                 183);  // 库自带 vtable patch（内建 mprotect）
    LOGI("[AshFix] patched vtable slot 183 at %p -> %p", (void *)slot, (void *)hkDeathSlot<I>);
    patchDeathSlot<I + 1>();
  }
}

inline void process() {
  if constexpr (ENABLE) {
    oZombieAnimPause = (ZombieAnimPause)getActualOffset(ZombieAnimPauseAddr);
    hookDeathFinishFuncs<0>();  // 巨人基类：hook 死亡收尾函数
    patchDeathSlot<0>();        // 继承自基类：patch vtable 槽 183
  }
}

}  // namespace AshDeathrattleFix

namespace SpringBeanPFInvuln {
// 本 namespace 可用的前置条件：用到的地址全部已适配
constexpr bool ENABLE = IsPlantFoodActiveAddr != UNKNOWN && SpringBeanDieAddr != UNKNOWN &&
                        SpringBeanVtableAddr != UNKNOWN;

// 弹簧豆 PF 期间无敌修复：正常植物槽 81 先查 IsPlantFoodActive（+232 标志），PF 中不死；
// SpringBean 槽 81 无检查直接走死亡汇聚点，PF 期间被秒杀。
// 修法：vtable 槽 81 替换（不碰代码区）。代码 hook 会越界覆盖邻槽函数（槽 81 实现仅 12B）。
typedef int (*IsPlantFoodActive)(int a1);
static IsPlantFoodActive oIsPlantFoodActive = nullptr;
typedef int (*SpringBeanDie)(int entity);
static SpringBeanDie oSpringBeanDie = nullptr;

int hkSpringBeanDie(int entity) {
  if (!entity)
    return 0;
  LOGI("[PFInvuln] SpringBeanDie entity=%p", (void *)entity);
  int container = *(int *)(entity + 4);  // 实体+4 = 容器
  if (oIsPlantFoodActive(container))
    return 0;  // PF 中：跳过死亡处理（不掉血不死，返回 0 = 未执行死亡）
  return oSpringBeanDie(entity);
}

inline void process() {
  if constexpr (ENABLE) {
    oIsPlantFoodActive = (IsPlantFoodActive)getActualOffset(IsPlantFoodActiveAddr);
    oSpringBeanDie = (SpringBeanDie)getActualOffset(SpringBeanDieAddr);
    size_t vtableActual = getActualOffset(SpringBeanVtableAddr);  // vtable 数据实际地址
    patchVFTable((void *)vtableActual, (void *)hkSpringBeanDie, kSpringBeanDieSlot);
    LOGI("[PFInvuln] patched vtable slot %d at %p -> %p", kSpringBeanDieSlot,
         (void *)(vtableActual + kSpringBeanDieSlot * sizeof(void *)), (void *)hkSpringBeanDie);
  }
}

}  // namespace SpringBeanPFInvuln

// skin 装扮搬运只对 9.x 之前的版本有意义（高版本游戏自带），9.x 起不参与
#if GAME_VERSION < 900

namespace CostumeSkinPort {
// 本 namespace 可用的前置条件：用到的地址（含 GeneralFunction 的）全部已适配
constexpr bool ENABLE = CostumeFindItemAddr != UNKNOWN && CostumeGetIdAddr != UNKNOWN &&
                        CostumeAnimRateGetAddr != UNKNOWN && CostumeAnimRateSetAddr != UNKNOWN &&
                        CostumeAnimApplierAddr != UNKNOWN && CostumeSwitchAddr != UNKNOWN &&
                        CostumePreviewCtorAddr != UNKNOWN && HotUIPlantAnimAddr != UNKNOWN &&
                        SexyStringAssignAddr != UNKNOWN;

// 高版本 skin 装扮搬运（低版本上的实现）。
// 目标：skin 装扮时植物改用 CostumeItemType 的 PopAnimName 创建动画对象，而非原生动画。
//
// 方案：CostumeItemType 是 vector 的内联 44B 元素（CostumeID@16 / PlantTypeName@20 /
// LayerName@32），元素构建与搬移用编译期常量步长，结构不能扩、也没地方加新字段，所以
// 不动布局、复用原有 LayerName 字段存标记：值以 "skin:" 开头即 skin 装扮，冒号后是
// PopAnimName（如 "skin:Peashooter_skinA"），普通装扮照旧填层名。不注册新字段的原因：
// 别名 key 会与官方或移植数据里的同名 key 抢同一个槽位。
// 数据侧硬要求：植物数据要列 "LoDCostumes": [装扮ID...]（否则取当前装扮 ID 只会得到 -100），
// skin 动画所在的资源组也要在植物已加载的资源组里。
//
// 机制：a1 = PlantType 系对象，+28 = AnimRigClass（决定建哪个动画类），+40 = PopAnim
// （动画资源名，解析不到有兜底）。skin 即换 +40 的名字串、跑原函数、再还原。
//
// 组成：A skin 分支（改 PopAnim 名字串 + 跑原创建函数），B 图鉴切换重建（切换入口 hook）。

constexpr int kCostumeNameOff = 32;  // LayerName 槽位（ARM32）
#ifdef _DEBUG
constexpr const char *kCostumeSkinRev = __DATE__ " " __TIME__;  // 构建时间戳（仅 Debug）
#endif

// ============ A. skin 分支 ============
typedef int (*CostumeAnimApplier)(int a1, char a2);
static CostumeAnimApplier oCostumeAnimApplier = nullptr;
typedef uint32_t (*CostumeGetId)(int plantName);
static CostumeGetId oCostumeGetId = nullptr;
typedef int (*CostumeFindItem)(uint32_t costumeID);
static CostumeFindItem oCostumeFindItem = nullptr;
constexpr int kCostumeAnimNameOff = 40;  // PlantType::PopAnim（A32；A64 = +80）

// CostumeItemType（44B）：LayerName @32(String)；值以 "skin:" 开头即 skin 装扮
static bool isSkinItem(int item, const char **outAnim) {
  if (!item)
    return false;
  const char *v = GeneralFunction::sexyStrPtr(item + kCostumeNameOff);
  if (!v || strncmp(v, "skin:", 5) != 0 || !v[5])
    return false;
  *outAnim = v + 5;
  return true;
}

// 把配置对象上的 PopAnim 名字串换成 animName，跑原创建函数（名字解析成 PopAnim 资源）后还原
static int createAnimWithName(int a1, char a2, const char *animName) {
  void *nameField = (void *)(a1 + kCostumeAnimNameOff);
  std::string saved(GeneralFunction::sexyStrPtr((int)nameField));
  LOGI("[CostumeSkin] skin '%s' (native PopAnim is '%s')", animName, saved.c_str());
  GeneralFunction::oSexyStringAssign(nameField, animName, (int)strlen(animName));
  int obj = oCostumeAnimApplier(a1, a2);  // 原函数：把该名字解析成 PopAnim 资源再建动画
  GeneralFunction::oSexyStringAssign(nameField, saved.c_str(), (int)saved.size());  // 还原
  return obj;
}

int hkCostumeAnimApplier(int a1, char a2) {
  if (!a1)
    return 0;
  // a1：+4 = 植物名(SexyString)；+28 = AnimRigClass；+40 = PopAnim（动画资源名）
  uint32_t cid = oCostumeGetId(a1 + 4);
  const char *skinAnim = nullptr;
  if (isSkinItem(oCostumeFindItem(cid), &skinAnim)) {
    LOGI("[CostumeSkin] skin apply plant='%s' cid=%u anim='%s'",
         GeneralFunction::sexyStrPtr(a1 + 4), cid, skinAnim);
    return createAnimWithName(a1, a2, skinAnim);
  }
  return oCostumeAnimApplier(a1, a2);  // 非 skin：原逻辑
}

// ============ B. 图鉴切换装扮重建 ============
// 图鉴预览 UI 的切换入口只对已存在的动画对象开关层，不重建动画对象；所以切到
// skin 装扮时要补一次重建（含从 skin 切回普通装扮的反向重建）。
typedef void (*CostumeSwitch)(int self);
static CostumeSwitch oCostumeSwitch = nullptr;
typedef float (*CostumeAnimRateGet)(int animObj);
static CostumeAnimRateGet oCostumeAnimRateGet = nullptr;
typedef void (*CostumeAnimRateSet)(int animObj, float rate);
static CostumeAnimRateSet oCostumeAnimRateSet = nullptr;
constexpr int kCostumeAnimFinishSlot =
    184;  // 预览 ctor 建完动画后调用的虚表槽（A32 槽 46 × 4 字节）

// ============ 卡片 box 覆盖表（skin 装扮在图鉴/选卡预览里的定位用）============
// 卡片上的 box（4 个 int）：绘制动画时按它把内容居中放进卡片。它由卡片布局按
// 当时的动画算出，所以显示 skin（套用别的植物的动画）时与卡片尺寸不同源，预览位置偏移。
// 该值只与植物和原装扮绑定、稳定不变，直接查表覆盖。
// （A64 动画对象槽 +272 / box +280；A32 动画对象槽 +200 / box +204。）
//
// 添加植物：表里没有的不会被覆盖。请自行用 Debug 配置编译，在原装扮状态下进一次
// 图鉴/选卡，从日志读取 "[CostumeSkin] box plant='…' skin=0 = [a b c d]" 的四个数，填进下表即可。
// 嫌繁琐也可以不加：代价仅是图鉴/选卡预览偏，不影响关卡内显示。
constexpr int kCardBoxOff = 204;

struct CostumeBoxEntry {
  const char *plantName;
  int v[4];
};
constexpr CostumeBoxEntry kCostumeBoxes[] = {
    {"sunflower", {245, 183, 204, 245}},  {"kernelpult", {131, 166, 323, 237}},
    {"banana", {201, 129, 197, 274}},     {"primalsunflower", {205, 147, 267, 280}},
    {"moonflower", {203, 119, 204, 251}},
};
constexpr size_t kCostumeBoxCount = sizeof(kCostumeBoxes) / sizeof(kCostumeBoxes[0]);

static void applyCostumeBox(int card) {
  if (!card)
    return;
  int entity = *(int *)(card + 136);
  const char *plantName = entity ? GeneralFunction::sexyStrPtr(entity + 4) : nullptr;
  if (!plantName)
    return;
  for (size_t i = 0; i < kCostumeBoxCount; i++) {
    if (kCostumeBoxes[i].plantName && strcmp(kCostumeBoxes[i].plantName, plantName) == 0) {
      memcpy((void *)(card + kCardBoxOff), kCostumeBoxes[i].v, sizeof(kCostumeBoxes[i].v));
      return;
    }
  }
}

// 卡片 ctor 之后：按植物查到 box 就覆盖（进图鉴时已是 skin 的情况靠这一步）
typedef void (*CostumePreviewCtor)(int card, int entity, char flag);
static CostumePreviewCtor oCostumePreviewCtor = nullptr;

void hkCostumePreviewCtor(int card, int entity, char flag) {
  if (!card)
    return;
  oCostumePreviewCtor(card, entity, flag);
#ifdef _DEBUG
  const int *b = (const int *)(card + kCardBoxOff);
  const char *plantName = entity ? GeneralFunction::sexyStrPtr(entity + 4) : nullptr;
  const char *skinAnim = nullptr;
  int skin = 0;
  if (plantName) {
    uint32_t cid = oCostumeGetId(entity + 4);
    skin = isSkinItem(oCostumeFindItem(cid), &skinAnim) ? 1 : 0;
  }
  LOGI("[CostumeSkin] box plant='%s' skin=%d = [%d %d %d %d]", plantName ? plantName : "?", skin,
       b[0], b[1], b[2], b[3]);
#endif
  applyCostumeBox(card);
}

// 预览 ctor 建完动画后的收尾：虚表槽 + 速率 = 动画速率 × 实体速度系数@+120。
// 少这步时新对象速率为 0，动画不推进，控件按空包围盒塌到画面左上角。
static void finishPreviewAnim(int obj, int entity) {
  (*(void (**)(int))(*(int *)obj + kCostumeAnimFinishSlot))(obj);
  oCostumeAnimRateSet(obj, oCostumeAnimRateGet(obj) * *(float *)(entity + 120));
}

void hkCostumeSwitch(int self) {
  if (!self)
    return;
  oCostumeSwitch(self);
  int entity = *(int *)(self + 136);  // 预览对象：+136 = 植物实体，+200 = 动画对象
  if (!entity)
    return;
  uint32_t cid = oCostumeGetId(entity + 4);
  const char *skinAnim = nullptr;
  bool skin = isSkinItem(oCostumeFindItem(cid), &skinAnim);
  // 原函数只对旧对象开关层、不换动画，切换后一律重建（applier 内部会按当前装扮 ID 应用层）
  int obj = skin ? createAnimWithName(entity, 1, skinAnim) : oCostumeAnimApplier(entity, 1);
  if (!obj)
    return;                    // 创建失败：保留原动画对象
  *(int *)(self + 200) = obj;  // 旧动画对象不释放（可能仍被场景引用，宁可泄漏）
  applyCostumeBox(self);       // box 按植物查表覆盖（skin 动画的 box 与卡片尺寸不同源，会偏）
  finishPreviewAnim(obj, entity);
  LOGI("[CostumeSkin] almanac switch plant='%s' cid=%u skin=%d anim='%s'",
       GeneralFunction::sexyStrPtr(entity + 4), cid, (int)skin, skin ? skinAnim : "(native)");
}

// ============ H. 商店 HotUI 植物动画：按名字建动画的预览 ============
// 该函数按控件 +436（植物名）查到的配置对象的 PopAnim 名（+40）新建动画对象（存 +388），
// 再用 +448（装扮 LayerName）开层。动画由该名字决定，所以在跑原函数之前把配置对象的名字换成
// skin 名，建出来的就是 skin 动画。
// 注意：别去写 +388（动画对象），它是该函数自己的产物（手写会被覆盖）。
typedef void (*HotUIPlantAnim)(int self);
static HotUIPlantAnim oHotUIPlantAnim = nullptr;

void hkHotUIPlantAnim(int self) {
  if (self) {
    const char *layer = GeneralFunction::sexyStrPtr(self + kHotUiLayerNameOff);
    if (layer && strncmp(layer, "skin:", 5) == 0 && layer[5]) {
      const char *skinAnim = layer + 5;
      int cfg = GeneralFunction::resolveWeak((int *)(self + kHotUiPlantNameOff));
      if (cfg) {
        void *nameField = (void *)(cfg + kCostumeAnimNameOff);
        std::string saved(GeneralFunction::sexyStrPtr((int)nameField));
        GeneralFunction::oSexyStringAssign(nameField, skinAnim, (int)strlen(skinAnim));
        oHotUIPlantAnim(self);  // 原函数：拷名字，按名字建动画、开层
        GeneralFunction::oSexyStringAssign(nameField, saved.c_str(), (int)saved.size());  // 还原
        LOGI("[CostumeSkin] hotUI skin '%s' (native PopAnim is '%s')", skinAnim, saved.c_str());
        return;
      }
    }
  }
  oHotUIPlantAnim(self);
}

inline void process() {
  if constexpr (ENABLE) {
    oCostumeAnimApplier = (CostumeAnimApplier)getActualOffset(CostumeAnimApplierAddr);
    oCostumeFindItem = (CostumeFindItem)getActualOffset(CostumeFindItemAddr);
    oCostumeAnimRateGet = (CostumeAnimRateGet)getActualOffset(CostumeAnimRateGetAddr);
    oCostumeAnimRateSet = (CostumeAnimRateSet)getActualOffset(CostumeAnimRateSetAddr);
    oCostumeGetId = (CostumeGetId)getActualOffset(CostumeGetIdAddr);
    oHotUIPlantAnim = (HotUIPlantAnim)getActualOffset(HotUIPlantAnimAddr);
    // A：skin 分支 hook（动画创建时改用 PopAnimName）
    PVZ2HookFunction(CostumeAnimApplierAddr, (void *)hkCostumeAnimApplier,
                     (void **)&oCostumeAnimApplier, "CostumeAnimApplier");
    // B：图鉴切换重建 hook
    PVZ2HookFunction(CostumeSwitchAddr, (void *)hkCostumeSwitch, (void **)&oCostumeSwitch,
                     "CostumeSwitch");
    // H：商店 HotUI 植物动画（动画按配置对象的名字建，换名即可）
    PVZ2HookFunction(HotUIPlantAnimAddr, (void *)hkHotUIPlantAnim, (void **)&oHotUIPlantAnim,
                     "HotUIPlantAnim");
    // C：卡片 ctor 之后按植物覆盖 box（修进图鉴时已是 skin 的偏移）
    PVZ2HookFunction(CostumePreviewCtorAddr, (void *)hkCostumePreviewCtor,
                     (void **)&oCostumePreviewCtor, "CostumePreviewCtor");
#ifdef _DEBUG
    LOGI("[CostumeSkin] hooks installed @ %s", kCostumeSkinRev);
#else
    LOGI("[CostumeSkin] hooks installed");
#endif
  }
}

}  // namespace CostumeSkinPort

#endif

__attribute__((constructor)) void libRestructedLogic_ARM32__main() {
  LOGI("Initializing %s", LIB_TAG);

  GeneralFunction::process();  // 通用工具（SexyString/类型系统等）——最前（无条件）
  HookResourceManagerFunc::process();
  DirectInstallOBB::process();  // 直装包
#if GAME_VERSION < 1031
  AliasToID::process();  // 添加植物 ID
#endif
#ifdef _DEBUG
  LogOutput::process();     // 输出日志
  CDNExpansion::process();  // 自定义 CDN 列表
#endif
  RSBDecrypt::process();                 // RSB 加密
  PrimeGlyphCacheLimitation::process();  // 修改字符缓冲区大小
  MaxZoom::process();                    // 高视角
  WorldMapVerticalScrolling::process();  // 地图垂直移动
  EnableDangerRoomRestart::process();    // 无尽开放RESTART按钮
  DisableAlmanacTutorial::process();     // 禁用图鉴教程（前半段+后半段）
#if GAME_VERSION < 900
  SnapdragonWarming::process();  // 火龙草温暖
#endif
  AshDeathrattleFix::process();   // 化灰亡语修复（化灰死亡时停原动画时钟）
  SpringBeanPFInvuln::process();  // 弹簧豆 PF 期间无敌修复（补设 props+232 PF 标志）
#if GAME_VERSION < 900
  CostumeSkinPort::process();  // skin 装扮搬运（skin 分支 + 图鉴切换重建）
#endif

  LOGI("Finished initializing");
}
