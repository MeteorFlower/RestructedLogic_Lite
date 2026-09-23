#include "memUtils.hpp"
#include "Unzip/ApkUnzipper.hpp"
#include "Unzip/HashComparer.hpp"
#include "AXML/axml_parser.hpp"
#include "Decrypt/picosha2.hpp"
#include "Decrypt/aes.hpp"
#include "tinyxml2/tinyxml2.h"
#include "SexyTypes.hpp"
#include "RestructedLogic_ARM64_.hpp"
#include "VersionSwitcher.hpp"

using _DWORD = uint32_t;
using __int64 = int64_t;
using _BYTE = uint8_t;
using _QWORD = uint64_t;

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

// LawnAppScreenWidthHeight 的原函数会随版本变化。目前只适配了一种写法，其他版本欢迎补充。
typedef __int64 (*LawnAppScreenWidthHeight)(__int64 a1, int a2);
static LawnAppScreenWidthHeight oLawnAppScreenWidthHeight = nullptr;

__int64 hkLawnAppScreenWidthHeight(__int64 a1, int a2) {
  // 1. 先执行原函数，让内部逻辑完成内存写入
  __int64 result = oLawnAppScreenWidthHeight(a1, a2);

  if (a1 == NULL)
    return result;

  // 2. 根据偏移直接提取数据
#if GAME_VERSION == 1031

  // 10.3：分辨率 172/176，原始屏幕尺寸 1780/1784
#ifdef _DEBUG
  mOrigScreenWidth = *(unsigned int *)(a1 + 1780);
#endif
  mOrigScreenHeight = *(unsigned int *)(a1 + 1784);

  mWidth = *(unsigned int *)(a1 + 172);
#ifdef _DEBUG
  mHeight = *(unsigned int *)(a1 + 176);
#endif

#else

  // 8.7.3：分辨率 244/248，原始屏幕尺寸 1860/1864
#ifdef _DEBUG
  mOrigScreenWidth = *(unsigned int *)(a1 + 1860);
#endif
  mOrigScreenHeight = *(unsigned int *)(a1 + 1864);

  mWidth = *(unsigned int *)(a1 + 244);
#ifdef _DEBUG
  mHeight = *(unsigned int *)(a1 + 248);
#endif

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

typedef __int64 (*BoardZoom)(__int64 a1);
static BoardZoom oBoardZoom = nullptr;

__int64 hkBoardZoom(__int64 a1) {
  if (!a1)
    return 0;
  // 先跑原函数
  __int64 result = oBoardZoom(a1);
  // 改变选卡时视野左边缘与棋盘左边缘的距离
  if (readMaxZoomButton())
    *(_DWORD *)(a1 + 1140) = preGameRightLine - mWidth;
  // 高度无法调整，只能靠缩放
  return result;
}

typedef void (*BoardZoom2)(__int64 a1);
static BoardZoom2 oBoardZoom2 = nullptr;

void hkBoardZoom2(__int64 a1) {
  if (!a1)
    return;
  oBoardZoom2(a1);
  if (readMaxZoomButton()) {
    // 缩放系数
    *(float *)(a1 + 1120) = 1.0f;
    // 改变视野左边缘与棋盘左边缘的距离
    *(_DWORD *)(a1 + 1080) = -(gameStartRightLine - mWidth);
    // 顶部基准线
    *(_DWORD *)(a1 + 1128) = (_DWORD)mOrigScreenHeight;
  }
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

typedef int (*CDNExpand)(__int64 a1, const Sexy::SexyString &rtonName, int rtonTable, int a4);
static CDNExpand oCDNLoad = nullptr;

std::atomic<bool> executed(false);

int hkCDNLoad(__int64 a1, const Sexy::SexyString &rtonName, int rtonTable, int a4) {
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
constexpr bool ENABLE = RSBPathRecorderAddr != UNKNOWN;

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
typedef void *(*RSBPathRecorder)(_QWORD *a1);
static RSBPathRecorder oRSBPathRecorder = nullptr;

// 调用原函数的外壳
__attribute__((naked)) void *oRSBPathRecorderShell(_QWORD *a1) {
  __asm__ volatile(
      // 保存 x29, x30 并分配 16 字节栈空间（此时 sp 已减 16）
      "stp x29, x30, [sp, #-16]!\n"

      // 参数传递：将 x0（参数）移到 x8
      "mov x8, x0\n"

      // 加载原函数地址并调用
      "ldr x16, %0\n"
      "blr x16\n"

      // 恢复 x29, x30 并释放最后 16 字节
      "ldp x29, x30, [sp], #16\n"

      "ret\n"
      :
      : "m"(oRSBPathRecorder)
      : "x0", "x8", "x16", "x29", "x30", "memory");
}

void *hkRSBPathRecorder(_QWORD *a1) {
  LOGI("Hooking RSBPathRecorder");
  if (!a1) {
    LOGI("RSBPathRecorder: a1 is null");
    return oRSBPathRecorderShell(a1);
  }

  // 调用原始函数
  void *result = oRSBPathRecorderShell(a1);
  LOGI("RSBPathRecorder: Original function returned %lld, a1[0]=0x%x, a1[1]=0x%x, a1[2]=0x%x",
       result, a1[0], a1[1], a1[2]);

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

      const size_t CHUNK_SIZE = 256 * 1024 * 1024;  // 256MB，平衡内存压力与效率
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

static RSBPathRecorder hkRSBPathRecorder_ptr = &hkRSBPathRecorder;
// 拦截函数外壳
__attribute__((naked)) void *hkRSBPathRecorderShell(void) {
  __asm__ volatile(
      // 保存 x29, x30 并分配 16 字节栈空间（此时 sp 已减 16）
      "stp x29, x30, [sp, #-16]!\n"

      // 参数传递：将原函数参数从 x8 移到 x0
      "mov x0, x8\n"

      // 加载 C 函数地址并调用
      "ldr x16, %0\n"
      "blr x16\n"

      // 恢复 x29, x30 并释放最后 16 字节
      "ldp x29, x30, [sp], #16\n"

      "ret\n"
      :
      : "m"(hkRSBPathRecorder_ptr)
      : "x0", "x8", "x16", "x29", "x30", "memory");
}

inline void process() {
  if constexpr (ENABLE) {
    // Hook RSB 读取函数
    PVZ2HookFunction(RSBPathRecorderAddr, (void *)hkRSBPathRecorderShell,
                     (void **)&oRSBPathRecorder, "ResourceManager::RSBPathRecorder");
  }
}
}  // namespace RSBDecrypt

namespace PrimeGlyphCacheLimitation {
// 本 namespace 可用的前置条件：用到的地址全部已适配
constexpr bool ENABLE = PrimeGlyphCacheAddr != UNKNOWN;

// 一路：高端设备缓冲大小为2048，中端设备为1024，低端设备为512。经过测试，缓冲大小最大只能设为2048，设为更高值，会导致进入游戏后文字渲染全为空白，这与设为0的效果一致。
typedef __int64 (*PrimeGlyphCacheLimitation)(__int64 a1, __int64 a2, __int64 a3, int a4);
static PrimeGlyphCacheLimitation oPrimeGlyphCacheLimitation = nullptr;

__int64 hkPrimeGlyphCacheLimitation(__int64 a1, __int64 a2, __int64 a3, int a4) {
  __int64 result = oPrimeGlyphCacheLimitation(a1, a2, a3, a4);
  *(_DWORD *)(a1 + 164) = 2048;
  LOGI("Hooked PrimeGlyphCacheLimitation: Modified a1 + 164 to %d", *(_DWORD *)(a1 + 164));
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
typedef __int64 (*WorldMapScroll)(__int64 a1, __int64 a2);
static WorldMapScroll oWorldMapScroll = nullptr;

__int64 hkWorldMapScroll(__int64 a1, __int64 a2) {
  *(int32_t *)(a1 + 512) = -1000000000;
  *(int32_t *)(a1 + 516) = -1000000000;
  *(int32_t *)(a1 + 520) = 2000000000;
  *(int32_t *)(a1 + 524) = 2000000000;
  return oWorldMapScroll(a1, a2);
}

// 居中函数：
typedef __int64 (*KeepCenter)(__int64 a1, float *a2, char a3);
static KeepCenter oKeepCenter = nullptr;

__int64 hkKeepCenter(__int64 a1, float *a2, char a3) {
  *(int32_t *)(a1 + 512) = -1000000000;
  *(int32_t *)(a1 + 516) = -1000000000;
  *(int32_t *)(a1 + 520) = 2000000000;
  *(int32_t *)(a1 + 524) = 2000000000;
  return oKeepCenter(a1, a2, true);
}

// 惯性函数：
typedef void (*ScrollInertance)(__int64 a1);
static ScrollInertance oScrollInertance = nullptr;

void hkScrollInertance(__int64 a1) {
  *(int32_t *)(a1 + 512) = -1000000000;
  *(int32_t *)(a1 + 516) = -1000000000;
  *(int32_t *)(a1 + 520) = 2000000000;
  *(int32_t *)(a1 + 524) = 2000000000;
  oScrollInertance(a1);
}

#else

// 旧函数（10.0版本前有效）
typedef int (*WorldMapDoMovement)(void *map, float fX, float fY, bool allowVerticalMovement);
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
typedef void (*ResourceManagerFunc)(__int64 a1, char a2, int a3);
static ResourceManagerFunc oResourceManagerFunc = nullptr;

void hkResourceManagerFunc(__int64 a1, char a2, int a3) {
  LOGI("ResourceManagerFunc hook entered.");

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

  LOGI("ResourceManagerFunc hook done.");
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

typedef void (*ShowPauseMenu)(int64_t a1, char a2, char a3, int64_t a4, unsigned int a5);
static ShowPauseMenu oShowPauseMenu = nullptr;

void hkShowPauseMenu(int64_t a1, char a2, char a3, int64_t a4, unsigned int a5) {
  oShowPauseMenu(a1, a2, a3, 0, a5);
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
typedef void (*AlmanacStateUpdate)(int64_t a1, int state);
static AlmanacStateUpdate oAlmanacStateUpdate = nullptr;

void hkAlmanacStateUpdate(int64_t a1, int state) {
  if (state > 1)
    state = 1;
  oAlmanacStateUpdate(a1, state);
}

// Hook 2: 阻止教程检查
typedef void (*TutorialCheck)(uint64_t context);
static TutorialCheck oTutorialCheck = nullptr;

// 壳：调用原函数（X0=context，X1=resultBuf 搬入 X8）
__attribute__((naked)) void oTutorialCheckShell(uint64_t context, void *resultBuf) {
  __asm__ volatile(
      "stp x29, x30, [sp, #-16]!\n"
      "mov x8, x1\n"
      "ldr x16, %0\n"
      "blr x16\n"
      "ldp x29, x30, [sp], #16\n"
      "ret\n"
      :
      : "m"(oTutorialCheck)
      : "x0", "x1", "x8", "x16", "x29", "x30", "memory");
}

// Hook 实际逻辑: 调用原函数后在 resultBuf 里清除
void hkTutorialCheck(uint64_t context, void *resultBuf) {
  oTutorialCheckShell(context, resultBuf);
  if (resultBuf)
    *(char *)resultBuf = 0;
}

void (*hkTutorialCheck_ptr)(uint64_t, void *) = &hkTutorialCheck;

// 桥接壳：X8（原 caller 传入的 resultBuf）搬入 X1（hook 的第 2 参数）
__attribute__((naked)) void hkTutorialCheckShell(void) {
  __asm__ volatile(
      "stp x29, x30, [sp, #-16]!\n"
      "mov x1, x8\n"
      "ldr x16, %0\n"
      "blr x16\n"
      "ldp x29, x30, [sp], #16\n"
      "ret\n"
      :
      : "m"(hkTutorialCheck_ptr)
      : "x0", "x1", "x8", "x16", "x29", "x30", "memory");
}

// Hook 3: 阻止教程对话播放
typedef void (*NarrativeCheck)(uint64_t key);
static NarrativeCheck oNarrativeCheck = nullptr;

__attribute__((naked)) void oNarrativeCheckShell(uint64_t key, void *resultBuf) {
  __asm__ volatile(
      "stp x29, x30, [sp, #-16]!\n"
      "mov x8, x1\n"
      "ldr x16, %0\n"
      "blr x16\n"
      "ldp x29, x30, [sp], #16\n"
      "ret\n"
      :
      : "m"(oNarrativeCheck)
      : "x0", "x1", "x8", "x16", "x29", "x30", "memory");
}

void hkNarrativeCheck(uint64_t key, void *resultBuf) {
  oNarrativeCheckShell(key, resultBuf);
  if (resultBuf)
    *(char *)resultBuf = 0;
}

void (*hkNarrativeCheck_ptr)(uint64_t, void *) = &hkNarrativeCheck;

__attribute__((naked)) void hkNarrativeCheckShell(void) {
  __asm__ volatile(
      "stp x29, x30, [sp, #-16]!\n"
      "mov x1, x8\n"
      "ldr x16, %0\n"
      "blr x16\n"
      "ldp x29, x30, [sp], #16\n"
      "ret\n"
      :
      : "m"(hkNarrativeCheck_ptr)
      : "x0", "x1", "x8", "x16", "x29", "x30", "memory");
}

inline void process() {
  if constexpr (ENABLE) {
    PVZ2HookFunction(AlmanacStateUpdateAddr, (void *)hkAlmanacStateUpdate,
                     (void **)&oAlmanacStateUpdate, "AlmanacStateUpdate");
    PVZ2HookFunction(TutorialCheckAddr, (void *)hkTutorialCheckShell, (void **)&oTutorialCheck,
                     "TutorialCheck");
    PVZ2HookFunction(NarrativeCheckAddr, (void *)hkNarrativeCheckShell, (void **)&oNarrativeCheck,
                     "NarrativeCheck");
  }
}
}  // namespace DisableAlmanacTutorial

namespace GeneralFunction {
// 通用工具函数

typedef __int64 (*RtWeakPtrDtor)(void *a1);
static RtWeakPtrDtor oRtWeakPtrDtor = nullptr;
typedef __int64 (*RtClassContext)(void);
static RtClassContext oRtClassContext = nullptr;
static void *oRtWeakPtrBind = nullptr;  // __usercall(X0=上下文, X1=源弱指针, X8=输出)
typedef __int64 (*RtWeakPtrValid)(void *a1);
static RtWeakPtrValid oRtWeakPtrValid = nullptr;
typedef __int64 (*RtWeakPtrHandle)(void *a1);
static RtWeakPtrHandle oRtWeakPtrHandle = nullptr;
typedef __int64 (*RtWeakPtrResolve)(__int64 a1, int a2);
static RtWeakPtrResolve oRtWeakPtrResolve = nullptr;
typedef __int64 (*RtWeakPtrGet)(__int64 a1, void *a2);
static RtWeakPtrGet oRtWeakPtrGet = nullptr;
typedef __int64 (*RtWeakPtrCtor)(void *a1);
static RtWeakPtrCtor oRtWeakPtrCtor = nullptr;
typedef __int64 (*RtWeakPtrCopy)(void *a1, __int64 a2);
static RtWeakPtrCopy oRtWeakPtrCopy = nullptr;
typedef __int64 (*RtClassCtor)(void);
static RtClassCtor oRtClassCtor = nullptr;
typedef void (*RegisterClass)(__int64 rt, const char *name, __int64 parent, __int64 ctor);
static RegisterClass oRegisterClass = nullptr;
typedef __int64 (*RegistryGet)(void);
static RegistryGet oRegistryGet = nullptr;
typedef __int64 (*DirGet)(__int64 registry);
static DirGet oDirGet = nullptr;
typedef __int64 (*DirRegisterHandler)(__int64 dir, void *name, __int64 handler, __int64 offset,
                                      __int64 zero);
static DirRegisterHandler oDirRegisterHandler = nullptr;
typedef void (*SexyStringAssign)(void *dst, const void *data, size_t len);
static SexyStringAssign oSexyStringAssign = nullptr;
typedef __int64 (*GetAnimRig)(__int64 dino);
static GetAnimRig oGetAnimRig = nullptr;
typedef __int64 (*ZombieAnimRigGet)(__int64 a1);
static ZombieAnimRigGet oZombieAnimRigGet = nullptr;

// 调用壳：X2（第 3 参，输出弱指针）搬入 X8
__attribute__((naked)) void oRtWeakPtrBindShell(__int64 ctx, void *src, void *out) {
  __asm__ volatile(
      "stp x29, x30, [sp, #-16]!\n"
      "mov x8, x2\n"
      "ldr x16, %0\n"
      "blr x16\n"
      "ldp x29, x30, [sp], #16\n"
      "ret\n"
      :
      : "m"(oRtWeakPtrBind)
      : "x0", "x1", "x2", "x8", "x16", "x29", "x30", "memory");
}

// 从弱指针缓冲解析对象（RtWeakPtr 取回序列）
// src = 源弱指针所在地址（槽位或 __usercall 输出缓冲）
static __int64 weakResolve(void *src) {
  if (!src)
    return 0;
  __int64 ctx = oRtClassContext();  // RtTypeRegistry 全局单例
  uint64_t w[2] = {0};
  oRtWeakPtrBindShell(ctx, src, w);  // X0=ctx, X1=src, X8=out
  __int64 obj = 0;
  if (!(oRtWeakPtrValid(w) & 1)) {
    int h = oRtWeakPtrHandle(w);
    __int64 p = oRtWeakPtrResolve(ctx, h);
    if (p)
      obj = oRtWeakPtrGet(p, w);
  }
  oRtWeakPtrDtor(w);
  return obj;
}

// SexyString 数据指针（A64 24B：头@0 长度@8 指针@16）
static const char *sexyStrPtr(uint64_t p) {
  if (!p)
    return "";
  if (*(uint8_t *)p & 1)
    return *(const char **)(p + 16);
  return (const char *)(p + 1);
}

inline void process() {
  if constexpr (RtWeakPtrDtorAddr != UNKNOWN) {
    GeneralFunction::oRtWeakPtrDtor =
        (GeneralFunction::RtWeakPtrDtor)getActualOffset(RtWeakPtrDtorAddr);
    GeneralFunction::oRtClassContext =
        (GeneralFunction::RtClassContext)getActualOffset(RtClassContextAddr);
    GeneralFunction::oRtWeakPtrBind = (void *)getActualOffset(RtWeakPtrBindAddr);
    GeneralFunction::oRtWeakPtrValid =
        (GeneralFunction::RtWeakPtrValid)getActualOffset(RtWeakPtrValidAddr);
    GeneralFunction::oRtWeakPtrHandle =
        (GeneralFunction::RtWeakPtrHandle)getActualOffset(RtWeakPtrHandleAddr);
    GeneralFunction::oRtWeakPtrResolve =
        (GeneralFunction::RtWeakPtrResolve)getActualOffset(RtWeakPtrResolveAddr);
    GeneralFunction::oRtWeakPtrGet =
        (GeneralFunction::RtWeakPtrGet)getActualOffset(RtWeakPtrGetAddr);
    GeneralFunction::oRtWeakPtrCtor =
        (GeneralFunction::RtWeakPtrCtor)getActualOffset(RtWeakPtrCtorAddr);
    GeneralFunction::oRtWeakPtrCopy =
        (GeneralFunction::RtWeakPtrCopy)getActualOffset(RtWeakPtrCopyAddr);
    GeneralFunction::oRtClassCtor = (GeneralFunction::RtClassCtor)getActualOffset(RtClassCtorAddr);
    GeneralFunction::oRegisterClass =
        (GeneralFunction::RegisterClass)getActualOffset(RegisterClassAddr);
    GeneralFunction::oRegistryGet = (GeneralFunction::RegistryGet)getActualOffset(RegistryGetAddr);
    GeneralFunction::oDirGet = (GeneralFunction::DirGet)getActualOffset(DirGetAddr);
    GeneralFunction::oDirRegisterHandler =
        (GeneralFunction::DirRegisterHandler)getActualOffset(DirRegisterHandlerAddr);
    GeneralFunction::oGetAnimRig = (GeneralFunction::GetAnimRig)getActualOffset(AnimRigGetAddr);
    GeneralFunction::oZombieAnimRigGet =
        (GeneralFunction::ZombieAnimRigGet)getActualOffset(ZombieAnimRigGetAddr);
    GeneralFunction::oSexyStringAssign =
        (GeneralFunction::SexyStringAssign)getActualOffset(SexyStringAssignAddr);
  }
}
}  // namespace GeneralFunction

// 火龙草温暖只对 9.x 之前的版本有意义（高版本游戏自带），9.x 起不参与
#if GAME_VERSION < 900

namespace SnapdragonWarming {
// 本 namespace 可用的前置条件：用到的地址（含 GeneralFunction 的）全部已适配
constexpr bool ENABLE = PropsContextAddr != UNKNOWN && PropsPowersBindAddr != UNKNOWN &&
                        PowerListFindAddr != UNKNOWN && WarmingCompFactoryAddr != UNKNOWN &&
                        WarmingSetPropsAddr != UNKNOWN && SnapdragonInitAddr != UNKNOWN &&
                        RtWeakPtrDtorAddr != UNKNOWN && RtWeakPtrCtorAddr != UNKNOWN &&
                        RtWeakPtrCopyAddr != UNKNOWN && SexyStringAssignAddr != UNKNOWN;

// 低版本火龙草（Snapdragon）温暖功能（WarmingRadius）
// 根因：Snapdragon init 只附加 BreathBurst，不解析 WarmingRadius（类无对应成员、解析器也不
// 注册温暖属性）；共享温暖系统本身完好（Pepperpult 等 9 个植物正常）。
// 修法：hook init 后模仿 Pepperpult，创建 ComponentWarmingRadius（复用附加工厂，组件自动
// 加入 ctx+64 组件列表被驱动），并从 animRig 的 PowerPropsWarmingRadius (type=2) 拷配置；
// 配置中无此项则跳过（保持原行为）。

// ==== 内部函数（偏移经 getActualOffset 解析，o 前缀 = 原函数指针）====
typedef __int64 (*PropsContext)(__int64 a1);
static PropsContext oPropsContext = nullptr;
static void *oPropsPowersBind = nullptr;  // __usercall(X0=props, X8=out)，绑定 props+272
static void *oPowerListFind = nullptr;    // __usercall(X0=list, W1=type, W2=sub, X8=out)
typedef __int64 (*WarmingCompFactory)(__int64 a1, __int64 a2, void *a3);
static WarmingCompFactory oWarmingCompFactory = nullptr;
typedef __int64 (*WarmingSetProps)(__int64 a1, __int64 a2);
static WarmingSetProps oWarmingSetProps = nullptr;

// 调用壳：X1（第 2 参，输出缓冲）搬入 X8
__attribute__((naked)) void oPropsPowersBindShell(__int64 props, void *out) {
  __asm__ volatile(
      "stp x29, x30, [sp, #-16]!\n"
      "mov x8, x1\n"
      "ldr x16, %0\n"
      "blr x16\n"
      "ldp x29, x30, [sp], #16\n"
      "ret\n"
      :
      : "m"(oPropsPowersBind)
      : "x0", "x1", "x8", "x16", "x29", "x30", "memory");
}

// 调用壳：X3（第 4 参，输出缓冲）搬入 X8
__attribute__((naked)) void oPowerListFindShell(__int64 list, int type, int subtype, void *out) {
  __asm__ volatile(
      "stp x29, x30, [sp, #-16]!\n"
      "mov x8, x3\n"
      "ldr x16, %0\n"
      "blr x16\n"
      "ldp x29, x30, [sp], #16\n"
      "ret\n"
      :
      : "m"(oPowerListFind)
      : "x0", "x1", "x2", "x3", "x8", "x16", "x29", "x30", "memory");
}

typedef __int64 (*SnapdragonInit)(__int64 a1);
static SnapdragonInit oSnapdragonInit = nullptr;

__int64 hkSnapdragonInit(__int64 a1) {
  if (!a1)
    return 0;
  LOGI("[SnapWarm] Init enter a1=%p", (void *)a1);
  // 先执行原函数（BreathBurst 呼吸火柱正常附加，含尾部虚调用）
  __int64 ret = oSnapdragonInit(a1);
  LOGI("[SnapWarm] OrigInit done");

  // a1 = PlantSnapdragon；a1+8 = 植物属性表(props)；a1+16 = m_breathBurst 槽（不能写）
  __int64 props = *(__int64 *)(a1 + 8);
  if (!props)
    return ret;
#ifdef _DEBUG
  LOGI("[SnapWarm] props=%p pvt=%p p272=%p", (void *)props, (void *)*(__int64 *)props,
       (void *)*(__int64 *)(props + 272));
#endif

  // 1. 取 powers 上下文（组件容器 owner，与原函数相同方式）
  __int64 ctx = oPropsContext(props);
  LOGI("[SnapWarm] ctx=%p", (void *)ctx);
  if (!ctx)
    return ret;

  // 2. 构造弱指针链（props+8 处为实体组件列表引用）
  uint64_t w32[2] = {0}, w33[2] = {0};
  GeneralFunction::oRtWeakPtrCtor(w32);
  GeneralFunction::oRtWeakPtrCopy(w32, props + 8);
  GeneralFunction::oRtWeakPtrCtor(w33);
  GeneralFunction::oRtWeakPtrCopy(w33, (__int64)w32);

  // 3. "WarmingRadius" SexyString
  char name[24] = {0};
  GeneralFunction::oSexyStringAssign(name, "WarmingRadius", sizeof("WarmingRadius") - 1);

  // 4. 创建温暖组件并附加（内部: 创建(类型63) + 名字/弱指针写入组件 + 加入 ctx+64 列表）
  __int64 comp = oWarmingCompFactory(ctx, (__int64)w33, name);

  // 5. 清理弱指针链与 SexyString
  GeneralFunction::oRtWeakPtrDtor(w33);
  GeneralFunction::oRtWeakPtrDtor(w32);
  if (name[0] & 1)
    operator delete(*(void **)(name + 16));

  if (!comp)
    return ret;

  // 6. 取 props+272 的 powers 列表弱指针（__usercall），解析出实体
  uint64_t w28[2] = {0};
  oPropsPowersBindShell(props, w28);
  __int64 v16 = GeneralFunction::weakResolve(w28);
#ifdef _DEBUG
  if (v16)
    LOGI("[SnapWarm] v16=%p vt=%p", (void *)v16, (void *)*(__int64 *)v16);
  else
    LOGI("[SnapWarm] v16=0");
#endif

  // 7. 按 (type=2, sub=0) 从实体 powers 列表找 WarmingRadius 的 PowerProps（__usercall）
  __int64 v22 = 0;
  if (v16) {
    uint64_t w29[2] = {0};
    oPowerListFindShell(v16 + 176, 2, 0, w29);
    v22 = GeneralFunction::weakResolve(w29);
#ifdef _DEBUG
    if (v22)
      LOGI("[SnapWarm] v22=%p vt=%p r64=%f r68=%f p96=%p p104=%p", (void *)v22,
           (void *)*(__int64 *)v22, *(float *)(v22 + 64), *(float *)(v22 + 68),
           *(void **)(v22 + 96), *(void **)(v22 + 104));
    else
      LOGI("[SnapWarm] v22=0");
#endif
  }

  // 8. 验证 PowerPropsWarmingRadius 配置（不调用 IsA 虚函数——v22 的 vtable 槽4 不可靠会崩）：
  //    检查 +64 处半径 float 的合理范围
  LOGI("[SnapWarm] IsA check");
  __int64 powerProps = 0;
  if (v22) {
    float radius = *(float *)(v22 + 64);
    LOGI("[SnapWarm] radius=%f", radius);
    if (radius > 0.0f && radius < 50.0f)
      powerProps = v22;
  }
  LOGI("[SnapWarm] powerProps=%p", (void *)powerProps);

  // 9. 配置里有 WarmingRadius 才拷贝温暖参数（PowerPropsWarmingRadius.WarmingRadius@64）
  if (powerProps) {
    LOGI("[SnapWarm] SetProps enter r=%f c=%f t=%f d=%f g=%f", *(float *)(powerProps + 64),
         *(float *)(powerProps + 68), *(float *)(powerProps + 72), *(float *)(powerProps + 184),
         *(float *)(powerProps + 192));
    oWarmingSetProps(comp, powerProps + 64);
    LOGI("[SnapWarm] SetProps done");
    LOGI("[SnapdragonWarm] WarmingRadius applied (comp=%p)", (void *)comp);
  } else {
    LOGI("[SnapdragonWarm] WarmingRadius power not found in config, skip");
  }
  return ret;
}

inline void process() {
  if constexpr (ENABLE) {
    oPropsContext = (PropsContext)getActualOffset(PropsContextAddr);
    oPropsPowersBind = (void *)getActualOffset(PropsPowersBindAddr);
    oPowerListFind = (void *)getActualOffset(PowerListFindAddr);
    oWarmingCompFactory = (WarmingCompFactory)getActualOffset(WarmingCompFactoryAddr);
    oWarmingSetProps = (WarmingSetProps)getActualOffset(WarmingSetPropsAddr);
    PVZ2HookFunction(SnapdragonInitAddr, (void *)hkSnapdragonInit, (void **)&oSnapdragonInit,
                     "Snapdragon::Init");
  }
}

}  // namespace SnapdragonWarming

#endif

namespace AshDeathrattleFix {
// 本 namespace 可用的前置条件（只列入口依赖：vtable 名单是**动态表**，运行时逐条遍历、逐条跳过
// UNKNOWN，不能塞进 constexpr）
constexpr bool ENABLE = ZombieAnimRigGetAddr != UNKNOWN && ZombieAnimPauseAddr != UNKNOWN;

// 化灰亡语修复：僵尸 vtable 槽 183 = 死亡收尾——化灰致命伤害（a2+16 标志 0x20000000840，
// 火 0x40/0x800 + 电 0x200000000）后原动画只被渲染禁用、时钟不停，指令帧（扔小鬼/砸植物）
// 照常触发，死后仍执行。修法：化灰时解析 AnimRig 并暂停动画（mPaused=1），特效照常播。
// 1. 巨人基类（5 个 vtable 共享）：hook 槽 183 实现函数
// 2. 继承僵尸（槽 183 = nullsub，不能 hook）：patch 各自 vtable 槽 183 数据
// 加僵尸只补配置表行。

typedef __int64 (*ZombieAnimPause)(__int64 rig, char paused);
static ZombieAnimPause oZombieAnimPause = nullptr;

// ===== 1. 巨人基类：hook 死亡收尾函数（槽 183 实现，5 个巨人 vtable 共享）=====
// 配置表：每僵尸一行（槽 183 死亡收尾函数地址 + 化灰标志掩码）
struct AshDeathrattleEntry {
  size_t deathFuncAddr;  // 槽 183 死亡收尾（hook 点）
  uint64_t ashFlags;     // 化灰标志（a2+16 & ashFlags != 0 = 化灰死亡）
};

constexpr AshDeathrattleEntry kAshEntries[] = {
    {GargantuarDeathAddr, 0x20000000840},  // 巨人基类

    // 新僵尸：{ 槽183死亡收尾函数地址, 化灰标志掩码 }
};
constexpr size_t kAshEntryCount = sizeof(kAshEntries) / sizeof(kAshEntries[0]);
static void *oDeathFuncs[kAshEntryCount];

template <size_t I>
__int64 hkDeath(__int64 a1,
                __int64 a2) {  // a1 = 僵尸实体, a2 = 伤害对象
  if (a2 && (*(uint64_t *)(a2 + 16) & kAshEntries[I].ashFlags) != 0) {
    __int64 rig = a1 ? GeneralFunction::oZombieAnimRigGet(a1) : 0;
    if (rig) {
      oZombieAnimPause(rig, 1);  // 官方暂停动画（mPaused=1），指令帧不再触发
      LOGI(
          "[AshFix] entry[%d] paused anim on ash death "
          "zombie=%p rig=%p",
          (int)I, (void *)a1, (void *)rig);
    }
  }
  return ((__int64 (*)(__int64, __int64))oDeathFuncs[I])(a1, a2);
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
  size_t vtableAddr;  // 僵尸 vtable 起始（槽 183 =
                      // 死亡收尾，patch 该槽）
  uint64_t ashFlags;  // 化灰标志（a2+16 & ashFlags != 0 = 化灰死亡）
};

constexpr size_t kDeathSlotOffset = 183 * 8;  // 槽 183

constexpr AshDeathrattleVtableEntry kVtableEntries[] = {
    {BullVtableAddr, 0x20000000840},              // ZombieBull
    {ZCorpImpVtableAddr, 0x20000000840},          // ZombieZCorpImp
    {BullVeteranVtableAddr, 0x20000000840},       // ZombieBullVeteran（专属 vtable）
    {DinoBullyVeteranVtableAddr, 0x20000000840},  // ZombieDinoBullyVeteran（专属 vtable）

    // 新僵尸：{ vtable 起始地址, 化灰标志掩码 },
};
constexpr size_t kVtableEntryCount = sizeof(kVtableEntries) / sizeof(kVtableEntries[0]);
static void *oSlotFuncs[kVtableEntryCount];

template <size_t I>
__int64 hkDeathSlot(__int64 a1, __int64 a2) {
  // 槽 183 虚调：a1 = 僵尸实体, a2 = 伤害对象
  if (a2 && (*(uint64_t *)(a2 + 16) & kVtableEntries[I].ashFlags) != 0) {
    __int64 rig = a1 ? GeneralFunction::oZombieAnimRigGet(a1) : 0;
    if (rig) {
      oZombieAnimPause(rig, 1);  // 官方暂停动画（mPaused=1），指令帧不再触发
      LOGI(
          "[AshFix] vtbl[%d] paused anim on ash death zombie=%p "
          "rig=%p",
          (int)I, (void *)a1, (void *)rig);
    }
  }
  return ((__int64 (*)(__int64, __int64))oSlotFuncs[I])(a1, a2);  // 原槽函数（nullsub，空操作）
}

template <size_t I>
inline void patchDeathSlot() {
  if constexpr (I < kVtableEntryCount) {
    size_t vtableActual =
        getActualOffset(kVtableEntries[I].vtableAddr);  // 运行时地址（libBase + 偏移）
    void **slot = (void **)(vtableActual + kDeathSlotOffset);
    oSlotFuncs[I] = *slot;  // 保存原槽函数（nullsub）
    patchVFTable((void *)vtableActual, (void *)hkDeathSlot<I>, 183);
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

// 弹簧豆 PF 期间无敌修复：正常植物槽 81 先查 PF（+256 标志），PF 中不死；
// SpringBean 槽 81 无检查直调死亡汇聚点，PF 期间被秒杀。
// 修法：vtable 槽 81 替换（代码区零改动）。代码 hook 会越界覆盖邻槽函数（槽 81 实现仅 12B）。
typedef int (*IsPlantFoodActive)(uint64_t a1);
static IsPlantFoodActive oIsPlantFoodActive = nullptr;
typedef __int64 (*SpringBeanDie)(uint64_t entity);  // 原函数有返回值（保留返回类型）
static SpringBeanDie oSpringBeanDie = nullptr;

__int64 hkSpringBeanDie(uint64_t entity) {
  if (!entity)
    return 0;
  LOGI("[PFInvuln] SpringBeanDie entity=%p", (void *)entity);
  uint64_t container = *(uint64_t *)(entity + 8);  // 实体+8 = 容器
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
                        PlantRegistryGlobalAddr != UNKNOWN && PlantRegistryFindAddr != UNKNOWN &&
                        SexyStringAssignAddr != UNKNOWN;

// 高版本 skin 装扮搬运（低版本上的实现）。
// 目标：skin 装扮时植物改用 CostumeItemType 的 PopAnimName 创建动画对象，而非原生动画。
//
// 方案：低版本的 CostumeItemType 是 vector 的内联 88B 元素（元素构建与搬移全用编译期常量
// 步长，无法用 32 位指令 patch 覆盖），结构不能扩、也没地方加新字段，所以不动布局、复用
// 原有 LayerName 字段存标记：值以 "skin:" 开头即 skin 装扮，冒号后是 PopAnimName
// （如 "skin:Peashooter_skinA"），普通装扮照旧填层名。不注册新字段的原因：别名 key 会与
// 官方或移植数据里的同名 key 抢同一个槽位。
// 数据侧硬要求：植物数据要列出 "LoDCostumes": [装扮ID...]（否则取当前装扮 ID 只会得到 -100），
// skin 动画所在的资源组也要在植物已加载的组里。
//
// 机制：a1 = PlantType 系对象，+56 = AnimRigClass（决定建哪个动画类），+80 = PopAnim
// （动画资源名，解析不到会用 "&POPANIM_MISSING_PAM" 兜底）。skin 即换 +80 的名字串、
// 跑原函数、再还原。
//
// 组成：A skin 分支（改 PopAnim 名字串 + 跑原创建函数），B 图鉴切换重建（切换入口 hook）。

constexpr int kCostumeNameOff = 64;  // LayerName 槽位（ARM64）
#ifdef _DEBUG
constexpr const char *kCostumeSkinRev = __DATE__ " " __TIME__;  // 构建时间戳（仅 Debug）
#endif

// ============ A. skin 分支 ============
typedef __int64 (*CostumeAnimApplier)(__int64 a1, char a2);
static CostumeAnimApplier oCostumeAnimApplier = nullptr;
typedef uint32_t (*CostumeGetId)(uint64_t plantName);
static CostumeGetId oCostumeGetId = nullptr;
typedef uint64_t (*CostumeFindItem)(uint32_t costumeID);
static CostumeFindItem oCostumeFindItem = nullptr;
constexpr uint64_t kCostumeAnimNameOff = 80;  // PlantType::PopAnim（A64；A32 = +40）

// CostumeItemType（88B）：LayerName @64(String)；值以 "skin:" 开头即 skin 装扮
static bool isSkinItem(uint64_t item, const char **outAnim) {
  if (!item)
    return false;
  const char *v = GeneralFunction::sexyStrPtr(item + kCostumeNameOff);
  if (!v || strncmp(v, "skin:", 5) != 0 || !v[5])
    return false;
  *outAnim = v + 5;
  return true;
}

// 把配置对象上的 PopAnim 名字串换成 animName，跑原创建函数（名字解析成 PopAnim 资源）后还原
static uint64_t createAnimWithName(__int64 a1, char a2, const char *animName) {
  void *nameField = (void *)(a1 + kCostumeAnimNameOff);
  std::string saved(GeneralFunction::sexyStrPtr((uint64_t)nameField));
  LOGI("[CostumeSkin] skin '%s' (native PopAnim is '%s')", animName, saved.c_str());
  GeneralFunction::oSexyStringAssign(nameField, animName, strlen(animName));
  uint64_t obj = oCostumeAnimApplier(a1, a2);  // 原函数：把该名字解析成 PopAnim 资源再建动画
  GeneralFunction::oSexyStringAssign(nameField, saved.c_str(), saved.size());  // 还原
  return obj;
}

__int64 hkCostumeAnimApplier(__int64 a1, char a2) {
  if (!a1)
    return 0;
  // a1：+8 = 植物名(SexyString)；+56 = AnimRigClass；+80 = PopAnim（动画资源名）
  uint32_t cid = oCostumeGetId(a1 + 8);
  const char *skinAnim = nullptr;
  if (isSkinItem(oCostumeFindItem(cid), &skinAnim)) {
    LOGI("[CostumeSkin] skin apply plant='%s' cid=%u anim='%s'",
         GeneralFunction::sexyStrPtr(a1 + 8), cid, skinAnim);
    return (__int64)createAnimWithName(a1, a2, skinAnim);
  }
  return oCostumeAnimApplier(a1, a2);  // 非 skin：原逻辑
}

// ============ B. 图鉴切换装扮重建 ============
// 图鉴预览 UI 的切换入口只对已存在的动画对象开关层，不重建动画对象；所以切换到 skin 装扮
// 时要补一次重建（含从 skin 切回普通装扮的反向重建）。
//
// 旧动画对象为何不释放：它由引擎类型系统创建，所有权不在本工程；
// 游戏自身也从不替换动画对象（切装扮一律复用同一个），没有替换后善后的先例可抄，
// 贸然析构有 use-after-free / 引擎表悬垂的风险。代价是每次替换泄漏
// 一个对象（含其资源引用），触发频率仅为手动切装扮/新建预览，可接受。要彻底解决须先查清其生命周期。
typedef void (*CostumeSwitch)(__int64 self);
static CostumeSwitch oCostumeSwitch = nullptr;
typedef float (*CostumeAnimRateGet)(uint64_t animObj);
static CostumeAnimRateGet oCostumeAnimRateGet = nullptr;
typedef void (*CostumeAnimRateSet)(uint64_t animObj, float rate);
static CostumeAnimRateSet oCostumeAnimRateSet = nullptr;
constexpr uint64_t kCostumeAnimFinishSlot = 368;  // 预览 ctor 建完动画后调用的虚表槽（字节偏移）

// ============ 卡片 box 覆盖表（skin 装扮在图鉴/选卡预览里的定位用）============
// 卡片上的 box（4 个 int）：绘制动画时按它把内容居中放进卡片。它由卡片布局按
// 当时的动画算出，所以显示 skin（套用别的植物的动画）时与卡片尺寸不同源，预览位置偏移。
// 该值只与植物和原装扮绑定、稳定不变，直接查表覆盖。
//
// 添加植物：表里没有的不会被覆盖。请自行用 Debug 配置编译，在原装扮状态下进一次
// 图鉴/选卡，从日志读取 "[CostumeSkin] box plant='…' skin=0 = [a b c d]" 的四个数，填进下表即可。
// 嫌繁琐也可以不加：代价仅是图鉴/选卡预览偏，不影响关卡内显示。
constexpr uint64_t kCardBoxOff = 280;

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

static void applyCostumeBox(uint64_t card) {
  if (!card)
    return;
  uint64_t entity = *(uint64_t *)(card + 192);
  const char *plantName = entity ? GeneralFunction::sexyStrPtr(entity + 8) : nullptr;
  if (!plantName)
    return;
  for (size_t i = 0; i < kCostumeBoxCount; i++) {
    if (kCostumeBoxes[i].plantName && strcmp(kCostumeBoxes[i].plantName, plantName) == 0) {
      memcpy((void *)(card + kCardBoxOff), kCostumeBoxes[i].v, sizeof(kCostumeBoxes[i].v));
      return;
    }
  }
}

// 预览 ctor 建完动画后的收尾：虚表槽 + 速率 = 动画速率 × 实体速度系数@+212。
// 少这步时新对象速率为 0，动画不推进，控件按空包围盒塌到画面左上角。
static void finishPreviewAnim(uint64_t obj, uint64_t entity) {
  (*(void (**)(uint64_t))(*(uint64_t *)obj + kCostumeAnimFinishSlot))(obj);
  oCostumeAnimRateSet(obj, oCostumeAnimRateGet(obj) * *(float *)(entity + 212));
}

void hkCostumeSwitch(__int64 self) {
  if (!self)
    return;
  oCostumeSwitch(self);
  uint64_t entity = *(uint64_t *)(self + 192);  // 预览对象：+192 = 植物实体，+272 = 动画对象
  if (!entity)
    return;
  uint32_t cid = oCostumeGetId(entity + 8);
  const char *skinAnim = nullptr;
  bool skin = isSkinItem(oCostumeFindItem(cid), &skinAnim);
  // 原函数只对旧对象开关层、不换动画，切换后一律重建（applier 内部会按当前装扮 ID 应用层）
  uint64_t obj = skin ? createAnimWithName(entity, 1, skinAnim) : oCostumeAnimApplier(entity, 1);
  if (!obj)
    return;                         // 创建失败：保留原动画对象
  *(uint64_t *)(self + 272) = obj;  // 旧动画对象不释放（理由见 B 段）
  applyCostumeBox(self);            // box 按植物查表覆盖（skin 动画的 box 与卡片尺寸不同源，会偏）
  finishPreviewAnim(obj, entity);
  LOGI("[CostumeSkin] almanac switch plant='%s' cid=%u skin=%d anim='%s'",
       GeneralFunction::sexyStrPtr(entity + 8), cid, (int)skin, skin ? skinAnim : "(native)");
}

// 卡片 ctor 之后：按植物查到 box 就覆盖（进图鉴时已是 skin 的情况靠这一步）
typedef void (*CostumePreviewCtor)(uint64_t card, uint64_t entity, char flag);
static CostumePreviewCtor oCostumePreviewCtor = nullptr;

void hkCostumePreviewCtor(uint64_t card, uint64_t entity, char flag) {
  if (!card)
    return;
  oCostumePreviewCtor(card, entity, flag);
#ifdef _DEBUG
  const int *b = (const int *)(card + kCardBoxOff);
  const char *plantName = entity ? GeneralFunction::sexyStrPtr(entity + 8) : nullptr;
  const char *skinAnim = nullptr;
  int skin = 0;
  if (plantName) {
    uint32_t cid = oCostumeGetId(entity + 8);
    skin = isSkinItem(oCostumeFindItem(cid), &skinAnim) ? 1 : 0;
  }
  LOGI("[CostumeSkin] box plant='%s' skin=%d = [%d %d %d %d]", plantName ? plantName : "?", skin,
       b[0], b[1], b[2], b[3]);
#endif
  applyCostumeBox(card);
}

// 按植物名（SexyString 字段地址）查植物类型注册表对象（H 段用）
typedef uint64_t (*PlantRegistryFind)(uint64_t tree, uint64_t nameField);
static PlantRegistryFind oPlantRegistryFind = nullptr;

static uint64_t findPlantType(uint64_t nameField) {
  uint64_t reg = *(uint64_t *)getActualOffset(PlantRegistryGlobalAddr);
  if (!reg)
    return 0;
  uint64_t node = oPlantRegistryFind(reg + 8, nameField);
  if (!node || node == reg + 16)
    return 0;
  return (uint64_t)GeneralFunction::weakResolve((void *)(node + 56));
}

// ============ H. 商店 HotUI 植物动画：按名字建动画的预览 ============
// 该函数按配置对象（植物名 @+656 查注册表所得）的 PopAnim 名（@+80）新建动画对象（存 +568）
// 并自己设速率/开层，所以在它跑之前把配置对象的名字换成 skin 名，建出来的就是 skin 动画。
// 注意：别去写 +568，那是它自己的产物，手写会被覆盖。
typedef void (*HotUIPlantAnim)(uint64_t self);
static HotUIPlantAnim oHotUIPlantAnim = nullptr;

void hkHotUIPlantAnim(uint64_t self) {
  if (self) {
    const char *layer = GeneralFunction::sexyStrPtr(self + kHotUiLayerNameOff);
    if (layer && strncmp(layer, "skin:", 5) == 0 && layer[5]) {
      const char *skinAnim = layer + 5;
      uint64_t cfg = findPlantType(self + kHotUiPlantNameOff);
      if (cfg) {
        void *nameField = (void *)(cfg + kCostumeAnimNameOff);
        std::string saved(GeneralFunction::sexyStrPtr((uint64_t)nameField));
        GeneralFunction::oSexyStringAssign(nameField, skinAnim, strlen(skinAnim));
        oHotUIPlantAnim(self);  // 原函数：拷名字，按名字建动画、开层、设速率
        GeneralFunction::oSexyStringAssign(nameField, saved.c_str(), saved.size());  // 还原
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
    oCostumeGetId = (CostumeGetId)getActualOffset(CostumeGetIdAddr);
    oPlantRegistryFind = (PlantRegistryFind)getActualOffset(PlantRegistryFindAddr);
    oHotUIPlantAnim = (HotUIPlantAnim)getActualOffset(HotUIPlantAnimAddr);
    oCostumeAnimRateGet = (CostumeAnimRateGet)getActualOffset(CostumeAnimRateGetAddr);
    oCostumeAnimRateSet = (CostumeAnimRateSet)getActualOffset(CostumeAnimRateSetAddr);
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

__attribute__((constructor)) void libRestructedLogic_ARM64__main() {
  LOGI("Initializing %s", LIB_TAG);

  GeneralFunction::process();  // 通用工具（RtWeakPtr 解析，供温暖/PF 无敌复用）——最前（无条件）
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
  SpringBeanPFInvuln::process();  // 弹簧豆 PF 期间无敌修复
#if GAME_VERSION < 900
  CostumeSkinPort::process();  // skin 装扮搬运（skin 分支 + 图鉴切换重建）
#endif

  LOGI("Finished initializing");
}
