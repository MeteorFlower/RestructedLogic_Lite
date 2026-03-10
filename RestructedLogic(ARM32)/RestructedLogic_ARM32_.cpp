#include "memUtils.hpp"
#include "Unzip/ApkUnzipper.hpp"
#include "Unzip/HashComparer.hpp"
#include "AXML/axml_parser.hpp"
#include "Decrypt/picosha2.hpp"
#include "Decrypt/aes.hpp"
#include "SexyTypes.hpp"
#include "RestructedLogic_ARM32_.hpp"
#include "VersionSwitcher.hpp"

using _DWORD = uint32_t;
using __int64 = int64_t;
using _BYTE = uint8_t;

namespace DirectInstallOBB {
// 防止重复读取应用信息
std::atomic<bool> apkinforeaded(false);
// RSB迁移是否开始判定
std::atomic<bool> thread_applied(false);
// 源安装包路径
std::string apk;
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

// 让主程序延迟防止数据包迁移期间被读取（可放在除了Log输出函数以外的任一hook函数调用旧函数之前）
void dalay_hook() {
  while (thread_applied) {
    LOGI("RSB first loaded, sleeping......");
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
  }
}

// 数据分块
void copy_chunk(const std::filesystem::path &src, const std::filesystem::path &dst, uint64_t offset,
                uint64_t size) {
  const size_t BUF_SIZE = 64ull * 1024 * 1024;  // 512MB

  std::ifstream in(src, std::ios::binary);
  std::fstream out(dst, std::ios::binary | std::ios::in | std::ios::out);
  in.seekg(offset);
  out.seekp(offset);

  std::vector<char> buffer(std::min<uint64_t>(BUF_SIZE, size));
  uint64_t remaining = size;
  while (remaining > 0) {
    size_t to_read = std::min<uint64_t>(buffer.size(), remaining);

    in.read(buffer.data(), to_read);
    out.write(buffer.data(), to_read);

    remaining -= to_read;
  }
}

// 分块迁移函数
bool copy_file_parallel(const std::filesystem::path &src, const std::filesystem::path &dst,
                        int threads) {
  uint64_t file_size = std::filesystem::file_size(src);

  // 预创建目标文件
  {
    std::ofstream out(dst, std::ios::binary | std::ios::trunc);
    out.seekp(file_size - 1);
    out.write("", 1);
  }

  uint64_t chunk = file_size / threads;
  std::vector<std::thread> workers;
  for (int i = 0; i < threads; i++) {
    uint64_t offset = i * chunk;
    uint64_t size = (i == threads - 1) ? (file_size - offset) : chunk;
    workers.emplace_back(copy_chunk, src, dst, offset, size);
  }
  for (auto &t : workers)
    t.join();

  return true;
}

// RSB迁移期间防止主线程读取函数（大概率无法一次载入因为res头读取比RSB读取要早..........）
void safe_pipe_copy(const std::string &src_path, const std::string &target_path) {
  // 1. 如果路径已存在普通文件，先删掉，否则没法建管道
  unlink(target_path.c_str());

  // 2. 创建管道 (FIFO)
  if (mkfifo(target_path.c_str(), 0666) != 0) {
    // 如果创建失败（比如权限问题），退回到普通拷贝作为保底
    std::filesystem::copy(src_path, target_path, std::filesystem::copy_options::overwrite_existing);
    return;
  }

  // 3. 打开管道准备写入 (注意：如果主线程没来读，这里会阻塞)
  // 建议在子线程执行，这样不会卡死你的 Mod 初始化
  int fifo_fd = open(target_path.c_str(), O_WRONLY);
  if (fifo_fd < 0)
    return;

  // 4. 分块读写数据
  std::ifstream src(src_path, std::ios::binary);
  std::vector<char> buffer(1024 * 1024);  // 每次 64KB，正好是典型 Linux 管道的大小

  while (src.read(buffer.data(), buffer.size()) || src.gcount() > 0) {
    ssize_t count = src.gcount();
    // 这一步会根据主线程的读取速度自动“限速”
    if (write(fifo_fd, buffer.data(), count) == -1)
      break;
  }

  // 5. 关键：关闭管道，主线程才会收到 EOF 并结束读取
  close(fifo_fd);
  src.close();

  // 6. 可选：任务彻底完成后删除管道（或者留着下次用）
  unlink(target_path.c_str());
}

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
  apk = find_apk_path();
  LOGI("APK LOACTION:%s", apk.c_str());
  manifest = read_manifest(apk);
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

// OBB文件夹是否存在
bool OBBPathExisted() {
  app_version = get_apk_versioncode();
  rsb_path_str = "/storage/emulated/0/Android/obb/" + get_package_name();
  std::filesystem::path rsb_real_path = std::filesystem::path(rsb_path_str);
  if (std::filesystem::exists(rsb_real_path))
    return 1;
  return 0;
}

// OBB是否存在
bool OBBExisted() {
  app_version = get_apk_versioncode();
  ori_rsb_name = "main." + std::to_string(app_version) + "." + get_package_name() + ".obb";
  rsb_path_str = "/storage/emulated/0/Android/obb/" + get_package_name();
  rsb_self_path_str = rsb_path_str + "/" + ori_rsb_name;
  std::filesystem::path rsb_self_path = std::filesystem::path(rsb_self_path_str);
  if (std::filesystem::exists(rsb_self_path))
    return 1;
  return 0;
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

// 验证哈希值是否相等
bool OBBHashEquals() {
  LOGI("Hash Start");
  app_version = get_apk_versioncode();
  ori_rsb_name = "main." + std::to_string(app_version) + "." + get_package_name() + ".obb";
  rsb_path_str = "/storage/emulated/0/Android/obb/" + get_package_name();
  rsb_self_path_str = rsb_path_str + "/" + ori_rsb_name;
  // apk内数据包哈希值
  apkOBBHash = HashComparer::get_asset_hash(apk, "assets/" + ori_rsb_name);
  if (apkOBBHash == 0) {
    LOGI("哈希校验：非直装包");
    return true;
  }
  if (check_magic_number(rsb_self_path_str.c_str(), "EBRL")) {
    LOGI("检测到EBRL，读取后续哈希值");
    OBBHash = HashComparer::read_hash_after_header(rsb_self_path_str.c_str());
  } else {
    // 如果大小不一，直接就是不一样
    if (ApkUnzipper::get_apk_asset_size(apk, "assets/" + ori_rsb_name) !=
        std::filesystem::file_size(std::filesystem::path(rsb_self_path_str))) {
      LOGI("文件大小不一，必然不同");
      return false;
    }
    OBBHash = HashComparer::compute_file_hash(std::filesystem::path(rsb_self_path_str));
  }
  bool result = HashComparer::are_hashes_identical(apkOBBHash, OBBHash);
  LOGI("Hash End");
  return result;
}

// Assets版直装转移
bool AssetsRSBDirectInstall() {
  apk = find_apk_path();
  app_version = get_apk_versioncode();
  ori_rsb_name = "main." + std::to_string(app_version) + "." + get_package_name() + ".obb";
  rsb_path_str = "/storage/emulated/0/Android/obb/" + get_package_name();
  rsb_self_path_str = rsb_path_str + "/" + ori_rsb_name;
  LOGI("ori_rsb_name = %s,rsb_path_str = %s,rsb_self_path_str = %s", ori_rsb_name.c_str(),
       rsb_path_str.c_str(), rsb_self_path_str.c_str());
  // 提取并放置OBB
  if (ApkUnzipper::extract_asset(apk, "assets/" + ori_rsb_name, rsb_self_path_str)) {
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

bool available = 0;

inline void process() {
  available = 1;
  // 必须留，获取包名和版本号信息
  if (!apkinforeaded.exchange(true))
    get_apk_versioncode();
  // 直装包：数据包不存在或者哈希校验不通过则轮询路径是否存在
  if (!OBBExisted() || !OBBHashEquals())
    std::thread(obb_path_monitor).detach();
}
}  // namespace DirectInstallOBB

#if GAME_VERSION < 1031

namespace AliasToID {
class PlantNameMapper {
 public:
  void *vftable;
  std::map<Sexy::SexyString, uint> m_aliasToId;
};
std::vector<Sexy::SexyString> g_modPlantTypenames;

#define REGISTER_PLANT_TYPENAME(typename) g_modPlantTypenames.push_back(typename);

typedef PlantNameMapper *(*PlantNameMapperCtor)(PlantNameMapper *);
PlantNameMapperCtor oPlantNameMapperCtor = nullptr;

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
  if constexpr (PlantNameMapperAddr != UNKNOWN && firstFreePlantID != UNKNOWN)
    PVZ2HookFunction(PlantNameMapperAddr, (void *)hkCreatePlantNameMapper,
                     (void **)&oPlantNameMapperCtor, "PlantNameMapper::PlantNameMapper");
}
#undef REGISTER_PLANT_TYPENAME
}  // namespace AliasToID

#endif

namespace LogOutput {
typedef int (*LogOutputFunc)(char *, ...);
LogOutputFunc oLogOutputFunc = nullptr;
std::mutex g_logMutex;

int hkLogOutputFunc(char *format, ...) {
  DirectInstallOBB::dalay_hook();

  va_list va;
  va_start(va, format);

#ifdef _DEBUG

  std::lock_guard<std::mutex> lock(g_logMutex);
  LOGI("LogOutputFunc: ");
  LOGI(format, va);

#endif

  int result = oLogOutputFunc(format, va);
  va_end(va);
  return result;
}

typedef int (*LogOutputFunc_Simple)(const char *);
LogOutputFunc_Simple oLogOutputFunc_Simple = nullptr;
std::mutex g_logMutex_Simple;

int hkLogOutputFunc_Simple(const char *text) {
  // 预检逻辑（模仿 IDA 中的 if(!v2)）
  if (text && *text != '\0') {
    std::lock_guard<std::mutex> lock(g_logMutex_Simple);
    // 直接打印传入的字符串，无需 vsnprintf，因为这不是可变参数函数
    LOGI("LogOutputFunc_Simple: %s", text);
  }
  // 调用原函数
  return oLogOutputFunc_Simple(text);
}

// 参数是 int (寄存器 r0)，在 Hook 中我们定义为 void* 或 long
typedef int (*LogOutputFunc_Struct)(void *);
LogOutputFunc_Struct oLogOutputFunc_Struct = nullptr;
std::mutex g_logMutex_Struct;

int hkLogOutputFunc_Struct(void *result) {
  if (result) {
    const char *v1 = NULL;
    // 模仿 IDA 逻辑：检查标志位
    // 如果 (*(unsigned char*)result & 1) != 0
    if ((*((unsigned char *)result) & 1) != 0) {
      // 长字符串逻辑：从偏移 8 处取指针
      v1 = *(const char **)((uint)result + 8);
    } else {
      // 短字符串逻辑：从偏移 1 处取内容
      v1 = (const char *)((uint)result + 1);
    }
    // 如果指针不为空且内容不为空字符串
    if (v1 && *v1 != '\0') {
      std::lock_guard<std::mutex> lock(g_logMutex_Struct);
      LOGI("LogOutputFunc_Struct: %s", v1);
    }
  }
  // 调用原函数并返回其结果
  return oLogOutputFunc_Struct(result);
}

typedef int (*LogOutputFunc_v2)(int a1, ...);
LogOutputFunc_v2 oLogOutputFunc_v2 = nullptr;
std::mutex g_logMutex_v2;

int hkLogOutputFunc_v2(int a1, ...) {
  va_list va;
  va_start(va, a1);

#ifdef _DEBUG

  const char *format = (const char *)a1;
  std::lock_guard<std::mutex> lock(g_logMutex);
  LOGI("LogOutputFunc_v2: ");
  LOGI(format, va);

#endif

  int result = oLogOutputFunc_v2(a1, va);
  va_end(va);
  return result;
}

void process() {
#ifdef _DEBUG

  // 输出简要日志
  if constexpr (LogOutputFuncAddr_Simple != UNKNOWN)
    PVZ2HookFunction(LogOutputFuncAddr_Simple, (void *)hkLogOutputFunc_Simple,
                     (void **)&oLogOutputFunc_Simple, "LogOutputFunc_Simple");
  // 输出主日志
  if constexpr (LogOutputFuncAddr != UNKNOWN)
    PVZ2HookFunction(LogOutputFuncAddr, (void *)hkLogOutputFunc, (void **)&oLogOutputFunc,
                     "LogOutputFunc");
  // 输出结构日志
  if constexpr (LogOutputFuncAddr_Struct != UNKNOWN)
    PVZ2HookFunction(LogOutputFuncAddr_Struct, (void *)hkLogOutputFunc_Struct,
                     (void **)&oLogOutputFunc_Struct, "LogOutputFunc_Struct");
  // 输出v2日志
  if constexpr (LogOutputFuncAddr_v2 != UNKNOWN)
    PVZ2HookFunction(LogOutputFuncAddr_v2, (void *)hkLogOutputFunc_v2, (void **)&oLogOutputFunc_v2,
                     "LogOutputFunc_v2");

#else

  // hook 主日志，用于卡死主进程供 obb 复制
  if (DirectInstallOBB::available) {
    static_assert(LogOutputFuncAddr != UNKNOWN);
    PVZ2HookFunction(LogOutputFuncAddr, (void *)hkLogOutputFunc, (void **)&oLogOutputFunc,
                     "LogOutputFunc");
  }

#endif
}
}  // namespace LogOutput

namespace CDNExpansion {
// 在此感谢CZ的技术专栏分享，我将变量名和一些方式进行了小小的改变，但依旧需要对其为技术的分享表达感谢！！！！！
typedef int (*CDNExpand)(int *a1, const Sexy::SexyString &rtonName, int rtonTable, int a4);
CDNExpand oCDNLoad = nullptr;

std::atomic<bool> executed(false);

void hkCDNLoad(int *a1, const Sexy::SexyString &rtonName, int rtonTable, int a4) {
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
  oCDNLoad(a1, rtonName, rtonTable, a4);
}

inline void process() {
  // CDN读取rton，感谢CZ技术专栏分享技术！！！
  if constexpr (CDNLoadAddr != UNKNOWN)
    PVZ2HookFunction(CDNLoadAddr, (void *)hkCDNLoad, (void **)&oCDNLoad, "CDNLoadExpansion");
}
}  // namespace CDNExpansion

namespace RSBPathChangeAndDecryptRSB {
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
RSBPathRecorder oRSBPathRecorder = nullptr;

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
  if (!path_ptr || (uint)path_ptr < 0x1000) {
    LOGI("RSBPathRecorder: Invalid path pointer 0x%x, a1[0]=0x%x", (uint)path_ptr, a1[0]);
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

  // 验证预期路径，可改，改成你的改版路径即可，不改也没影响！！！！！！！！！！！！
  std::string expected_path = "/storage/emulated/0/Android/obb/" + pack_name + "/" + rsb_name;
  if (original_path != expected_path) {
    LOGI("RSBPathRecorder: Path mismatch, expected %s", expected_path.c_str());
    // 继续处理，允许非预期路径
  }

  LOGI("RSB_TRACE: Starting Hybrid Mmap-Stream Process...");

  // 一定要改！！！！！把你的地址改成/data/data/com.ea.game.pvz2_改版名/files！！！！！
  std::string cache_dir = "/data/data/" + pack_name +
                          "/files";  /// storage/emulated/0/Android/data/com.ea.game.pvz2_row/cache
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
    a1[2] = (uint)new_path;                     // 新路径指针
  } else {
    // 非动态分配
    a1[0] = 2 * new_path_len;  // a1[0] = 2 * 路径长度
    a1[1] = (uint)new_path;    // a1[1] = 新路径指针
  }
  LOGI("RSBPathRecorder: Replaced path with %s", temp_path.c_str());

  return result;
}

// ROOT 检测
typedef int (*ResourceManagerFunc)(int, int, int);
ResourceManagerFunc oResourceManagerFunc = nullptr;
int hkResourceManagerFunc(int a1, int a2, int a3) {
  LOGI("Hooking ResourcesManagerFunc 6EE218");
  LOGI("a1=%d, a2=%d, a3=%d", a1, a2, a3);
  int backdata = oResourceManagerFunc(a1, a2, a3);
  LOGI("Hooking ResourcesManagerFunc 6EE218 End");
  // 如果检测到ROOT，则进入秒删模式
  if (isRooted()) {
    LOGI("Cleaning up temp files");
    cleanupTempFiles();
  }
  return backdata;
}

inline void process() {
  if constexpr (RSBPathRecorderAddr != UNKNOWN && ResourceManagerFuncAddr != UNKNOWN) {
    // Hook RSB 读取函数
    PVZ2HookFunction(RSBPathRecorderAddr, (void *)hkRSBPathRecorder, (void **)&oRSBPathRecorder,
                     "ResourceManager::RSBPathRecorder");
    // ROOT 检测
    PVZ2HookFunction(ResourceManagerFuncAddr, (void *)hkResourceManagerFunc,
                     (void **)&oResourceManagerFunc, "ResourceManager::ResourceManagerFunc");
  }
}
}  // namespace RSBPathChangeAndDecryptRSB

namespace PrimeGlyphCacheLimitation {
typedef uint *(*PrimeGlyphCacheLimitation)(uint *, int, int, int);
PrimeGlyphCacheLimitation oPrimeGlyphCacheLimitation = nullptr;

// 一路：高端设备缓冲大小为2048，中端设备为1024，低端设备为512。经过测试，缓冲大小最大只能设为2048，设为更高值，会导致进入游戏后文字渲染全为空白，这与设为0的效果一致。
uint *hkPrimeGlyphCacheLimitation(uint *a1, int a2, int a3, int a4) {
  uint *result = oPrimeGlyphCacheLimitation(a1, a2, a3, a4);
  a1[22] = 2048;
  LOGI("Hooked sub_177ECF4: Modified a1[22] to %d", a1[22]);
  return result;
}

inline void process() {
  if constexpr (PrimeGlyphCacheAddr != UNKNOWN)
    PVZ2HookFunction(PrimeGlyphCacheAddr, (void *)hkPrimeGlyphCacheLimitation,
                     (void **)&oPrimeGlyphCacheLimitation,
                     "PrimeGlyphCache::PrimeGlyphCacheLimitation");
}
}  // namespace PrimeGlyphCacheLimitation

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

// LawnAppScreenWidthHeight 的原函数会随版本变化。目前只知道 8.7.3 和 10.3.1
// 的写法。其他版本欢迎补充。
#if GAME_VERSION == 873

typedef int (*LawnAppScreenWidthHeight)(int a1, int a2);
LawnAppScreenWidthHeight oLawnAppScreenWidthHeight = nullptr;

int hkLawnAppScreenWidthHeight(int a1, int a2) {
  // 1. 先执行原函数，让内部逻辑完成内存写入
  int result = oLawnAppScreenWidthHeight(a1, a2);

  if (a1 == NULL)
    return result;

  // 2. 根据偏移直接提取数据
  // 根据 sub_FFE7D0
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
LawnAppScreenWidthHeight oLawnAppScreenWidthHeight = nullptr;

int hkLawnAppScreenWidthHeight(float *a1, int a2) {
  // 1. 先执行原函数，让内部逻辑完成内存写入
  int result = oLawnAppScreenWidthHeight(a1, a2);

  if (a1 == nullptr)
    return result;

  // 2. 根据偏移直接提取数据
  // 注意：a1 是 float*，偏移计算需小心转换
  int *iPtr = (int *)a1;

  // 根据 sub_1482320: 1448字节 = 偏移362, 1452字节 = 偏移363
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

// 定义原函数的函数原型
typedef int (*OrigBoardZoom)(int a1);
OrigBoardZoom oBoardZoom = nullptr;

int hkBoardZoom(int a1) {
  // 先跑原函数
  int result = oBoardZoom(a1);
  // 改变选卡时视野左边缘与棋盘左边缘的距离
  *(_DWORD *)(a1 + 880) = preGameRightLine - mWidth;
  return result;
}

// 定义原函数的函数原型
typedef int (*OrigBoardZoom2)(int a1);
OrigBoardZoom2 oBoardZoom2 = nullptr;

int hkBoardZoom2(int a1) {
  int result = oBoardZoom2(a1);
  // 缩放系数
  *(float *)(a1 + 860) = 1.0f;
  // 改变视野左边缘与棋盘左边缘的距离
  *(_DWORD *)(a1 + 824) = -(gameStartRightLine - mWidth);
  // 顶部基准线
  *(_DWORD *)(a1 + 868) = (_DWORD)mOrigScreenHeight;
  return result;
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

namespace WorldMapVerticalScrolling {
// 本来我完全可以让你们每个版本都去找通用的三个偏移的，但是为了你们旧版本的，我采用条件编译了
// 旧版只需要找一个偏移，而新版则需要找三个

#if GAME_VERSION >= 1001

// 新版需要hook三个函数，而且由于该死的内联，不能把函数全反编译了，所以直接暴力扩边界让它们强行切到垂直移动判定
// 拖动函数:
typedef int (*WorldMapScroll)(int, int, int);
WorldMapScroll oWorldMapScroll = nullptr;
int hkWorldMapScroll(int a1, int a2, int a3) {
  *(int32_t *)(a1 + 312) = -1000000000;
  *(int32_t *)(a1 + 316) = -1000000000;
  *(int32_t *)(a1 + 320) = 2000000000;
  *(int32_t *)(a1 + 324) = 2000000000;
  int result = oWorldMapScroll(a1, a2, a3);
  return result;
}
// 居中函数：
typedef int (*KeepCenter)(int, uint *, bool);
KeepCenter oKeepCenter = nullptr;
int hkKeepCenter(int a1, uint *a2, bool a3) {
  *(int32_t *)(a1 + 312) = -1000000000;
  *(int32_t *)(a1 + 316) = -1000000000;
  *(int32_t *)(a1 + 320) = 2000000000;
  *(int32_t *)(a1 + 324) = 2000000000;
  int result = oKeepCenter(a1, a2, true);
  return result;
}
// 惯性函数：
typedef int (*ScrollInertance)(int);
ScrollInertance oScrollInertance = nullptr;
int hkScrollInertance(int a1) {
  *(int32_t *)(a1 + 312) = -1000000000;
  *(int32_t *)(a1 + 316) = -1000000000;
  *(int32_t *)(a1 + 320) = 2000000000;
  *(int32_t *)(a1 + 324) = 2000000000;
  int result = oScrollInertance(a1);
  return result;
}

#else

// 旧函数（10.0版本前有效）
typedef int (*worldMapDoMovement)(void *, float, float, bool);
worldMapDoMovement oWorldMapDoMovement = nullptr;

// 是否移动
bool g_allowVerticalMovement = true;

int hkWorldMapDoMovement(void *map, float fX, float fY, bool allowVerticalMovement) {
  LOGI("Doing map movement: fX - %f, fY - %f", fX, fY);
  return oWorldMapDoMovement(map, fX, fY, g_allowVerticalMovement);
}

#endif

inline void process() {
#if GAME_VERSION >= 1001

  if constexpr (WorldMapScrollAddr != UNKNOWN && KeepCenterAddr != UNKNOWN &&
                ScrollInertanceAddr != UNKNOWN) {
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

  if constexpr (WorldMapDoMovementAddr != UNKNOWN)
    PVZ2HookFunction(WorldMapDoMovementAddr, (void *)hkWorldMapDoMovement,
                     (void **)&oWorldMapDoMovement, "WorldMap::doMovement");

#endif
}
}  // namespace WorldMapVerticalScrolling

__attribute__((constructor)) void libRestructedLogic_ARM32__main() {
  LOGI("Initializing %s", LIB_TAG);

  DirectInstallOBB::process();  // 直装包

#if GAME_VERSION < 1031
  AliasToID::process();  // 添加植物 ID
#endif

#ifdef _DEBUG
  LogOutput::process();     // 输出日志
  CDNExpansion::process();  // 自定义 CDN 列表
#else
  if (DirectInstallOBB::available)
    LogOutput::process();  // 用于卡死主进程供 obb 复制
#endif

  RSBPathChangeAndDecryptRSB::process();  // RSB 加密
  PrimeGlyphCacheLimitation::process();   // 修改字符缓冲区大小
  MaxZoom::process();                     // 高视角
  WorldMapVerticalScrolling::process();   // 地图垂直移动

  LOGI("Finished initializing");
}
