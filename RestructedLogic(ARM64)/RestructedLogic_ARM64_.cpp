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
using _QWORD = uint64_t;

#pragma region IsRooted

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

#pragma endregion

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

namespace RSBDecrypt {
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
typedef __int64 (*RSBPathRecorder)(_QWORD *a1);
RSBPathRecorder oRSBPathRecorder = nullptr;

__int64 hkRSBPathRecorder(_QWORD *a1) {
  LOGI("Hooking RSBPathRecorder");
  if (!a1) {
    LOGI("RSBPathRecorder: a1 is null");
    return oRSBPathRecorder(a1);
  }

  // 调用原始函数
  __int64 result = oRSBPathRecorder(a1);
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
    a1[2] = (size_t)new_path;                     // 新路径指针
  } else {
    // 非动态分配
    a1[0] = 2 * new_path_len;  // a1[0] = 2 * 路径长度
    a1[1] = (size_t)new_path;    // a1[1] = 新路径指针
  }
  LOGI("RSBPathRecorder: Replaced path with %s", temp_path.c_str());

  return result;
}

inline void process() {
  if constexpr (RSBPathRecorderAddr != UNKNOWN && ResourceManagerFuncAddr != UNKNOWN) {
    // Hook RSB 读取函数
    PVZ2HookFunction(RSBPathRecorderAddr, (void *)hkRSBPathRecorder, (void **)&oRSBPathRecorder,
                     "ResourceManager::RSBPathRecorder");
  }
}
}  // namespace RSBDecrypt

namespace PrimeGlyphCacheLimitation {
typedef __int64 (*PrimeGlyphCacheLimitation)(__int64 a1, __int64 a2, __int64 a3, int a4);
PrimeGlyphCacheLimitation oPrimeGlyphCacheLimitation = nullptr;

// 一路：高端设备缓冲大小为2048，中端设备为1024，低端设备为512。经过测试，缓冲大小最大只能设为2048，设为更高值，会导致进入游戏后文字渲染全为空白，这与设为0的效果一致。
__int64 hkPrimeGlyphCacheLimitation(__int64 a1, __int64 a2, __int64 a3, int a4) {
  __int64 result = oPrimeGlyphCacheLimitation(a1, a2, a3, a4);
  *(_DWORD *)(a1 + 164) = 2048;
  LOGI("Hooked PrimeGlyphCacheLimitation: Modified a1 + 164 to %d", *(_DWORD *)(a1 + 164));
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

#elif GAME_VERSION == 1031

typedef __int64 (*LawnAppScreenWidthHeight)(__int64 *a1, int a2);
LawnAppScreenWidthHeight oLawnAppScreenWidthHeight = nullptr;

__int64 hkLawnAppScreenWidthHeight(__int64 *a1, int a2) {
  // 1. 先执行原函数，让内部逻辑完成内存写入
  __int64 result = oLawnAppScreenWidthHeight(a1, a2);

  if (a1 == nullptr)
    return result;

  // 2. 根据偏移直接提取数据
#ifdef _DEBUG
  mOrigScreenWidth = *((unsigned int *)a1 + 445);
#endif
  mOrigScreenHeight = *((unsigned int *)a1 + 446);

  mWidth = *((unsigned int *)a1 + 43);
#ifdef _DEBUG
  mHeight = *((unsigned int *)a1 + 44);
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

namespace WorldMapVerticalScrolling {
// 本来我完全可以让你们每个版本都去找通用的三个偏移的，但是为了你们旧版本的，我采用条件编译了
// 旧版只需要找一个偏移，而新版则需要找三个

#if GAME_VERSION >= 1001

// 新版需要hook三个函数，而且由于该死的内联，不能把函数全反编译了，所以直接暴力扩边界让它们强行切到垂直移动判定
// 拖动函数:
typedef __int64 (*WorldMapScroll)(__int64 a1, __int64 a2);
WorldMapScroll oWorldMapScroll = nullptr;
__int64 hkWorldMapScroll(__int64 a1, __int64 a2) {
  *(int32_t *)(a1 + 512) = -1000000000;
  *(int32_t *)(a1 + 516) = -1000000000;
  *(int32_t *)(a1 + 520) = 2000000000;
  *(int32_t *)(a1 + 524) = 2000000000;
  return oWorldMapScroll(a1, a2);
}
// 居中函数：
typedef __int64 (*KeepCenter)(__int64 a1, float *a2, char a3);
KeepCenter oKeepCenter = nullptr;
__int64 hkKeepCenter(__int64 a1, float *a2, char a3) {
  *(int32_t *)(a1 + 512) = -1000000000;
  *(int32_t *)(a1 + 516) = -1000000000;
  *(int32_t *)(a1 + 520) = 2000000000;
  *(int32_t *)(a1 + 524) = 2000000000;
  return oKeepCenter(a1, a2, true);
}
// 惯性函数：
typedef void (*ScrollInertance)(__int64 a1);
ScrollInertance oScrollInertance = nullptr;
void hkScrollInertance(__int64 a1) {
  *(int32_t *)(a1 + 512) = -1000000000;
  *(int32_t *)(a1 + 516) = -1000000000;
  *(int32_t *)(a1 + 520) = 2000000000;
  *(int32_t *)(a1 + 524) = 2000000000;
  oScrollInertance(a1);
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

#endif
}
}  // namespace WorldMapVerticalScrolling

namespace HookResourceManagerFunc {

#define USE_DIRECT_INSTALL_OBB
#define USE_RSB_DECRYPT

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

#if GAME_VERSION < 1031
  AliasToID::process();  // 添加植物 ID
#endif

#ifdef _DEBUG
  LogOutput::process();  // 输出日志
#endif

  RSBDecrypt::process();                 // RSB 加密
  PrimeGlyphCacheLimitation::process();  // 修改字符缓冲区大小
  MaxZoom::process();                    // 高视角
  WorldMapVerticalScrolling::process();  // 地图垂直移动

  LOGI("Finished initializing");
}
