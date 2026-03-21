extern "C" {
#include "miniz.hpp"
#include "../XXHash/xxhash.hpp"
}

class HashComparer {
 public:
  // 辅助函数：计算单个文件的哈希值
  static XXH64_hash_t compute_file_hash(const std::filesystem::path &filePath) {
    // 基础检查：文件是否存在且是常规文件
    if (!std::filesystem::exists(filePath) || !std::filesystem::is_regular_file(filePath)) {
      return 0;
    }

    std::ifstream file(filePath, std::ios::binary);
    if (!file)
      return 0;

    // 使用 XXH3 的流式处理（State），防止大文件撑爆内存
    XXH3_state_t *state = XXH3_createState();
    XXH3_64bits_reset(state);

    // 使用缓冲区分段计算哈希
    std::vector<char> buffer(256 * 1024);
    while (file.read(buffer.data(), buffer.size()) || file.gcount() > 0) {
      XXH3_64bits_update(state, buffer.data(), file.gcount());
    }

    XXH64_hash_t hash = XXH3_64bits_digest(state);
    XXH3_freeState(state);
    return hash;
  }

  // 根据路径对比函数
  static bool are_files_identical(const std::filesystem::path &p1,
                                  const std::filesystem::path &p2) {
    // 优化 1：先比大小。如果大小不等，内容绝对不等，没必要算哈希。
    if (std::filesystem::file_size(p1) != std::filesystem::file_size(p2)) {
      return false;
    }

    // 优化 2：计算并对比哈希
    return compute_file_hash(p1) == compute_file_hash(p2);
  }

  // 根据哈希值对比
  static bool are_hashes_identical(const uint64_t p1, const uint64_t p2) {
    return p1 == p2;
  }

  // 回调函数：适配 XXH3
  static size_t hash_update_callback(void *pUser_data, mz_uint64 file_ofs, const void *pBuffer,
                                     size_t n) {
    XXH3_state_t *state = static_cast<XXH3_state_t *>(pUser_data);
    // XXH3 的更新接口是 XXH3_64bits_update
    if (XXH3_64bits_update(state, pBuffer, n) == XXH_OK) {
      return n;
    }
    return 0;
  }

  static XXH64_hash_t get_asset_hash(const std::string &apk_path,
                                 const std::string &asset_internal_path) {
    mz_zip_archive zip{};

    // 1. 初始化并打开 APK
    if (!mz_zip_reader_init_file(&zip, apk_path.c_str(), 0)) {
      // LOGI("Failed to open apk: %s", apk_path.c_str());
      return 0;
    }

    // 2. 定位目标文件
    int file_index = mz_zip_reader_locate_file(&zip, asset_internal_path.c_str(), nullptr, 0);

    if (file_index < 0) {
      mz_zip_reader_end(&zip);
      return 0;
    }

    // 3. 准备 XXH3 64位状态机
    XXH3_state_t *state = XXH3_createState();
    if (!state) {
      mz_zip_reader_end(&zip);
      return 0;
    }
    // 重置状态机（XXH3 特有 API）
    XXH3_64bits_reset(state);

    // 4. 流式解压
    if (!mz_zip_reader_extract_to_callback(&zip, (mz_uint)file_index, hash_update_callback, state,
                                           0)) {
      XXH3_freeState(state);
      mz_zip_reader_end(&zip);
      return 0;
    }

    // 5. 生成 64 位哈希
    XXH64_hash_t final_hash = XXH3_64bits_digest(state);

    // 6. 清理
    XXH3_freeState(state);
    mz_zip_reader_end(&zip);

    return final_hash;
  }

  // 读取预存的哈希值
  static XXH64_hash_t read_hash_after_header(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp)
      return 0;

    XXH64_hash_t hash_val = 0;

    // 1. 直接跳到偏移量为 4 的位置
    if (fseek(fp, 4, SEEK_SET) == 0) {
      // 2. 读取 8 字节的 64 位哈希
      if (fread(&hash_val, sizeof(XXH64_hash_t), 1, fp) != 1) {
        hash_val = 0;
      }
    }

    fclose(fp);
    return hash_val;
  }

  /**
   * @brief 生成指纹文件
   * @param targetFilePath 要计算哈希的原始文件路径
   * @param outputHashPath 生成的指纹文件保存路径
   * @param header 4字节的头部字符串
   */

  // 哈希值文件生成函数
  static bool generate_hash_file_with_header(const std::filesystem::path &targetFilePath,
                                             const std::filesystem::path &outputHashPath,
                                             const char *header) {
    // 1. 计算 64 位哈希
    XXH64_hash_t hashResult = compute_file_hash(targetFilePath);
    if (hashResult == 0)
      return false;

    // 2. 二进制写入模式打开
    std::ofstream outFile(outputHashPath, std::ios::binary | std::ios::trunc);
    if (!outFile)
      return false;

    // 3. 写入 4 字节头部
    outFile.write(header, 4);

    // 4. 写入 8 字节哈希值 (uint64_t / XXH64_hash_t)
    outFile.write(reinterpret_cast<const char *>(&hashResult), sizeof(XXH64_hash_t));

    outFile.close();
    return true;
  }
};
