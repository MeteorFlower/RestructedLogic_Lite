extern "C" {
#include "miniz.hpp"
}

class ApkUnzipper {
 public:
  // 直接将文件截断为 4 字节，以求更小占用
  static bool truncate_to_header(const std::string &file_path) {
    int rl_fd = open(file_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (rl_fd >= 0) {
      write(rl_fd, "1bsr", 4);
      close(rl_fd);
      LOGI("旧数据包截断为4字节头成功");
      return true;
    } else {
      LOGI("旧数据包截断为4字节头失败");
      return false;
    }
  }
  static bool extract_asset(const std::string &apk_path, const std::string &asset_internal_path,
                            const std::string &out_path) {
    mz_zip_archive zip{};

    if (!mz_zip_reader_init_file(&zip, apk_path.c_str(), 0)) {
      LOGI("Failed to open apk: %s", apk_path.c_str());
      return false;
    }

    int file_index = mz_zip_reader_locate_file(&zip, asset_internal_path.c_str(), nullptr, 0);

    if (file_index < 0) {
      LOGI("File not found in apk: %s", asset_internal_path.c_str());
      mz_zip_reader_end(&zip);
      return false;
    }

    //  关键点：解压到 .tmp 临时文件
    std::string tmp_path = out_path + ".tmp";

    // 移除旧的临时文件（如果存在）
    std::filesystem::remove(tmp_path);

    // 截断旧数据包只剩4字节头以求占用最小
    truncate_to_header(out_path);

    // 执行解压
    if (!mz_zip_reader_extract_to_file(&zip, file_index, tmp_path.c_str(), 0)) {
      LOGI("Extract failed");
      mz_zip_reader_end(&zip);
      return false;
    }
    mz_zip_reader_end(&zip);

    // 原子性替换：rename 会自动覆盖已存在的 out_path
    std::error_code ec;
    std::filesystem::rename(tmp_path, out_path, ec);

    if (ec) {
      LOGI("Atomic rename failed: %s", ec.message().c_str());
      return false;
    }

    return true;
  }
  // 解压到内存
  static bool extract_to_memory(const std::string &apk_path, const std::string &internal_path,
                                std::vector<uint8_t> &out) {
    mz_zip_archive zip{};

    if (!mz_zip_reader_init_file(&zip, apk_path.c_str(), 0)) {
      LOGI("Failed to open apk.");
      return false;
    }

    int file_index = mz_zip_reader_locate_file(&zip, internal_path.c_str(), nullptr, 0);

    if (file_index < 0) {
      LOGI("File not found: %s", internal_path.c_str());
      mz_zip_reader_end(&zip);
      return false;
    }

    size_t file_size = 0;

    void *data = mz_zip_reader_extract_to_heap(&zip, file_index, &file_size, 0);

    if (!data) {
      std::cerr << "Extract failed\n";
      mz_zip_reader_end(&zip);
      return false;
    }

    out.resize(file_size);
    memcpy(out.data(), data, file_size);

    mz_free(data);
    mz_zip_reader_end(&zip);

    return true;
  }
  // 统一的接口：获取 APK 内文件大小
  // 使用 uintmax_t 匹配 std::filesystem::file_size 的返回值
  static std::uintmax_t get_apk_asset_size(const std::string &apk_path,
                                           const std::string &asset_internal_path) {
    mz_zip_archive zip{};

    if (!mz_zip_reader_init_file(&zip, apk_path.c_str(), 0)) {
      return 0;
    }

    int file_index = mz_zip_reader_locate_file(&zip, asset_internal_path.c_str(), nullptr, 0);
    if (file_index < 0) {
      mz_zip_reader_end(&zip);
      return 0;
    }

    mz_zip_archive_file_stat file_stat{};
    if (!mz_zip_reader_file_stat(&zip, file_index, &file_stat)) {
      mz_zip_reader_end(&zip);
      return 0;
    }

    mz_zip_reader_end(&zip);

    // 显式转换以匹配 std::uintmax_t 类型
    return static_cast<std::uintmax_t>(file_stat.m_uncomp_size);
  }
  // 通用式自动识别获取apk内文件还是apk外文件大小
  static std::uintmax_t get_file_size(const std::filesystem::path &p,
                                      const std::string &apk_path = "") {
    if (apk_path.empty()) {
      // 如果没有传入 apk_path，直接调用系统 API 获取本地文件大小
      return std::filesystem::file_size(p);
    } else {
      // 否则，从 APK 内部获取该路径对应的大小
      return get_apk_asset_size(apk_path, p.string());
    }
  }
};