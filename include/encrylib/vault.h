#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "encrylib/secure_bytes.h"

namespace encrylib {

struct FileEntry {
  std::string id;
  std::string name;
  std::uint64_t size = 0;
  std::uint64_t added_unix_seconds = 0;
};

struct VaultConfig {
  std::uint32_t kdf_iterations = 120000;
};

class Vault {
 public:
  static void init(const std::filesystem::path& root,
                   const SecureString& password,
                   const VaultConfig& config = {});

  Vault(const std::filesystem::path& root, const SecureString& password);
  Vault(const Vault&) = delete;
  Vault& operator=(const Vault&) = delete;
  Vault(Vault&&) = default;
  Vault& operator=(Vault&&) = default;
  ~Vault();

  std::vector<FileEntry> list() const;
  void add_file(const std::filesystem::path& source,
                const std::string& stored_name,
                bool keep_source);
  void extract_file(const std::string& stored_name,
                    const std::filesystem::path& destination,
                    bool remove_after_extract);
  void delete_file(const std::string& stored_name);

 private:
  explicit Vault(std::filesystem::path root);

  void load(const SecureString& password);
  void load_manifest();
  void save_manifest();
  std::filesystem::path meta_path() const;
  std::filesystem::path manifest_path() const;
  std::filesystem::path objects_dir() const;
  std::filesystem::path object_path(const std::string& id) const;
  FileEntry* find_entry(const std::string& name);
  const FileEntry* find_entry(const std::string& name) const;

  std::filesystem::path root_;
  SecureBytes master_key_;
  Hash32 manifest_enc_key_{};
  Hash32 manifest_mac_key_{};
  Hash32 wrap_enc_key_{};
  Hash32 wrap_mac_key_{};
  std::vector<FileEntry> entries_;
};

}  // namespace encrylib
