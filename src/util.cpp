#include "encrylib/util.h"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <system_error>

namespace encrylib {

namespace {

constexpr std::uint64_t kMaxFileBytes =
    static_cast<std::uint64_t>(1024) * 1024 * 1024 * 16;

}  // namespace

void append_u32(Bytes& out, std::uint32_t value) {
  out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xffU));
  out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xffU));
  out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xffU));
  out.push_back(static_cast<std::uint8_t>(value & 0xffU));
}

void append_u64(Bytes& out, std::uint64_t value) {
  for (int shift = 56; shift >= 0; shift -= 8) {
    out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffU));
  }
}

void append_bytes(Bytes& out, std::span<const std::uint8_t> bytes) {
  out.insert(out.end(), bytes.begin(), bytes.end());
}

std::uint32_t read_u32(std::span<const std::uint8_t> bytes,
                       std::size_t& offset) {
  if (bytes.size() - offset < 4) {
    throw std::runtime_error("unexpected end of data");
  }
  const std::uint32_t value =
      (static_cast<std::uint32_t>(bytes[offset]) << 24) |
      (static_cast<std::uint32_t>(bytes[offset + 1]) << 16) |
      (static_cast<std::uint32_t>(bytes[offset + 2]) << 8) |
      static_cast<std::uint32_t>(bytes[offset + 3]);
  offset += 4;
  return value;
}

std::uint64_t read_u64(std::span<const std::uint8_t> bytes,
                       std::size_t& offset) {
  if (bytes.size() - offset < 8) {
    throw std::runtime_error("unexpected end of data");
  }
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value = (value << 8) | bytes[offset + static_cast<std::size_t>(i)];
  }
  offset += 8;
  return value;
}

std::span<const std::uint8_t> read_span(std::span<const std::uint8_t> bytes,
                                        std::size_t& offset,
                                        std::size_t size) {
  if (bytes.size() - offset < size) {
    throw std::runtime_error("unexpected end of data");
  }
  const auto result = bytes.subspan(offset, size);
  offset += size;
  return result;
}

Bytes read_file(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary | std::ios::ate);
  if (!input) {
    throw std::runtime_error("failed to open file for reading: " +
                             path.string());
  }
  const auto end = input.tellg();
  if (end < 0) {
    throw std::runtime_error("failed to determine file size: " + path.string());
  }
  const auto size = static_cast<std::uint64_t>(end);
  if (size > kMaxFileBytes) {
    throw std::runtime_error("file is too large for this build: " +
                             path.string());
  }
  input.seekg(0, std::ios::beg);
  Bytes bytes(static_cast<std::size_t>(size));
  if (!bytes.empty()) {
    input.read(reinterpret_cast<char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
    if (!input) {
      throw std::runtime_error("failed to read file: " + path.string());
    }
  }
  return bytes;
}

void write_file_atomic(const std::filesystem::path& path,
                       std::span<const std::uint8_t> bytes) {
  const auto parent = path.parent_path();
  if (!parent.empty()) {
    ensure_directory(parent);
  }
  const auto tmp = path.string() + ".tmp";
  {
    std::ofstream output(tmp, std::ios::binary | std::ios::trunc);
    if (!output) {
      throw std::runtime_error("failed to open file for writing: " + tmp);
    }
    if (!bytes.empty()) {
      output.write(reinterpret_cast<const char*>(bytes.data()),
                   static_cast<std::streamsize>(bytes.size()));
      if (!output) {
        throw std::runtime_error("failed to write file: " + tmp);
      }
    }
    output.flush();
    if (!output) {
      throw std::runtime_error("failed to flush file: " + tmp);
    }
  }
  std::filesystem::rename(tmp, path);
}

void ensure_directory(const std::filesystem::path& path) {
  if (path.empty()) {
    return;
  }
  std::error_code ec;
  if (std::filesystem::exists(path, ec)) {
    if (!std::filesystem::is_directory(path, ec)) {
      throw std::runtime_error("path exists but is not a directory: " +
                               path.string());
    }
    return;
  }
  if (!std::filesystem::create_directories(path, ec) && ec) {
    throw std::runtime_error("failed to create directory: " + path.string() +
                             ": " + ec.message());
  }
}

std::string sanitize_name(const std::filesystem::path& source,
                          const std::string& requested_name) {
  std::string name =
      requested_name.empty() ? source.filename().string() : requested_name;
  if (name.empty() || name == "." || name == "..") {
    throw std::runtime_error("invalid stored file name");
  }
  std::replace(name.begin(), name.end(), '\\', '/');
  if (name.find('/') != std::string::npos) {
    throw std::runtime_error("stored file name must not contain path separators");
  }
  if (name.find('\0') != std::string::npos) {
    throw std::runtime_error("stored file name contains NUL");
  }
  return name;
}

std::string current_time_string() {
  const auto now = std::chrono::system_clock::now();
  const auto time = std::chrono::system_clock::to_time_t(now);
  std::tm tm{};
#if defined(_WIN32)
  gmtime_s(&tm, &time);
#else
  gmtime_r(&time, &tm);
#endif
  std::ostringstream out;
  out << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
  return out.str();
}

}  // namespace encrylib
