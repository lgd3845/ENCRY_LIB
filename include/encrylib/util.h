#pragma once

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>

#include "encrylib/secure_bytes.h"

namespace encrylib {

void append_u32(Bytes& out, std::uint32_t value);
void append_u64(Bytes& out, std::uint64_t value);
void append_bytes(Bytes& out, std::span<const std::uint8_t> bytes);
std::uint32_t read_u32(std::span<const std::uint8_t> bytes, std::size_t& offset);
std::uint64_t read_u64(std::span<const std::uint8_t> bytes, std::size_t& offset);
std::span<const std::uint8_t> read_span(std::span<const std::uint8_t> bytes,
                                        std::size_t& offset,
                                        std::size_t size);

Bytes read_file(const std::filesystem::path& path);
void write_file_atomic(const std::filesystem::path& path,
                       std::span<const std::uint8_t> bytes);
void ensure_directory(const std::filesystem::path& path);
std::string sanitize_name(const std::filesystem::path& source,
                          const std::string& requested_name);
std::string current_time_string();

}  // namespace encrylib
