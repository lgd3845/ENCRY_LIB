#include <cstdlib>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <iostream>
#include <iterator>
#include <optional>
#include <stdexcept>
#include <string>
#include <termios.h>
#include <unistd.h>
#include <vector>

#include "encrylib/vault.h"

namespace {

using encrylib::SecureString;
using encrylib::Vault;
using encrylib::VaultConfig;

void usage() {
  std::cerr
      << "Usage:\n"
      << "  encrylib init <vault> [--iterations N] [--password P]\n"
      << "  encrylib list <vault> [--password P]\n"
      << "  encrylib add <vault> <source> [--name NAME] [--keep-source] [--password P]\n"
      << "  encrylib extract <vault> <name> [destination] [--keep-in-vault] [--password P]\n"
      << "  encrylib remove <vault> <name> [--password P]\n\n"
      << "Password can also be provided with ENCRYLIB_PASSWORD.\n";
}

std::optional<std::string> take_option(std::vector<std::string>& args,
                                       const std::string& name) {
  for (auto it = args.begin(); it != args.end(); ++it) {
    if (*it == name) {
      if (std::next(it) == args.end()) {
        throw std::runtime_error("missing value for " + name);
      }
      std::string value = *std::next(it);
      args.erase(it, std::next(std::next(it)));
      return value;
    }
  }
  return std::nullopt;
}

bool take_flag(std::vector<std::string>& args, const std::string& name) {
  for (auto it = args.begin(); it != args.end(); ++it) {
    if (*it == name) {
      args.erase(it);
      return true;
    }
  }
  return false;
}

std::string read_password_from_tty() {
  std::cerr << "Password: ";
  std::string password;
  if (isatty(STDIN_FILENO) == 0) {
    std::getline(std::cin, password);
    return password;
  }

  termios old_term{};
  if (tcgetattr(STDIN_FILENO, &old_term) != 0) {
    std::getline(std::cin, password);
    return password;
  }
  termios new_term = old_term;
  new_term.c_lflag &= static_cast<tcflag_t>(~ECHO);
  if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_term) != 0) {
    std::getline(std::cin, password);
    return password;
  }
  std::getline(std::cin, password);
  tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_term);
  std::cerr << "\n";
  return password;
}

SecureString obtain_password(const std::optional<std::string>& cli_password) {
  if (cli_password.has_value()) {
    return SecureString(*cli_password);
  }
  if (const char* env = std::getenv("ENCRYLIB_PASSWORD"); env != nullptr) {
    return SecureString(std::string(env));
  }
  return SecureString(read_password_from_tty());
}

std::string format_time(std::uint64_t seconds) {
  const auto time = static_cast<std::time_t>(seconds);
  std::tm tm{};
  gmtime_r(&time, &tm);
  char buffer[32]{};
  std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &tm);
  return buffer;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc < 2) {
      usage();
      return 1;
    }

    std::vector<std::string> args;
    args.reserve(static_cast<std::size_t>(argc - 1));
    for (int i = 1; i < argc; ++i) {
      args.emplace_back(argv[i]);
    }

    const auto cli_password = take_option(args, "--password");
    const std::string command = args.front();
    args.erase(args.begin());

    if (command == "-h" || command == "--help" || command == "help") {
      usage();
      return 0;
    }

    if (command == "init") {
      const auto iterations_arg = take_option(args, "--iterations");
      if (args.size() != 1) {
        usage();
        return 1;
      }
      VaultConfig config;
      if (iterations_arg.has_value()) {
        const auto parsed = std::stoul(*iterations_arg);
        if (parsed > UINT32_MAX) {
          throw std::runtime_error("iteration count is too large");
        }
        config.kdf_iterations = static_cast<std::uint32_t>(parsed);
      }
      auto password = obtain_password(cli_password);
      Vault::init(args[0], password, config);
      std::cout << "initialized vault: " << args[0] << "\n";
      return 0;
    }

    if (command == "list") {
      if (args.size() != 1) {
        usage();
        return 1;
      }
      auto password = obtain_password(cli_password);
      Vault vault(args[0], password);
      const auto entries = vault.list();
      std::cout << "NAME\tSIZE\tADDED_UTC\n";
      for (const auto& entry : entries) {
        std::cout << entry.name << "\t" << entry.size << "\t"
                  << format_time(entry.added_unix_seconds) << "\n";
      }
      return 0;
    }

    if (command == "add") {
      const bool keep_source = take_flag(args, "--keep-source");
      const auto stored_name = take_option(args, "--name");
      if (args.size() != 2) {
        usage();
        return 1;
      }
      auto password = obtain_password(cli_password);
      Vault vault(args[0], password);
      vault.add_file(args[1], stored_name.value_or(""), keep_source);
      std::cout << "added: "
                << (stored_name.has_value()
                        ? *stored_name
                        : std::filesystem::path(args[1]).filename().string())
                << "\n";
      return 0;
    }

    if (command == "extract") {
      const bool keep_in_vault = take_flag(args, "--keep-in-vault");
      if (args.size() != 2 && args.size() != 3) {
        usage();
        return 1;
      }
      auto password = obtain_password(cli_password);
      Vault vault(args[0], password);
      const std::filesystem::path destination =
          (args.size() == 3) ? std::filesystem::path(args[2])
                             : std::filesystem::path(".");
      vault.extract_file(args[1], destination, !keep_in_vault);
      std::cout << "extracted: " << args[1] << "\n";
      return 0;
    }

    if (command == "remove" || command == "delete") {
      if (args.size() != 2) {
        usage();
        return 1;
      }
      auto password = obtain_password(cli_password);
      Vault vault(args[0], password);
      vault.delete_file(args[1]);
      std::cout << "removed: " << args[1] << "\n";
      return 0;
    }

    usage();
    return 1;
  } catch (const std::exception& e) {
    std::cerr << "error: " << e.what() << "\n";
    return 2;
  }
}
