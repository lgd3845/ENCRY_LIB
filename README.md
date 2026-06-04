# ENCRY_LIB

高性能国密保密文件库原型，使用 C++20 实现，生成原生 Linux 可执行文件 `encrylib`。

## 构建

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
ctest --test-dir build --output-on-failure
```

## 使用

```bash
# 初始化文件库
./build/encrylib init ./myvault

# 移入文件；成功后源文件会被删除
./build/encrylib add ./myvault ./secret.txt

# 浏览文件库
./build/encrylib list ./myvault

# 移出文件；成功后库内条目会被删除
./build/encrylib extract ./myvault secret.txt ./restore_dir

# 复制语义
./build/encrylib add ./myvault ./secret.txt --keep-source
./build/encrylib extract ./myvault secret.txt ./restore_dir --keep-in-vault
```

密码可交互输入，也可用 `ENCRYLIB_PASSWORD` 或 `--password` 便于脚本化测试。交互输入更安全，因为命令行参数和环境变量可能被同机用户或 shell 历史泄漏。

## 性能测试

```bash
./build/encrylib_bench
```

详细设计、密钥策略和本机性能结果见 [docs/report.md](docs/report.md)。
