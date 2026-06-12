# Media Crypto: TEE 视频分块加密存储

`media_crypto` 是一个基于 OP-TEE 的视频/大文件加密存储原型。它面向“TEE 隔离环境视频的加密存储”选题，核心目标是避免把完整视频一次性加载到 TEE 中，而是采用普通世界分块读写、安全世界分块加解密的流式方案。

当前版本已经实现：

- host 端分块读取输入文件，每块默认 `64 KiB`。
- TA 端在 TEE 中使用 `SM4-CTR` 执行分块加解密。
- 加密文件携带自描述 header，记录类型、算法、原始大小、密文大小、IV 等信息。
- 加密文件末尾携带 `HMAC-SM3` 完整性标签。
- 解密前先校验 HMAC，防止密文被篡改。
- 支持视频专用命令 `video-encrypt` / `video-decrypt`。
- 支持 `info` 命令查看加密文件元数据。
- 支持攻击实验命令，生成被篡改、截断的加密文件样本。
- 支持 `benchmark` / `video-benchmark` 输出效率评测指标。
- 支持加解密性能统计输出。

## 目录结构

```text
media_crypto/
├── 1.sh                         # 一键构建脚本，编译 host 和 TA 并复制产物
├── Makefile                     # 顶层 Makefile，调用 host/ta 子目录构建
├── README.md                    # 当前说明文档
├── build_log.txt                # 历史构建日志
├── check_ta_sdk.sh              # TA SDK 检查脚本
├── compile.sh                   # 旧环境构建辅助脚本
├── host/
│   ├── Makefile                 # host 端编译规则
│   ├── media_crypto.c           # 普通世界 CA 主程序
│   └── media_crypto             # 编译生成的 AArch64 可执行程序
└── ta/
    ├── Makefile                 # TA 编译规则
    ├── sub.mk                   # TA 源文件和 include 目录声明
    ├── user_ta_header_defines.h # TA UUID、栈/堆大小、TA 属性
    ├── include/
    │   └── ta_media_crypto.h    # CA/TA 共用 UUID、命令号、常量
    ├── media_crypto_ta.c        # 安全世界 TA 逻辑
    └── 8aaaf200-2450-11e4-abe20002a5d5c51b.ta # 编译签名后的 TA
```

部分 `.o`、`.elf`、`.map`、`.dmp`、`.cmd` 文件是构建中间产物，不是主要源码。

## 总体架构

系统由两个部分组成：

```text
普通世界 Linux 用户态
  host/media_crypto
      |
      | TEEC_InvokeCommand()
      v
安全世界 OP-TEE
  ta/media_crypto_ta.c
```

host 端负责：

- 打开输入/输出文件。
- 读取和写入加密文件 header。
- 按 `64 KiB` 分块读取视频或普通文件。
- 将数据块通过 OP-TEE Client API 发送给 TA。
- 接收加密/解密后的数据块并写回文件。
- 调用 TA 计算/校验 HMAC-SM3。
- 输出进度、性能统计和文件信息。

TA 端负责：

- 维护每个 session 的加密上下文。
- 使用 `TEE_ALG_SM4_CTR` 进行分块加解密。
- 使用 `TEE_ALG_HMAC_SM3` 进行完整性校验。
- 使用 `TEE_GenerateRandom()` 生成随机 IV。
- 在 TEE 内保存加密密钥和 HMAC key 的使用逻辑。

## 加密文件格式

加密输出文件格式如下：

```text
[media_crypto_header][ciphertext blocks][HMAC-SM3 tag]
```

header 字段由 `host/media_crypto.c` 中的 `media_crypto_header_t` 定义：

```c
typedef struct __attribute__((packed)) media_crypto_header {
    uint8_t magic[8];       // "MCTEEv2"
    uint32_t version;       // 当前为 2
    uint32_t algorithm;     // 当前为 SM4-CTR
    uint32_t flags;         // video 标记等
    uint32_t header_size;   // header 大小
    uint64_t plain_size;    // 原始文件大小
    uint64_t cipher_size;   // 补齐后的密文大小
    uint32_t chunk_size;    // 默认 65536
    uint8_t iv[16];         // TEE 生成的随机 IV
    char media_type[16];    // "video" 或 "file"
    uint8_t reserved[16];   // 保留字段
} media_crypto_header_t;
```

注意：为了规避部分 OP-TEE/SM4-CTR 环境在非 16 字节尾块上的兼容性问题，host 端会把最后一块补零到 16 字节边界后送入 TA 加密。因此：

```text
cipher_size >= plain_size
cipher_size - plain_size < 16
```

解密时会根据 `plain_size` 截断补零部分，所以解密结果和原始视频逐字节一致。

## TA 命令接口

命令号定义在 `ta/include/ta_media_crypto.h`：

```c
#define TA_MEDIA_CRYPTO_CMD_INC_VALUE    0
#define TA_MEDIA_CRYPTO_CMD_ENCRYPT_INIT 1
#define TA_MEDIA_CRYPTO_CMD_DECRYPT_INIT 2
#define TA_MEDIA_CRYPTO_CMD_UPDATE       3
#define TA_MEDIA_CRYPTO_CMD_FINISH       4
#define TA_MEDIA_CRYPTO_CMD_HMAC_INIT    5
#define TA_MEDIA_CRYPTO_CMD_HMAC_UPDATE  6
#define TA_MEDIA_CRYPTO_CMD_HMAC_FINAL   7
#define TA_MEDIA_CRYPTO_CMD_HMAC_FINISH  8
```

主要调用流程：

```text
加密：
  HMAC_INIT
  ENCRYPT_INIT -> TA 生成 IV
  HMAC_UPDATE(header)
  循环：
    UPDATE(plain block) -> cipher block
    HMAC_UPDATE(cipher block)
  HMAC_FINAL -> tag
  FINISH

解密：
  读取 header
  HMAC_INIT
  HMAC_UPDATE(header)
  循环：
    HMAC_UPDATE(cipher block)
  HMAC_FINAL -> 与文件末尾 tag 比较
  DECRYPT_INIT(header.iv)
  循环：
    UPDATE(cipher block) -> plain block
    按 plain_size 截掉补零
  FINISH
```

## 主要源码说明

### `host/media_crypto.c`

普通世界 CA 程序，运行在 Linux 用户态，链接 `libteec`。

核心功能：

- `init_tee()` / `finalize_tee()`
  - 初始化 `TEEC_Context`
  - 根据 TA UUID 打开/关闭 session

- `encrypt_file()`
  - 支持 `encrypt` 和 `video-encrypt`
  - 创建 header
  - 请求 TA 生成 IV
  - 分块读输入文件
  - 最后一块按 16 字节补零
  - 调用 TA 加密
  - 写出密文和 HMAC tag
  - 输出加密性能

- `decrypt_file()`
  - 支持 `decrypt` 和 `video-decrypt`
  - 读取并校验 header
  - 校验 HMAC-SM3
  - 分块调用 TA 解密
  - 根据 `plain_size` 去掉补零
  - 输出解密性能

- `show_info()`
  - 实现 `info` 命令
  - 展示文件类型、算法、大小、chunk size、HMAC 状态等

- `cipher_init()` / `cipher_update()`
  - 封装 CA 到 TA 的 SM4-CTR 调用

- `hmac_init()` / `hmac_update()` / `hmac_final()`
  - 封装 CA 到 TA 的 HMAC-SM3 调用

### `ta/media_crypto_ta.c`

安全世界 TA 程序，运行在 OP-TEE 中。

核心功能：

- `TA_CreateEntryPoint()`
  - TA 创建入口

- `TA_OpenSessionEntryPoint()`
  - 为每个 session 分配 `media_crypto_ctx_t`
  - 保存 cipher/HMAC operation handle

- `TA_CloseSessionEntryPoint()`
  - 释放 cipher/HMAC operation 和 transient key object

- `cipher_init()`
  - 加密模式下生成随机 IV
  - 解密模式下使用 header 中的 IV
  - 初始化 `TEE_ALG_SM4_CTR`

- `cipher_update()`
  - 调用 `TEE_CipherUpdate()` 处理数据块

- `hmac_init()` / `hmac_update()` / `hmac_final()`
  - 使用 `TEE_ALG_HMAC_SM3` 完整性校验加密文件

- `TA_InvokeCommandEntryPoint()`
  - 根据命令号分发到对应功能

当前版本为了保证板子运行稳定，使用 TA 内部 demo key。后续如果要继续增强安全性，可以把 demo key 替换为 TEE Persistent Object 或硬件派生密钥。

### `ta/include/ta_media_crypto.h`

CA 和 TA 共用的接口文件：

- TA UUID
- key/IV/HMAC 长度
- 命令号

这里不要包含 `tee_client_api.h`，因为它属于普通世界 API；该头文件同时被 TA 侧包含，必须保持 CA/TA 都能使用。

### `ta/user_ta_header_defines.h`

定义 TA 元信息：

- `TA_UUID`
- `TA_FLAGS`
- `TA_STACK_SIZE`
- `TA_DATA_SIZE`
- TA 描述和版本

### `1.sh`

一键构建脚本：

1. 设置 TA SDK 路径：

```bash
TA_DEV_KIT_DIR=/home/hfut/phytium-pi-os/output/build/phytium-optee-v4.6.0/out/data/link/export-ta_arm64
```

2. 设置 host 端 `libteec` 导出路径：

```bash
TEEC_EXPORT=/home/hfut/phytium-pi-os/output/build/phytium-optee-v4.6.0/out/data/link/export/usr
```

3. 生成 TA 公钥文件。

4. 编译 host 程序。

5. 编译 TA。

6. 将产物复制到：

```text
../../out/data/bin/
../../out/data/optee_armtz/
```

## 编译

在编译机上执行：

```bash
cd /home/hfut/phytium-pi-os/output/build/phytium-optee-v4.6.0/app/media_crypto
./1.sh
```

成功时会看到：

```text
=== Build finished successfully ===
```

生成的关键产物：

```text
out/data/bin/media_crypto
out/data/optee_armtz/8aaaf200-2450-11e4-abe20002a5d5c51b.ta
```

完整路径通常是：

```text
/home/hfut/phytium-pi-os/output/build/phytium-optee-v4.6.0/out/data/bin/media_crypto
/home/hfut/phytium-pi-os/output/build/phytium-optee-v4.6.0/out/data/optee_armtz/8aaaf200-2450-11e4-abe20002a5d5c51b.ta
```

## 部署到目标板

需要拷贝两个文件：

1. host 可执行程序：

```text
media_crypto
```

可以放在板子的任意目录，例如：

```text
/home/dejavu/桌面/media_crypto/host/media_crypto
```

2. TA 文件：

```text
8aaaf200-2450-11e4-abe20002a5d5c51b.ta
```

放到板子的 TA 加载目录：

```bash
sudo cp 8aaaf200-2450-11e4-abe20002a5d5c51b.ta /data/optee_armtz/
```

给 host 程序执行权限：

```bash
chmod +x /home/dejavu/桌面/media_crypto/host/media_crypto
```

确认 OP-TEE 设备存在：

```bash
ls /dev/tee*
```

通常应能看到：

```text
/dev/tee0
/dev/teepriv0
```

## 命令用法

在板子上进入程序目录：

```bash
cd /home/dejavu/桌面/media_crypto
```

查看帮助：

```bash
./host/media_crypto
```

支持命令：

```text
encrypt        普通文件加密
decrypt        普通文件解密
video-encrypt  视频文件加密
video-decrypt  视频文件解密
info           查看加密文件信息
attack-bitflip 生成密文被篡改的攻击样本
attack-header  生成 header 被篡改的攻击样本
attack-tag     生成 HMAC tag 被篡改的攻击样本
attack-truncate 生成被截断的攻击样本
attack-all     一键生成 bitflip/header/tag/truncated 四类攻击样本
benchmark      普通文件加解密效率评测
video-benchmark 视频加解密效率评测
```

## 视频加密演示

假设原视频是：

```text
/home/dejavu/桌面/test.mp4
```

加密：

```bash
sudo ./host/media_crypto video-encrypt /home/dejavu/桌面/test.mp4 /tmp/test.mp4.enc
```

成功输出类似：

```text
video encrypt: 12645566/12645566 bytes (100%)
video encrypt stats: 12.06 MiB in 6.137 s, 1.96 MiB/s
video-encrypt completed successfully.
```

查看加密文件信息：

```bash
sudo ./host/media_crypto info /tmp/test.mp4.enc
```

输出类似：

```text
Media Crypto File Info
  Type          : video
  Version       : 2
  Algorithm     : SM4-CTR
  Integrity     : HMAC-SM3 enabled
  TEE key       : TA private demo key
  Plain size    : 12645566 bytes (12.06 MiB)
  Cipher size   : 12645568 bytes (12.06 MiB)
  Chunk size    : 65536 bytes
  Header size   : 92 bytes
  HMAC size     : 32 bytes
  File size     : 12645692 bytes
  Size check    : ok
```

说明：

- `Plain size` 是原始视频大小。
- `Cipher size` 是补齐后的密文大小。
- `Cipher size` 可能比 `Plain size` 大 0 到 15 字节，这是最后一块 16 字节补齐导致的正常现象。
- `File size = Header size + Cipher size + HMAC size`。
- `Size check: ok` 表示加密文件结构完整。

解密：

```bash
sudo ./host/media_crypto video-decrypt /tmp/test.mp4.enc /tmp/test.dec.mp4
```

成功输出类似：

```text
video verify: 12645568/12645568 bytes (100%)
video decrypt: 12645566/12645566 bytes (100%)
video decrypt stats: 12.06 MiB in 4.140 s, 2.91 MiB/s
video-decrypt completed successfully.
```

校验原视频和解密视频是否完全一致：

```bash
cmp /home/dejavu/桌面/test.mp4 /tmp/test.dec.mp4
```

如果 `cmp` 没有任何输出，说明两个文件逐字节完全一致。

打开解密视频：

```bash
xdg-open /tmp/test.dec.mp4
```

或复制到桌面双击打开：

```bash
cp /tmp/test.dec.mp4 /home/dejavu/桌面/
```

## 证明加密文件不能直接播放

尝试打开加密文件：

```bash
xdg-open /tmp/test.mp4.enc
```

正常情况下播放器无法识别或无法播放。因为加密文件已经不是标准 MP4 格式，而是：

```text
MCTEEv2 header + SM4-CTR 密文 + HMAC-SM3 tag
```

这可以作为演示“视频已经加密存储”的直观证据。

## 普通文件测试

生成随机测试文件：

```bash
dd if=/dev/urandom of=/tmp/test.bin bs=1M count=5
```

加密：

```bash
sudo ./host/media_crypto encrypt /tmp/test.bin /tmp/test.bin.enc
```

查看信息：

```bash
sudo ./host/media_crypto info /tmp/test.bin.enc
```

解密：

```bash
sudo ./host/media_crypto decrypt /tmp/test.bin.enc /tmp/test.bin.dec
```

校验：

```bash
cmp /tmp/test.bin /tmp/test.bin.dec
```

## 效率评测演示

`video-benchmark` 会自动完成一次视频加密、一次视频解密，并统计吞吐率、总耗时、存储额外开销和解密结果一致性。

```bash
sudo ./host/media_crypto video-benchmark /home/dejavu/桌面/test.mp4 /tmp/bench.mp4.enc /tmp/bench.dec.mp4
```

输出中会包含类似内容：

```text
Media Crypto Benchmark
  Input       : /home/dejavu/桌面/test.mp4
  Encrypted   : /tmp/bench.mp4.enc
  Decrypted   : /tmp/bench.dec.mp4
  Type        : video
  Algorithm   : SM4-CTR + HMAC-SM3
  Chunk size  : 65536 bytes

Benchmark Summary
  Plain size        : 12645566 bytes (12.06 MiB)
  Cipher size       : 12645568 bytes (12.06 MiB)
  Encrypted file    : 12645692 bytes (12.06 MiB)
  Decrypted file    : 12645566 bytes (12.06 MiB)
  Encrypt time      : 6.137 s
  Encrypt speed     : 1.96 MiB/s
  Decrypt time      : 4.140 s
  Decrypt speed     : 2.91 MiB/s
  Total crypto time : 10.277 s
  Storage overhead  : 126 bytes
  Overhead ratio    : 0.000997 %
  Header overhead   : 92 bytes
  HMAC overhead     : 32 bytes
  Padding overhead  : 2 bytes
  Compare result    : match
```

这些指标可以用于论文中的效率分析：

- `Encrypt speed`：加密吞吐率。
- `Decrypt speed`：解密吞吐率。
- `Total crypto time`：完整加解密总耗时。
- `Storage overhead`：加密存储带来的额外字节数。
- `Overhead ratio`：额外存储占原视频大小的比例。
- `Compare result: match`：解密输出与原文件逐字节一致。

普通文件也可以使用：

```bash
sudo ./host/media_crypto benchmark /tmp/test.bin /tmp/bench.bin.enc /tmp/bench.bin.dec
```

## 攻击实验演示

攻击实验命令只在普通世界修改加密文件，不接触 TEE 内部密钥，也不改变 TA 的加解密逻辑。它们的作用是生成“被攻击后的样本”，然后再用正常 `video-decrypt` 命令验证系统能否拒绝异常文件。

先生成正常加密文件：

```bash
sudo ./host/media_crypto video-encrypt /home/dejavu/桌面/test.mp4 /tmp/test.mp4.enc
```

### 1. 密文比特翻转攻击

生成密文被篡改的文件：

```bash
sudo ./host/media_crypto attack-bitflip /tmp/test.mp4.enc /tmp/test.bitflip.enc
```

再尝试解密：

```bash
sudo ./host/media_crypto video-decrypt /tmp/test.bitflip.enc /tmp/test.bitflip.dec.mp4
```

预期会失败，并输出类似：

```text
hmac check failed: encrypted file may be corrupted
```

这说明攻击者即使只修改密文中的 1 个字节，也会被 HMAC-SM3 检测出来。

### 2. Header 篡改攻击

生成 header 被篡改的文件：

```bash
sudo ./host/media_crypto attack-header /tmp/test.mp4.enc /tmp/test.header.enc
```

尝试解密：

```bash
sudo ./host/media_crypto video-decrypt /tmp/test.header.enc /tmp/test.header.dec.mp4
```

预期结果：

```text
hmac check failed: encrypted file may be corrupted
```

说明 header 也参与了 HMAC-SM3 计算，攻击者不能随意修改文件元数据。

### 3. HMAC 标签篡改攻击

生成 HMAC tag 被篡改的文件：

```bash
sudo ./host/media_crypto attack-tag /tmp/test.mp4.enc /tmp/test.tag.enc
```

尝试解密：

```bash
sudo ./host/media_crypto video-decrypt /tmp/test.tag.enc /tmp/test.tag.dec.mp4
```

预期结果：

```text
hmac check failed: encrypted file may be corrupted
```

说明攻击者不能伪造或替换文件末尾的完整性标签。

### 4. 截断攻击

生成尾部被截断的文件：

```bash
sudo ./host/media_crypto attack-truncate /tmp/test.mp4.enc /tmp/test.truncated.enc
```

查看信息或尝试解密：

```bash
sudo ./host/media_crypto info /tmp/test.truncated.enc
sudo ./host/media_crypto video-decrypt /tmp/test.truncated.enc /tmp/test.truncated.dec.mp4
```

预期结果：

```text
encrypted file size does not match header
```

说明攻击者不能删除部分密文或 HMAC tag 后伪造成合法加密视频。

### 5. 一键生成攻击样本

可以用 `attack-all` 一次性生成四类攻击样本：

```bash
sudo ./host/media_crypto attack-all /tmp/test.mp4.enc /tmp/test.attack
```

它会生成：

```text
/tmp/test.attack.bitflip.enc
/tmp/test.attack.header.enc
/tmp/test.attack.tag.enc
/tmp/test.attack.truncated.enc
```

然后可以逐个验证：

```bash
sudo ./host/media_crypto video-decrypt /tmp/test.attack.bitflip.enc /tmp/bitflip.dec.mp4
sudo ./host/media_crypto video-decrypt /tmp/test.attack.header.enc /tmp/header.dec.mp4
sudo ./host/media_crypto video-decrypt /tmp/test.attack.tag.enc /tmp/tag.dec.mp4
sudo ./host/media_crypto video-decrypt /tmp/test.attack.truncated.enc /tmp/truncated.dec.mp4
```

预期前三个出现 HMAC 校验失败，截断样本出现文件大小校验失败。

### 6. 直接播放密文攻击

尝试直接播放加密文件：

```bash
xdg-open /tmp/test.mp4.enc
```

预期播放器无法正常播放。该实验用于证明普通世界看到的是密文文件，而不是可直接观看的视频内容。

攻击实验可证明：

- 机密性：加密文件不能直接播放。
- 完整性：密文、header、HMAC tag 被修改后无法通过校验。
- 抗截断：文件长度被破坏后无法通过结构校验。
- 隔离性：攻击命令只在普通世界修改文件，无法获得 TEE 内部密钥。

## 板端实测结果

本节记录一次在 Phytium Pi 板端的完整实测结果，可作为论文或答辩中的实验数据样例。

### 1. 功能正确性验证

测试视频：

```text
/home/dejavu/桌面/test.mp4
```

测试命令：

```bash
sudo ./host/media_crypto video-encrypt /home/dejavu/桌面/test.mp4 /tmp/test.mp4.enc
sudo ./host/media_crypto info /tmp/test.mp4.enc
sudo ./host/media_crypto video-decrypt /tmp/test.mp4.enc /tmp/test.dec.mp4
cmp /home/dejavu/桌面/test.mp4 /tmp/test.dec.mp4
xdg-open /tmp/test.dec.mp4
```

实测结果：

| 验证项 | 结果 |
|---|---|
| 视频加密 | `video-encrypt completed successfully.` |
| 加密文件信息 | `Size check : ok` |
| 视频解密 | `video-decrypt completed successfully.` |
| 文件一致性 | `cmp` 无输出，表示逐字节一致 |
| 视频播放 | `/tmp/test.dec.mp4` 可被 VLC 正常播放 |

该结果说明：加密文件可以被 TEE 正确解密还原，解密后视频与原始视频完全一致。

### 2. 加密文件结构结果

`info` 命令输出的关键字段如下：

| 字段 | 实测值 |
|---|---:|
| Type | `video` |
| Version | `2` |
| Algorithm | `SM4-CTR` |
| Integrity | `HMAC-SM3 enabled` |
| TEE key | `TA private demo key` |
| Plain size | `12645566 bytes (12.06 MiB)` |
| Cipher size | `12645568 bytes (12.06 MiB)` |
| Chunk size | `65536 bytes` |
| Header size | `92 bytes` |
| HMAC size | `32 bytes` |
| File size | `12645692 bytes` |
| Size check | `ok` |

由此可得：

```text
File size = Header size + Cipher size + HMAC size
          = 92 + 12645568 + 32
          = 12645692 bytes
```

其中密文比原文多 `2 bytes`，这是最后一块补齐到 16 字节边界导致的正常现象。

### 3. 效率评测结果

测试命令：

```bash
sudo ./host/media_crypto video-benchmark /home/dejavu/桌面/test.mp4 /tmp/bench.mp4.enc /tmp/bench.dec.mp4
```

实测结果：

| 指标 | 实测值 |
|---|---:|
| Plain size | `12645566 bytes (12.06 MiB)` |
| Cipher size | `12645568 bytes (12.06 MiB)` |
| Encrypted file | `12645692 bytes (12.06 MiB)` |
| Decrypted file | `12645566 bytes (12.06 MiB)` |
| Encrypt time | `6.485 s` |
| Encrypt speed | `1.86 MiB/s` |
| Decrypt time | `6.634 s` |
| Decrypt speed | `1.82 MiB/s` |
| Total crypto time | `13.119 s` |
| Storage overhead | `126 bytes` |
| Overhead ratio | `0.000996 %` |
| Header overhead | `92 bytes` |
| HMAC overhead | `32 bytes` |
| Padding overhead | `2 bytes` |
| Compare result | `match` |

效率结论：

- 当前板端实测加密吞吐率约为 `1.86 MiB/s`。
- 当前板端实测解密吞吐率约为 `1.82 MiB/s`。
- 对 `12.06 MiB` 视频，加密文件额外存储开销为 `126 bytes`。
- 额外存储占比约为 `0.000996 %`，几乎可以忽略。
- `Compare result: match` 表示解密文件与原视频完全一致。

该结果说明：方案在提供 TEE 隔离、SM4-CTR 加密和 HMAC-SM3 完整性校验的同时，采用分块流式处理，额外存储开销很小。

### 4. 攻击实验结果

测试命令：

```bash
sudo ./host/media_crypto attack-all /tmp/test.mp4.enc /tmp/test.attack

sudo ./host/media_crypto video-decrypt /tmp/test.attack.bitflip.enc /tmp/bitflip.dec.mp4
sudo ./host/media_crypto video-decrypt /tmp/test.attack.header.enc /tmp/header.dec.mp4
sudo ./host/media_crypto video-decrypt /tmp/test.attack.tag.enc /tmp/tag.dec.mp4
sudo ./host/media_crypto info /tmp/test.attack.truncated.enc
```

实测结果：

| 攻击类型 | 攻击位置 | 程序输出 | 验证结论 |
|---|---:|---|---|
| bitflip 密文篡改 | ciphertext offset `6322876` | `hmac check failed: encrypted file may be corrupted` | 检测成功 |
| header 篡改 | header offset `76` | `hmac check failed: encrypted file may be corrupted` | 检测成功 |
| HMAC tag 篡改 | tag offset `12645691` | `hmac check failed: encrypted file may be corrupted` | 检测成功 |
| 文件截断 | tail `32 bytes` removed | `Size check : mismatch` | 检测成功 |

攻击实验结论：

- 修改密文任意位置会导致 HMAC-SM3 校验失败。
- 修改受保护 header 会导致 HMAC-SM3 校验失败。
- 修改 HMAC tag 会导致完整性校验失败。
- 删除文件尾部会导致文件结构校验失败。
- 攻击命令只在普通世界生成异常样本，无法获得或修改 TEE 内部密钥。

因此，该方案不仅能完成视频加密存储，还能抵抗普通世界中的密文篡改、元数据篡改、完整性标签篡改和截断攻击。

### 5. 实验总结

综合上述实测结果，可以得出：

```text
1. 功能有效性：视频可成功加密、解密，解密结果与原视频逐字节一致。
2. 机密性：加密文件不是标准 MP4，普通世界不能直接播放获取视频内容。
3. 完整性：密文、header、HMAC tag 被篡改后均无法通过校验。
4. 抗截断性：文件长度异常可被结构校验发现。
5. 效率表现：12.06 MiB 视频加密速率约 1.86 MiB/s，解密速率约 1.82 MiB/s。
6. 存储开销：额外开销仅 126 bytes，占比约 0.000996 %。
7. 大文件适配性：系统按 64 KiB 分块处理，不需要把整个视频一次性加载进 TEE。
```

## 常见问题

### 1. `bash: encrypt: 未找到命令`

错误用法：

```bash
encrypt /tmp/test.bin /tmp/test.bin.enc
```

正确用法：

```bash
./host/media_crypto encrypt /tmp/test.bin /tmp/test.bin.enc
```

`encrypt` 是 `media_crypto` 的参数，不是独立命令。

### 2. `TEEC_InitializeContext failed: 0xffff0008`

通常是普通用户没有权限访问 `/dev/tee0`。

可以先用 `sudo`：

```bash
sudo ./host/media_crypto video-encrypt input.mp4 output.enc
```

后续如果想不用 `sudo`，需要配置 `/dev/tee*` 权限或 udev 规则。

### 3. `TEEC_OpenSession failed: 0xffff3024`

`0xffff3024` 表示 `TEE_ERROR_TARGET_DEAD`，即 TA 在打开 session 或执行命令时崩溃。

排查方向：

- 是否把最新 `.ta` 拷贝到了 `/data/optee_armtz/`。
- host 程序和 TA 是否来自同一次构建。
- 是否还有旧的半成品 `.enc` 文件。
- 重新执行：

```bash
sudo cp 8aaaf200-2450-11e4-abe20002a5d5c51b.ta /data/optee_armtz/
chmod +x ./host/media_crypto
sudo rm -f /tmp/test.mp4.enc /tmp/test.dec.mp4
```

### 4. `Size check : mismatch`

说明加密文件大小和 header 中记录的结构不一致。

常见原因：

- 上一次加密中途失败，留下了半成品。
- 手动修改过 `.enc` 文件。
- 使用旧版程序读取新版加密文件。

解决：

```bash
sudo rm -f /tmp/test.mp4.enc /tmp/test.dec.mp4
sudo ./host/media_crypto video-encrypt /home/dejavu/桌面/test.mp4 /tmp/test.mp4.enc
```

然后重新运行：

```bash
sudo ./host/media_crypto info /tmp/test.mp4.enc
```

应看到：

```text
Size check    : ok
```

### 5. 加密后 `Cipher size` 比 `Plain size` 大

这是正常现象。

当前实现会将最后一块补零到 16 字节边界再送入 TA 加密：

```text
0 <= Cipher size - Plain size < 16
```

解密时会根据 `plain_size` 截断补零，最终输出仍然和原始文件完全一致。

### 6. 加密文件无法播放

这是预期结果。加密文件已经不是 MP4 格式，播放器无法识别。

需要先解密：

```bash
sudo ./host/media_crypto video-decrypt /tmp/test.mp4.enc /tmp/test.dec.mp4
xdg-open /tmp/test.dec.mp4
```

## 当前安全说明

当前实现重点是验证选题要求中的：

```text
分块读取、分块加密、分块写回
```

并展示：

- 视频密文不可直接播放。
- 解密后视频可播放。
- 原视频和解密视频 `cmp` 完全一致。
- HMAC 可检测密文篡改。
- 攻击样本无法通过解密校验。

为了保证目标板运行稳定，当前 key 使用 TA 内部 demo key。进一步增强可做：

- 使用 TEE Persistent Object 保存加密密钥和 HMAC key。
- 使用硬件唯一密钥派生业务密钥。
- 增加密钥轮换和 key version。
- 增加用户 PIN 或设备绑定策略。
- 支持 image/feature 类型命令，覆盖人脸图片和特征数据。

## 推荐演示流程

完整演示可以按下面顺序：

```bash
cd /home/dejavu/桌面/media_crypto

sudo rm -f /tmp/test.mp4.enc /tmp/test.dec.mp4

sudo ./host/media_crypto video-encrypt /home/dejavu/桌面/test.mp4 /tmp/test.mp4.enc
sudo ./host/media_crypto info /tmp/test.mp4.enc

xdg-open /tmp/test.mp4.enc

sudo ./host/media_crypto video-decrypt /tmp/test.mp4.enc /tmp/test.dec.mp4
cmp /home/dejavu/桌面/test.mp4 /tmp/test.dec.mp4
xdg-open /tmp/test.dec.mp4

sudo ./host/media_crypto video-benchmark /home/dejavu/桌面/test.mp4 /tmp/bench.mp4.enc /tmp/bench.dec.mp4

sudo ./host/media_crypto attack-bitflip /tmp/test.mp4.enc /tmp/test.bitflip.enc
sudo ./host/media_crypto video-decrypt /tmp/test.bitflip.enc /tmp/test.bitflip.dec.mp4

sudo ./host/media_crypto attack-all /tmp/test.mp4.enc /tmp/test.attack
sudo ./host/media_crypto video-decrypt /tmp/test.attack.tag.enc /tmp/tag.dec.mp4
sudo ./host/media_crypto info /tmp/test.attack.truncated.enc
```

预期结论：

```text
原视频可以播放
加密文件不能播放
info 显示 Size check: ok
解密视频可以播放
cmp 无输出，表示完全一致
benchmark 输出加密速率、解密速率、存储开销和 match
bitflip 攻击样本解密失败，提示 hmac check failed
truncated 攻击样本结构校验失败，提示 encrypted file size does not match header
```
