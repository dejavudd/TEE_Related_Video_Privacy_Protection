[readme.md](https://github.com/user-attachments/files/27806458/readme.md)
# Media Crypto: TEE 视频分块加密存储示例

`media_crypto` 是一个基于 OP-TEE 的视频/大文件加密存储原型。它面向“TEE 隔离环境视频的加密存储”选题，核心目标是避免把完整视频一次性加载到 TEE 中，而是采用普通世界分块读写、安全世界分块加解密的流式方案。

当前版本已经实现：

- host 端分块读取输入文件，每块默认 `64 KiB`。
- TA 端在 TEE 中使用 `SM4-CTR` 执行分块加解密。
- 加密文件携带自描述 header，记录类型、算法、原始大小、密文大小、IV 等信息。
- 加密文件末尾携带 `HMAC-SM3` 完整性标签。
- 解密前先校验 HMAC，防止密文被篡改。
- 支持视频专用命令 `video-encrypt` / `video-decrypt`。
- 支持 `info` 命令查看加密文件元数据。
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

## 篡改检测演示

先生成正常加密文件：

```bash
sudo ./host/media_crypto video-encrypt /home/dejavu/桌面/test.mp4 /tmp/test.mp4.enc
```

故意修改密文中的一个字节：

```bash
printf '\xff' | sudo dd of=/tmp/test.mp4.enc bs=1 seek=200 conv=notrunc
```

再尝试解密：

```bash
sudo ./host/media_crypto video-decrypt /tmp/test.mp4.enc /tmp/test.dec.mp4
```

预期会失败，并输出类似：

```text
hmac check failed: encrypted file may be corrupted
```

这说明 HMAC-SM3 完整性校验生效。

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
```

预期结论：

```text
原视频可以播放
加密文件不能播放
info 显示 Size check: ok
解密视频可以播放
cmp 无输出，表示完全一致
```

