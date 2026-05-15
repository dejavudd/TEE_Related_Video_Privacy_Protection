# OP-TEE 开发基础知识入门

## 1. 什么是 OP-TEE

OP-TEE（Open Portable Trusted Execution Environment）是面向 Arm TrustZone 场景的开源 TEE（Trusted Execution Environment）实现。开发者通常在 **REE（Rich Execution Environment，普通世界）** 中运行 Linux / Android 应用，在 **TEE（安全世界）** 中运行可信应用。OP-TEE 主要实现了两套接口：

- **TEE Client API**：给普通世界中的客户端程序（CA, Client Application）使用。
- **TEE Internal Core API**：给安全世界中的可信应用（TA, Trusted Application）使用。

从开发视角看，最常见的组件关系如下：

- **CA**：运行在普通世界，通常是一个 Linux 用户态程序，链接 `libteec`。
- **TA**：运行在安全世界，使用 `libutee` 和 TA Dev Kit 构建。
- **tee-supplicant**：普通世界中的辅助进程，帮助 OP-TEE 完成动态 TA 加载、REE 文件系统访问、RPC 服务等。
- **optee_client**：提供 CA 所需的头文件和 `libteec`。
- **optee_os**：提供 OP-TEE OS 本体，以及构建 TA 所需的 TA Dev Kit。

---

## 2. OP-TEE 开发的基本模型

最典型的 OP-TEE 开发模式是：

1. 普通世界中的 **CA** 初始化上下文。
2. CA 按照 **TA UUID** 打开会话。
3. CA 使用 `TEEC_InvokeCommand()` 发送命令和参数。
4. 安全世界中的 **TA** 在 `TA_InvokeCommandEntryPoint()` 中解析命令并执行业务。
5. TA 将结果通过参数返回给 CA。
6. CA 关闭会话并释放上下文。

可以把它理解成“**普通世界调用安全世界中的远程过程**”。

一个极简的调用顺序是：

```text
CA:
  TEEC_InitializeContext()
  TEEC_OpenSession()
  TEEC_InvokeCommand()
  TEEC_CloseSession()
  TEEC_FinalizeContext()
```

---

## 3. CA 与 TA 交互基础

### 3.1 角色分工

**CA（Client Application）负责：**

- 准备输入参数
- 建立到 TA 的会话
- 发起命令调用
- 接收返回值 / 返回缓冲区

**TA（Trusted Application）负责：**

- 校验参数类型
- 执行敏感逻辑
- 访问安全接口（如加密、随机数、安全存储）
- 返回结果

### 3.2 CA/TA 常见调用关系

一个 TA 一般由以下入口点组成：

- `TA_CreateEntryPoint()`：TA 实例创建时调用
- `TA_DestroyEntryPoint()`：TA 实例销毁时调用
- `TA_OpenSessionEntryPoint()`：打开会话时调用
- `TA_CloseSessionEntryPoint()`：关闭会话时调用
- `TA_InvokeCommandEntryPoint()`：接收命令调用

### 3.3 参数类型

OP-TEE 的参数一般分为两大类：

- **值类型**：`VALUE_INPUT`、`VALUE_OUTPUT`、`VALUE_INOUT`
- **内存引用类型**：`MEMREF_INPUT`、`MEMREF_OUTPUT`、`MEMREF_INOUT`

通常：

- 传整数、标志位、长度时，用 `VALUE_*`
- 传字节数组、字符串、二进制数据时，用 `MEMREF_*`

### 3.4 一个最小 CA 示例

下面示例演示 CA 向 TA 发送一个整数，TA 将其加一后返回。

```c
#include <stdio.h>
#include <string.h>
#include <tee_client_api.h>
#include "demo_ta.h"

static const TEEC_UUID ta_uuid = DEMO_TA_UUID;

int main(void)
{
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    uint32_t origin;

    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InitializeContext failed: 0x%x\n", res);
        return -1;
    }

    res = TEEC_OpenSession(&ctx, &sess, &ta_uuid,
                           TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_OpenSession failed: 0x%x origin=0x%x\n", res, origin);
        TEEC_FinalizeContext(&ctx);
        return -1;
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT,
                                     TEEC_NONE,
                                     TEEC_NONE,
                                     TEEC_NONE);
    op.params[0].value.a = 41;

    res = TEEC_InvokeCommand(&sess, DEMO_CMD_INC_VALUE, &op, &origin);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InvokeCommand failed: 0x%x origin=0x%x\n", res, origin);
    } else {
        printf("result = %u\n", op.params[0].value.a);
    }

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
    return 0;
}
```

### 3.5 一个最小 TA 示例

```c
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include "demo_ta.h"

TEE_Result TA_CreateEntryPoint(void)
{
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
                                    TEE_Param params[4],
                                    void **sess_ctx)
{
    uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE);
    (void)params;
    (void)sess_ctx;

    if (param_types != exp)
        return TEE_ERROR_BAD_PARAMETERS;

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
    (void)sess_ctx;
}

static TEE_Result inc_value(uint32_t param_types, TEE_Param params[4])
{
    uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE);

    if (param_types != exp)
        return TEE_ERROR_BAD_PARAMETERS;

    params[0].value.a += 1;
    return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx,
                                      uint32_t cmd_id,
                                      uint32_t param_types,
                                      TEE_Param params[4])
{
    (void)sess_ctx;

    switch (cmd_id) {
    case DEMO_CMD_INC_VALUE:
        return inc_value(param_types, params);
    default:
        return TEE_ERROR_NOT_SUPPORTED;
    }
}
```

### 3.6 TA 头文件示例

```c
#ifndef DEMO_TA_H
#define DEMO_TA_H

#define DEMO_TA_UUID \
    { 0x12345678, 0x1234, 0x5678, \
      { 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 } }

#define DEMO_CMD_INC_VALUE  0

#endif
```

### 3.7 交互时必须注意的点

#### 1）TA 必须严格校验 `param_types`

这是 OP-TEE 开发里最重要的安全习惯之一。TA 在使用 `params[]` 前，必须先校验调用方传入的参数类型是否符合预期。

错误示例：

- 直接访问 `params[0].memref.buffer`
- 没有核对 `param_types`
- 假设 CA 一定传了合法长度

正确做法：

- 先用 `TEE_PARAM_TYPES(...)` 构造期望值
- 再比较 `param_types != exp`
- 不符合就立即返回 `TEE_ERROR_BAD_PARAMETERS`

#### 2）CA/TA 的命令号与头文件必须统一

通常会把 `UUID`、`CMD_ID`、结构体定义都放在一个公共头文件里，这样 CA 和 TA 共享同一套协议定义。

#### 3）返回码需要双重检查

CA 侧除了检查 `TEEC_Result` 外，还应关注 `origin`，便于判断错误来自：

- `TEEC_ORIGIN_API`
- `TEEC_ORIGIN_COMMS`
- `TEEC_ORIGIN_TEE`
- `TEEC_ORIGIN_TRUSTED_APP`

---

## 4. 共享内存（Shared Memory）

### 4.1 为什么需要共享内存

CA 和 TA 分别运行在普通世界和安全世界，二者地址空间不同，不能直接共享普通指针。因此在传输较大数据块时，需要通过 **共享内存** 机制来完成。

典型场景：

- 传输明文 / 密文缓冲区
- 传输文件内容
- 传输证书、公钥、签名数据
- 多次重复调用同一块缓冲区

### 4.2 两种常见方式

#### 方式 1：临时内存引用 `TEEC_TempMemoryReference`

特点：

- 使用方便
- 适合一次性调用
- 内部可能发生额外拷贝
- 性能通常不如显式共享内存

示例：

```c
char in_buf[128] = "hello optee";
char out_buf[128] = {0};
TEEC_Operation op = {0};

op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                 TEEC_MEMREF_TEMP_OUTPUT,
                                 TEEC_NONE,
                                 TEEC_NONE);
op.params[0].tmpref.buffer = in_buf;
op.params[0].tmpref.size   = sizeof(in_buf);
op.params[1].tmpref.buffer = out_buf;
op.params[1].tmpref.size   = sizeof(out_buf);
```

#### 方式 2：显式共享内存 `TEEC_SharedMemory`

特点：

- 适合大块数据
- 适合多次调用复用
- 更容易做到零拷贝
- 性能更好

有两种初始化方式：

- `TEEC_AllocateSharedMemory()`：由 TEE Client 库分配共享内存，通常更容易获得零拷贝效果
- `TEEC_RegisterSharedMemory()`：把已有缓冲区注册成共享内存

### 4.3 `TEEC_AllocateSharedMemory()` 示例

```c
TEEC_SharedMemory shm;
TEEC_Operation op;

memset(&shm, 0, sizeof(shm));
shm.size = 4096;
shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

res = TEEC_AllocateSharedMemory(&ctx, &shm);
if (res != TEEC_SUCCESS)
    return res;

memcpy(shm.buffer, "hello secure world", 19);

memset(&op, 0, sizeof(op));
op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE,
                                 TEEC_NONE,
                                 TEEC_NONE,
                                 TEEC_NONE);
op.params[0].memref.parent = &shm;
op.params[0].memref.size = shm.size;

res = TEEC_InvokeCommand(&sess, DEMO_CMD_PROCESS_BUFFER, &op, &origin);

TEEC_ReleaseSharedMemory(&shm);
```

### 4.4 `TEEC_RegisterSharedMemory()` 示例

```c
uint8_t buf[4096];
TEEC_SharedMemory shm;

memset(&shm, 0, sizeof(shm));
shm.buffer = buf;
shm.size = sizeof(buf);
shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;

res = TEEC_RegisterSharedMemory(&ctx, &shm);
```

### 4.5 TA 侧如何接收共享内存

无论 CA 用的是临时内存还是共享内存，TA 侧看到的通常都是 `TEE_Param params[4]` 中的 `memref`：

```c
static TEE_Result handle_buf(uint32_t param_types, TEE_Param params[4])
{
    uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE,
                                   TEE_PARAM_TYPE_NONE);

    if (param_types != exp)
        return TEE_ERROR_BAD_PARAMETERS;

    uint8_t *buf = params[0].memref.buffer;
    uint32_t sz = params[0].memref.size;

    if (!buf)
        return TEE_ERROR_BAD_PARAMETERS;

    /* 示例：把全部字节加 1 */
    for (uint32_t i = 0; i < sz; i++)
        buf[i] += 1;

    return TEE_SUCCESS;
}
```

### 4.6 共享内存的几个关键概念

#### 1）零拷贝（zero-copy）

`TEEC_AllocateSharedMemory()` 一般是更推荐的方式，因为更容易建立高效共享内存，减少数据复制。

#### 2）影子缓冲区（shadow buffer）

使用 `TEEC_RegisterSharedMemory()` 时，如果底层不能直接注册该块内存，框架可能退化成“影子缓冲区”——也就是内部再拷贝一份，这会降低性能。

常见触发原因：

- 原缓冲区不是普通可读写内存
- 内存未按预期对齐
- 某些 FF-A 场景下内存区间已经被注册过

#### 3）静态共享内存与动态共享内存

- **静态/保留共享内存**：历史上常见，预留一块连续物理内存作为共享区
- **动态共享内存**：现代平台更常见，允许把普通世界中的系统内存注册为共享内存

开发者通常更关心的结论是：

- 平台支持动态共享内存时，开发会更灵活
- 大数据交换优先考虑显式共享内存
- 高性能场景优先考虑复用同一块共享内存

### 4.7 共享内存的实践建议

- 小数据、一次性调用：优先 `TEEC_TempMemoryReference`
- 大数据、多次调用：优先 `TEEC_AllocateSharedMemory`
- TA 中不要盲信 `memref.size`
- 修改输出缓冲区时，注意返回后的实际长度
- 避免在 TA 中对未校验长度的缓冲区做复杂解析

---

## 5. OP-TEE 中的基础加密接口

在 OP-TEE 中，**加密相关逻辑通常应尽量放在 TA 内部执行**。这样密钥和敏感中间态可以尽量留在安全世界。

OP-TEE 的加密接口属于 **TEE Internal Core API** 的一部分，常见能力包括：

- 随机数生成
- 哈希 / 摘要
- 对称加密（AES 等）
- MAC / HMAC
- 非对称加密与签名（RSA / ECC）
- 密钥派生

从编程模型看，最常见的对象有两类：

- **Operation（操作句柄）**：描述一个加密操作，例如 AES-CBC、SHA-256、HMAC-SHA256
- **Object（对象句柄）**：描述密钥对象，例如 AES key、RSA keypair、公钥对象

### 5.1 随机数生成

最简单的接口之一：

```c
uint8_t rnd[32];
TEE_GenerateRandom(rnd, sizeof(rnd));
```

适合：

- 生成 nonce
- 生成 IV
- 生成会话随机数
- 生成盐值

### 5.2 哈希（SHA-256）示例

```c
TEE_Result calc_sha256(const void *in, uint32_t in_sz,
                       uint8_t *out, uint32_t out_sz)
{
    TEE_Result res;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    uint32_t hash_len = out_sz;

    if (out_sz < 32)
        return TEE_ERROR_SHORT_BUFFER;

    res = TEE_AllocateOperation(&op, TEE_ALG_SHA256,
                                TEE_MODE_DIGEST, 0);
    if (res != TEE_SUCCESS)
        return res;

    TEE_DigestDoFinal(op, in, in_sz, out, &hash_len);
    TEE_FreeOperation(op);
    return TEE_SUCCESS;
}
```

使用流程：

1. `TEE_AllocateOperation()` 申请摘要操作句柄
2. `TEE_DigestDoFinal()` 计算摘要
3. `TEE_FreeOperation()` 释放资源

### 5.3 AES 对称加密基本流程

OP-TEE 中做 AES，一般要经过以下步骤：

1. 申请一个瞬时密钥对象 `TEE_AllocateTransientObject()`
2. 用 `TEE_InitRefAttribute()` / `TEE_PopulateTransientObject()` 导入密钥
3. 申请加密操作 `TEE_AllocateOperation()`
4. 绑定密钥 `TEE_SetOperationKey()`
5. 初始化算法参数，例如 IV：`TEE_CipherInit()`
6. 执行加解密：`TEE_CipherUpdate()` 或 `TEE_CipherDoFinal()`
7. 释放资源

### 5.4 AES-CBC 示例骨架

下面是一个教学化的最小骨架：

```c
TEE_Result aes_cbc_encrypt(const uint8_t *key, uint32_t key_len,
                           const uint8_t *iv,
                           const uint8_t *in, uint32_t in_len,
                           uint8_t *out, uint32_t *out_len)
{
    TEE_Result res;
    TEE_ObjectHandle key_obj = TEE_HANDLE_NULL;
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    TEE_Attribute attr;

    if (key_len != 16 && key_len != 24 && key_len != 32)
        return TEE_ERROR_BAD_PARAMETERS;

    res = TEE_AllocateTransientObject(TEE_TYPE_AES, key_len * 8, &key_obj);
    if (res != TEE_SUCCESS)
        goto out;

    TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE,
                         (void *)key, key_len);

    res = TEE_PopulateTransientObject(key_obj, &attr, 1);
    if (res != TEE_SUCCESS)
        goto out;

    res = TEE_AllocateOperation(&op, TEE_ALG_AES_CBC_NOPAD,
                                TEE_MODE_ENCRYPT, key_len * 8);
    if (res != TEE_SUCCESS)
        goto out;

    res = TEE_SetOperationKey(op, key_obj);
    if (res != TEE_SUCCESS)
        goto out;

    TEE_CipherInit(op, iv, 16);
    res = TEE_CipherDoFinal(op, in, in_len, out, out_len);

out:
    if (op)
        TEE_FreeOperation(op);
    if (key_obj)
        TEE_FreeTransientObject(key_obj);
    return res;
}
```

注意：

- `TEE_ALG_AES_CBC_NOPAD` 要求输入长度通常是 16 字节对齐
- 如果需要处理任意长度数据，需要自行做 PKCS#7 等填充，或选择支持不同模式的实现方案
- 实战中不要把固定密钥硬编码在源码里

### 5.5 HMAC / MAC 思路

HMAC 的整体模式与 AES 类似，只是算法类型和模式不同：

- 申请密钥对象
- 申请 `TEE_OperationHandle`
- 绑定密钥
- `TEE_MACInit()`
- `TEE_MACUpdate()` / `TEE_MACComputeFinal()`

适合：

- 消息完整性校验
- 请求认证
- 轻量级密钥确认

### 5.6 RSA / ECC 基本思路

非对称算法的流程一般是：

- 创建密钥对象（公钥或密钥对）
- 导入或生成密钥
- 分配对应算法操作句柄
- 执行签名 / 验签 / 加解密 / 密钥协商

常见接口：

- `TEE_AllocateTransientObject()`
- `TEE_GenerateKey()`
- `TEE_AsymmetricSignDigest()`
- `TEE_AsymmetricVerifyDigest()`
- `TEE_AsymmetricEncrypt()`
- `TEE_AsymmetricDecrypt()`

### 5.7 加密接口开发建议

- **尽量让密钥只存在于 TA 内部**
- CA 尽量只传业务数据，不传长期密钥
- 对输入长度、输出长度做严格检查
- 操作完成后及时释放 `OperationHandle` 和 `ObjectHandle`
- 选择算法时优先考虑现代安全参数，例如 SHA-256、AES-128/256、RSA-2048/ECC P-256 及以上

---

## 6. 交叉编译基础知识

OP-TEE 开发通常不是在目标板上原生编译，而是在宿主机上交叉编译，再部署到目标板。

### 6.1 OP-TEE 常见的三类构建对象

#### 1）构建 `optee_os`

用于生成：

- OP-TEE OS 本体
- TA Dev Kit（后续编译 TA 要用）

#### 2）构建 `optee_client`

用于生成：

- `libteec`
- CA 所需头文件与导出目录

#### 3）构建你的 CA / TA

- **CA**：链接 `libteec`
- **TA**：依赖 `TA_DEV_KIT_DIR`

### 6.2 常见交叉编译变量

#### `CROSS_COMPILE`

交叉编译器前缀，例如：

```bash
arm-linux-gnueabihf-
aarch64-linux-gnu-
```

最终会拼接成：

- `arm-linux-gnueabihf-gcc`
- `aarch64-linux-gnu-gcc`

#### `CROSS_COMPILE32` / `CROSS_COMPILE64`

在同时涉及 32 位 TA 和 64 位 core 的场景中，可能需要分别指定 32 位和 64 位工具链。

#### `PLATFORM`

指定目标平台，例如：

- `vexpress-qemu_virt`
- `vexpress-qemu_armv8a`
- 其他厂商 SoC 对应平台名

#### `O`

指定输出目录。

#### `TA_DEV_KIT_DIR`

编译 TA 时非常关键，指向 `optee_os` 构建产物中的 `export-ta_arm32` 或 `export-ta_arm64`。

#### `TEEC_EXPORT`

编译 CA 时常用，指向 `optee_client` 的导出目录。

### 6.3 构建 `optee_os` 示例

#### AArch32 / QEMU 示例

```bash
make \
  CFG_TEE_CORE_LOG_LEVEL=3 \
  CROSS_COMPILE=arm-linux-gnueabihf- \
  CROSS_COMPILE_core=arm-linux-gnueabihf- \
  CROSS_COMPILE_ta_arm32=arm-linux-gnueabihf- \
  CROSS_COMPILE_ta_arm64=aarch64-linux-gnu- \
  DEBUG=1 \
  O=out/arm \
  PLATFORM=vexpress-qemu_virt
```

#### AArch64 / QEMU 示例

```bash
make \
  CFG_ARM64_core=y \
  CFG_TEE_CORE_LOG_LEVEL=3 \
  CROSS_COMPILE=aarch64-linux-gnu- \
  CROSS_COMPILE_core=aarch64-linux-gnu- \
  CROSS_COMPILE_ta_arm32=arm-linux-gnueabihf- \
  CROSS_COMPILE_ta_arm64=aarch64-linux-gnu- \
  DEBUG=1 \
  O=out/arm \
  PLATFORM=vexpress-qemu_armv8a
```

### 6.4 构建 CA 示例

```bash
cd optee_examples/hello_world/host
make \
  CROSS_COMPILE=arm-linux-gnueabihf- \
  TEEC_EXPORT=<optee_client>/out/export/usr \
  --no-builtin-variables
```

要点：

- CA 本质是普通世界程序
- 需要链接 `libteec`
- `TEEC_EXPORT` 需要指向 `optee_client` 的导出目录

### 6.5 构建 TA 示例

```bash
cd optee_examples/hello_world/ta
make \
  CROSS_COMPILE=arm-linux-gnueabihf- \
  PLATFORM=vexpress-qemu_virt \
  TA_DEV_KIT_DIR=<optee_os>/out/arm/export-ta_arm32
```

要点：

- TA 不是普通 ELF 程序，而是带有 OP-TEE 头和签名的 `.ta`
- `TA_DEV_KIT_DIR` 是 TA 能否正确构建的关键
- 构建输出里常见 `.ta`、`.elf`、`.map`、`.dmp` 等文件

### 6.6 一个典型 TA 目录结构

```text
my_ta/
├── Makefile
├── sub.mk
├── user_ta_header_defines.h
├── include/
│   └── my_ta.h
└── my_ta.c
```

其中：

- `Makefile`：包含 TA Dev Kit
- `sub.mk`：列出源文件和编译选项
- `user_ta_header_defines.h`：定义 TA UUID、栈大小、堆大小、标志位
- `include/my_ta.h`：给 CA/TA 共享的协议头文件

### 6.7 TA Makefile 最小示例

```makefile
BINARY=12345678-1234-5678-1234-56789abcdef0
include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk
```

### 6.8 `sub.mk` 最小示例

```makefile
srcs-y += my_ta.c
global-incdirs-y += include/
```

### 6.9 `user_ta_header_defines.h` 最小示例

```c
#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#define TA_UUID \
    { 0x12345678, 0x1234, 0x5678, \
      { 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 } }

#define TA_FLAGS      (TA_FLAG_EXEC_DDR | TA_FLAG_SINGLE_INSTANCE | TA_FLAG_MULTI_SESSION)
#define TA_STACK_SIZE (2 * 1024)
#define TA_DATA_SIZE  (32 * 1024)
#define TA_VERSION    "1.0"
#define TA_DESCRIPTION "Demo TA"

#endif
```

### 6.10 编译后的部署

通常需要把产物放到目标系统约定的位置：

- **CA**：拷到 `/usr/bin/` 或其他可执行目录
- **TA**：拷到 `/lib/optee_armtz/`（很多 Linux 系统中如此）

运行前通常还需要：

- OP-TEE 驱动正常加载
- `tee-supplicant` 已启动
- TA 文件名与 UUID 对应

### 6.11 常见编译问题

#### 1）用了错误的交叉编译器

例如本来要编 ARM 目标，却误用了宿主机 x86 的 `gcc`。

#### 2）`TA_DEV_KIT_DIR` 路径错误

会导致找不到 TA Dev Kit 的头文件、脚本、库。

#### 3）`TEEC_EXPORT` 路径错误

会导致 CA 找不到 `tee_client_api.h` 或 `libteec`。

#### 4）32 位 / 64 位 ABI 不匹配

例如：

- 64 位系统中用错 32 位库
- TA 与 core 目标位数配置不一致
- toolchain 前缀不匹配

#### 5）TA UUID 与部署文件名不一致

`.ta` 文件名通常就是 UUID，如果不一致，TA 可能无法被正常加载。

---

## 7. 从开发视角理解 OP-TEE 的最小工程

一个最小可工作的 OP-TEE 工程通常包括：

```text
demo/
├── host/
│   ├── main.c
│   └── Makefile
└── ta/
    ├── Makefile
    ├── sub.mk
    ├── user_ta_header_defines.h
    ├── include/
    │   └── demo_ta.h
    └── demo_ta.c
```

其中：

- `host/main.c`：CA 侧逻辑
- `ta/demo_ta.c`：TA 侧逻辑
- `include/demo_ta.h`：定义 UUID、命令号、共享结构体

这也是最推荐的学习路径：

1. 先做一个 `VALUE_INOUT` 的整数加一 demo
2. 再做一个 `MEMREF_INOUT` 的缓冲区处理 demo
3. 再加入哈希 / AES 功能
4. 最后再引入安全存储、密钥持久化、签名验签等能力

---

## 8. 开发建议与最佳实践

### 8.1 协议设计建议

- CA/TA 共享一个公共头文件
- 明确每个 `command_id` 的参数布局
- 每个命令都写清楚输入/输出类型和长度约束

### 8.2 安全建议

- TA 永远先校验 `param_types`
- TA 对 `memref.buffer` 和 `memref.size` 做完整检查
- 不把长期密钥暴露给 CA
- 不把测试密钥用于生产环境
- 尽量减少 TA 中不必要的复杂解析逻辑

### 8.3 性能建议

- 大块数据优先共享内存
- 多次调用复用会话和共享内存
- 不要频繁重复打开/关闭 session
- 只把真正敏感的逻辑放进 TA

### 8.4 调试建议

- 先从 `hello_world` 级别示例开始
- 先验证 UUID、命令号、参数类型是否匹配
- 出错时同时看：
  - CA 返回码
  - `origin`
  - normal world 日志
  - secure world 日志

---

## 9. 学习路线建议

建议按下面顺序学习：

1. **理解 CA/TA 交互模型**
2. **掌握 `VALUE_*` 与 `MEMREF_*` 参数传递**
3. **掌握共享内存与数据拷贝行为**
4. **掌握 TA 的基本生命周期与入口点**
5. **掌握哈希、随机数、AES 等基础加密 API**
6. **掌握 TA 的交叉编译与部署**
7. **再进入安全存储、密钥管理、签名体系、生产签名等主题**

---

## 10. 参考资料

以下资料适合作为进一步阅读的起点：

1. [OP-TEE 官方文档：GlobalPlatform API](https://optee.readthedocs.io/en/latest/architecture/globalplatform_api.html)
2. [OP-TEE 官方文档：Trusted Applications](https://optee.readthedocs.io/en/latest/building/trusted_applications.html)
3. [OP-TEE 官方文档：Core / Shared Memory](https://optee.readthedocs.io/en/latest/architecture/core.html)
4. [OP-TEE 官方文档：Cryptographic implementation](https://optee.readthedocs.io/en/latest/architecture/crypto.html)
5. [OP-TEE 官方文档：optee_os](https://optee.readthedocs.io/en/latest/building/gits/optee_os.html)
6. [OP-TEE 官方文档：optee_examples](https://optee.readthedocs.io/en/latest/building/gits/optee_examples/optee_examples.html)
7. [官方示例仓库：linaro-swg/optee_examples](https://github.com/linaro-swg/optee_examples)

---

## 11. 一页总结

可以把 OP-TEE 开发浓缩成下面几句话：

- **CA 负责调用，TA 负责保护敏感逻辑。**
- **小数据传值，大数据用共享内存。**
- **TA 中先校验参数类型，再处理数据。**
- **密钥尽量留在 TA 内，不要在 CA 暴露。**
- **CA 依赖 `optee_client`，TA 依赖 `optee_os` 导出的 TA Dev Kit。**
- **交叉编译的关键变量是 `CROSS_COMPILE`、`TEEC_EXPORT`、`TA_DEV_KIT_DIR`、`PLATFORM`。**

如果你刚开始接触 OP-TEE，最好的起点就是：

> 先跑通一个 hello_world 风格的 CA/TA，再逐步加入共享内存和 AES/SHA 功能。

