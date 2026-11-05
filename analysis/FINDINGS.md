# Goodnotes 7.1.34 逆向记录（付费/权益链路）

对象：`com.goodnotesapp.x` 7.1.34（用户提供的解密 IPA）

## 1. 二进制事实

| 项 | 值 |
|---|---|
| 主二进制 | `Payload/Goodnotes.app/Goodnotes`，261,754,016 B |
| 架构 | 单架构 arm64（`cputype 0x0100000c`） |
| 加密 | `LC_ENCRYPTION_INFO cryptoff=0x8000 cryptsize=218005504 cryptid=0` → **已解密** |
| 段 | `__TEXT` 0x100000000 (218,054,656) / `__DATA_CONST` / `__DATA` / `__LINKEDIT` |
| `__text` | vm 0x100008000，179,737,228 B（约 4493 万条指令） |
| 头部 padding | `__text` fileoff `0x8000`，load commands 结束在 `0x44a0` → **14,848 B 余量**（够放 LC_LOAD_DYLIB，不用重排文件） |
| 符号 | `LC_SYMTAB` 17,214 条，全是 **undefined（import）**；导出表 4,634 条，只有 C++ 符号（giac/fst 等），**没有任何 App 自己的 Swift 符号** |
| Swift 元数据 | `__swift5_types` 140,636 B → 解析出 **35,159 个类型描述符**（其中 8,378 个 class） |
| ObjC 运行时 | `__objc_classlist` 8,074 个类，共 20,444 个方法（chained fixups 解码后） |

结论：**没有符号可 `dlsym`**，所有 App 内部 Swift 方法只能靠偏移 / vtable 槽位。

## 2. 付费链路结构（从类型表 + 字符串还原）

```
用户动作
  └─ GNPaywall.PaywallViewModel / PaywallStore（远端 paywall 配置, paywall_pro_only 等 ID）
       └─ GNPaywall.PurchaseManager ── StoreKit2 / RevenueCat
            └─ GNISI.LivePurchaseService        ← 权益真值来源（"PurchaseService"）
                 ├─ GNISI.LiveTransactionStore  ← 交易落库
                 ├─ GNISI.SubscriptionStatusMonitor
                 └─ ISI 服务端 JWT：{ currentPlans: { base: { planKey: "pro"|"premium" } },
                                      entitlements: { pro_access / crossplatform_access ... },
                                      quotas: { ai: { quota } } }
       └─ GNLicenseKey.LicenseKeyManager / B2BLicenseService（学校/企业 license key 路径）
       └─ RevenueCat：EntitlementInfo / EntitlementInfos / CustomerInfo（另一路权益来源）
```

关键类型（`ObjC 名 → Swift 类型`）：

- `_TtC5GNISI19LivePurchaseService` = `GNISI.LivePurchaseService`
- `_TtC5GNISI25SubscriptionStatusMonitor`
- `_TtC5GNISI20LiveTransactionStore`
- `_TtC5GNISI25SubscriptionTypeFormatter`（字符串 `LIFETIME(entitlement=` / `PRO(entitlement=` / `ESSENTIAL(entitlement=`）
- `_TtC9GNPaywall15PurchaseManager`、`_TtC9GNPaywall16PaywallViewModel`
- `_TtC12GNLicenseKey17LicenseKeyManager`
- `_TtC6GN6App18LivePaywallService`

**关键坑**：上面这些类在 ObjC 运行时里存在，但 `class_copyMethodList` 返回 **0 个方法** —— 也就是没有 @objc 成员，**不能用 method swizzling**。数据见 `analysis/data/objc_classes.txt`（这些行后面是空的）。

## 3. 有价值的常量

产品 / 方案：

- `com.goodnotes.gn6_one_time_unlock` / `com.goodnotes.gn6_one_time_unlock_3999`（买断）
- `com.goodnotes.premium_1y_799`、`premium_subscription`、`pro_promotional`、`pro_7dt_1y_3599`、`essential_subscription`、`special_edition_subscription`
- planKey：`pro` / `premium` / `essential`
- 权益 ID：`pro_access` / `apple_access` / `crossplatform_access` / `gnc_access` / `pro_access`

QA / 调试开关（**release 里字符串在，但 QAPurchaseService 是否装配需在设备上确认**）：

- `mock_entitlements_enabled_key` / `mock_entitlements_key` / `mock_entitlements_premium_state_key`
- `com.goodnotes.one_time_unlock_confirmed_by_purchase_service`
- UI 文案：`Allow override entitlements`、`Mock entitlements are not enabled!`、`PurchaseService is not QAPurchaseService - mock entitlements not set`

## 4. 已定位的字符串锚点（unslid 偏移，base = 0x100000000）

用 `analysis/tools/anchor.py` 扫 `__text` 里的 ADRP+ADD 引用 + 回溯函数头得到：

| cstring | 引用函数（未滑动偏移） |
|---|---|
| `paywall_pro_only` | `0xbfd98`, `0xe48f38`, `0xe492dc`, `0xe9eb28`, `0x34ee4f0`, `0x34f8964`, `0x3508718`, …（共 20+ 处） |
| `special_edition_subscription` | `0x231f1fc` |
| `com.goodnotes.gn6_one_time_unlock_3999` | `0x232b150` |
| `LIFETIME(entitlement=` | `0x2331b60` |
| `missing_active_pro_entitlement` | `0x7d429b8` |
| `mock_entitlements_enabled_key` | `0x7faabd8`, `0x7faac84`, `0x7faadb8` |

**`0x231f000 – 0x2332000` 这一段高度集中在权益状态实现上**（special_edition / one_time_unlock / LIFETIME 描述串都在里面）。反汇编 `0x2331b60` 已确认是合法的函数入口（`sub sp, sp, #0x80` 起头、标准 prologue），下一步就从这一段往下找「返回 plan / entitlement 枚举」的 getter，然后钉 vtable 槽或直接改机器码。

## 5. 工具

```bash
# 列出所有 Swift 类型 / 某个类的方法描述符
python3 analysis/tools/gnsym.py list Purchase
python3 analysis/tools/gnsym.py methods LivePurchaseService

# 解 chained fixups、导出全部 ObjC 类 + 方法（已生成 analysis/data/objc_classes.txt）
python3 analysis/tools/gnobjc.py

# 字符串锚点 → 引用它的函数（需要 numpy）
python3 analysis/tools/anchor.py "pro_access" "missing_active_pro_entitlement"

# 导出表
python3 analysis/tools/trie.py
```

反汇编用 capstone：`pip install capstone`，把 `m.read(addr, n)` 的字节丢进去即可（`gnobjc.MachO` 已经封装好 vmaddr→file offset）。

## 6. 下一步（钉死解锁点）

1. 装一次带 recon 的包，取回 `Documents/gnunlock-recon.txt`（里面有运行时每个 Swift 描述符地址 + 实例化后的 class metadata），确认 `LivePurchaseService` 的 metadata 地址与 vtable 起址。
2. 在 `0x231f000`–`0x2332000` 段内找返回 Bool 的小函数（`cmp` + `cset` 形式），配合 `has(entitlement:)` 调用点确认语义。
3. 把结论写进 `config/GNUnlock.plist` 的 `BytePatches`（`mov w0,#1; ret` = `20008052c0035fd6`）或加锚点规则，重跑流水线出成品。
