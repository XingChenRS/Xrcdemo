// © 雾月星辰 & MLXC · github@XingChenRS
// XRCProfile.h — 版本契约（Arcaea iOS 7.0.255）。
// 跨版本迁移只改本文件（+ 注入器 inject.py 侧对应常量）——每个版本按指纹重定位。
//
// ---- 分区目录（按主题检索）----
//   · 指纹区：判定核入口 3 指令 / 各站点原字节 expect（跨版本重定位依据）
//   · 字段布局区：谱面钟 / note 对象 / note group / FMOD 链路 / vtable 槽等（每项带出处注释）
//   · 站点区：BRK 站点 {site, replay} 常量（与 inject.py BRK_HOOKS、XRCHook.m 表三处同步）
// 纪律：每个偏移必须有出处注释（逆向结论/实测记录）；禁止只改代码不加出处。
// 跨版本锚点：判定核/每帧更新/谱面钟/音频链在 6.13.10 与
// 7.0.255 均已定位（判定核入口与 CMP 站点字节级同构）——新版本按
// 同一指纹重定位后，只改本文件的偏移宏。
#pragma once

#include <stdint.h>
#include <stdbool.h>

// ---------------- 谱面钟对象布局 ----------------
// 出处: 逆向笔记 §4
// （与 6.13 真机验证的布局逐字节一致；+45 标志/+40 base/+52 当前/-3000 前导）。
#define XRC_CLK_FLAG45_OFF        45   // =1 时走分段钟分支（读 +32）
#define XRC_CLK_BASE_OFF          40   // seek 平移目标（base_off）
#define XRC_CLK_ALT_START_OFF     32   // flag45=1 分支的起始值
#define XRC_CLK_SEG16_OFF         16   // 分段态另一半（外部参考实现 finish_scrub 写 uptime_ms−ref；读法不查它——照抄留档，见设计纪要 §1.2/§4）
#define XRC_CLK_CUR_OFF           52   // 非分段钟当前值（<=0 时 -3000 前导）
#define XRC_CLK_NEG_LEAD_MS       (-3000)

// gameplay 对象 → note group（6.13 称 logic）→ 谱面钟
#define XRC_GP_NOTEGROUP_OFF       928
#define XRC_CLOCK_IN_NOTEGROUP_OFF 48

// ---------------- note group 内部布局 ----------------
// 出处：外部参考实现的 Rust 符号 `practice::seek_to`（离线样本 dylib @0x20120）逐行：
//     v18 = (__int64 *)result[20];   // 音符数组 begin = *(note_group + 0xA0)
//     v19 = result[21];              // 音符数组 end   = *(note_group + 0xA8)
//     v22 = *v18++;                  // 8 字节/项（指针数组，元素是 note 对象）
//   且同一函数里 `result[6]`（= note_group+0x30）当谱面钟用（读 +32/+40/+45/+52）——
//   与本文件的 +48 是同一物，故 外部参考实现的 result 即我们的 note group（6.13↔7.0 同布局）。
// ⚠ *(scene+0x360) 不是音符管理器：对局中实测恒为 0。槽 155 sub_100CA118C 是
//   **场景初始化**函数（只跑一次），不代表每帧更新。
#define XRC_NG_NOTEVEC_BEGIN_OFF   0xA0   // note group + 160：音符指针数组 begin
#define XRC_NG_NOTEVEC_END_OFF     0xA8   // note group + 168：end

// note 对象字段（外部参考实现 seek_to 的"重新武装"逐字 + 7.0 判定核交叉验证）
//   +0x00 vtable（类型判据：Hold / Arc 各一）
//   +0x0C 判定态字（16 位；外部参考实现回退 seek 时清它来重新武装 —— 这是 replay 要清的核心）
//   +0x18 音符时间 —— 与 XRC_NOTE_TIME_OFF=24 独立吻合，
//         且 7.0 判定核 sub_10091E684 的 `v6 = a2[6]` 也是它 ⇒ 跨版本一致
//   +0x1C 次时间（dword）—— 外部参考实现的判据是 `+24 >= t || +28 > t`
//   +0x30 / +0x5C / +0xA0  类型专属重武装字段（外部参考实现对其中一类清这三个）
//   +0xD8 子对象指针（另一类：清子对象 +0x10 字 / +0x12 字节）
#define XRC_NOTE_JUDGED_OFF        0x0C
#define XRC_NOTE_TIME2_OFF         0x1C

// ---------------- GameScene ----------------
// 出处: 逆向笔记 §2/§3
// （vtable RTTI 名 9GameScene 已验；本文件所有值均为 image 偏移，
//   运行时地址 = image_base + offset）
#define XRC_OFF_GP_VTABLE          (0x151D8C0ULL)   // 绝对 VA 0x10151D8C0
// 每帧更新 = vtable 槽 103 sub_100CA7160（帧去重模式与 6.13 gp.update 同源：
// 全局时间 +308 == self+1168 走快路径；否则 tick note group + 判定分发）。
// 槽 155（sub_100CA118C）是场景初始化函数（只跑一次），不是每帧更新。
#define XRC_OFF_GP_UPDATE_FN       (0xCA7160ULL)    // 五参 (self,a2,a3,a4,a5)，同 6.13

// ---------------- 桩点（改判） ----------------
// 出处: 逆向笔记。判定核心 = sub_10091E684（与 6.13 sub_100870FD0 逐行同构的整数 CMP 级联；
// 判别：sub_1009D9ED8/表B 是特效显示链，不参与判定）。
// ABI: X0 = note_group, X1 = note, X2 = ts（判定时刻 ms）；返回 1 = 消费该 note，
// 0 = Miss（不消费）。handler 另收 X3 = caller X6（跳板 v2 的 MOV X3,X6）。
#define XRC_HAS_JUDGE_STUB          1
#define XRC_JUDGE_STUB_ENTRY_OFF    (0x91E684ULL)   // sub_10091E684（判定核心，2 处直接 BL 调用）
#define XRC_OFF_JUDGE_COMMIT_FN     (0xACB880ULL)   // sub_100ACB880（grade 落账，6 参，首指令是门）
#define XRC_OFF_JUDGE_COMMIT_LN_FN  (0xACB6A4ULL)   // sub_100ACB6A4（近失/长条落账，3 参）
#define XRC_OFF_JUDGE_FX_OBJ        (64)            // note_group+64 = 特效对象
#define XRC_OFF_JUDGE_COMMIT_OBJ    (56)            // note_group+56 = 判定计数对象
// 桩跳板（inject.py 生成，跳板 v2 = 40B：分发 + MOV X3,X6 + native 重放 3 条）
// 布局：ADRP/ADD(8) LDR(4) CBZ(4) MOV X3,X6(4) BR(4) → native 重放 3 条原指令
// + B 回 entry+12。handler 从 X3 拿 caller 的 X6（判定核从不写、落账函数需要）。
// 直通（slot.handler==0）= CBZ 跳 native，行为与未注入完全一致。
#define XRC_STUB_TRAMP_OFF          (0x146800CULL)  // trampoline 静态偏移

// 判定函数的 8 个 CMP 阈值站点（CMP Wn,#imm12）。
// 方案：**handler + 运行时阈值**（dylib 写 __TEXT 会撞 CT/PAC）。这些偏移保留用于：
// (a) 跨版本指纹校验；(b) 静态烘焙路线（重打包版把 imm12 直接写成目标值 → 无需桩点）。
// 分支 B（分段钟，clk+45==1）：26/51/101/121
// 分支 A（普通钟）：25/50/100/120
// 注入器在 __DATA 零填充尾部写入 slot（24B）+ info blob（120B，紧邻其后）。
#define XRC_JUDGE_SLOT_OFF          (0x164AB28ULL)
#define XRC_INFO_OFF                (0x164AB40ULL)   // slot + 24

// ---------------- retry 触发链（研究记录；**禁止调用**） ----------------
// 出处: 逆向笔记 §11（retry 三层链路逆向）
// 程序化 retry 不可行：触发调用（triggerAction(GameModel, 13, 1) 及"建暂停层+推进度"
// 组合）会被游戏静默忽略（Retry 回调首校验 PauseLayer+0x298==1），且重复触发会污染
// GameModel action 队列，让玩家手动 retry 卡在转场界面。
// 手动 retry 由玩家操作；本插件只做"音频回跳检测 → 回循环 A"（见 XRCGameplay.m
// retry watchdog）。相关偏移不落入 profile，代码不得引用。

// note 字段（改判 handler 读；replay-chain 笔记 §3.2）
#define XRC_NOTE_TIME_OFF           24

// ---------------- 转场 / 循环 ----------------
// 出处: 逆向笔记 §6 + 诊断笔记 §7
// replay 路线 = deferred seek 平移（音频 seek + 谱面钟 base 平移）；循环 = 到 B 点
// deferred 回 A。已判 note 不重现、计分不回滚，属"练习定位"语义；需要完整重播时
// 玩家在暂停菜单自行 retry 后再 seek。
// 直调转场不可用：sub_100CA9590 先构造新场景、再读已拆解的旧场景 note group
//（sub_10091BBB8(v3[116]) 为 NULL）→ far=0x30 空指针。相关探针与常量不落入 profile。

// ---------------- 音频链（seek/进度条） ----------------
// 出处: 研究笔记 ios-7.0.255-replay-chain.md 重定位（锚点链：6.13 RTTI 名
// 20AudioProviderFMODiOS → 7.0 typeinfo 0x1014B7690 → MTP vtable 0x1014B75B0；
// getpos 槽 7 与 seek 槽 8 形状与 6.13 逐条一致）
// 路线：只读位置 + seekTo。
#define XRC_OFF_MTP_VTABLE           (0x14B75B0ULL)   // 绝对 VA 0x1014B75B0（注意：偏移是 0x14B75B0）
#define XRC_OFF_MTP_GETPOS           (0x8E24F0ULL)    // vtable 槽 7，形状同 6.13
#define XRC_PLAYER_SEEK_SLOT_OFF     (0x40)           // vtable 槽 8，形状同 6.13
// vtable 槽 6（+0x30）= setPaused(paused, index)：内部按 index 取通道 handle
// （0 = 默认 *(mtp+0x18) = mainBGMGroup 句柄）后尾调 FMOD_Channel_SetPaused。
// 证据：外部参考实现全链对齐（resolver 0x1010E846C → 对象 vt[+0x10] → 实现 0x1010E84A0 与 6.13
// 逐字节相同）；7.0 的 FMOD_Channel_SetPaused 本体 = 0x1010E2CCC。详见
// 内部设计纪要（离线记录） §1.3/§2。
#define XRC_PLAYER_PAUSE_SLOT_OFF    (0x30)           // vtable 槽 6
#define XRC_OFF_CH_GET_POSITION      (0x1033BBCULL)   // Channel::getPosition（内层同源）
#define XRC_OFF_GET_CURRENT_SOUND    (0x103415CULL)   // Channel::getCurrentSound（日志串已验）
// get_sound_length：未定位（进度条用 max_seen 兜底）。
// get_registry：由 getpos hook 缓存 player 实例替代。
#define XRC_OFF_GET_REGISTRY        0
#define XRC_OFF_GET_SOUND_LENGTH    0
#define XRC_REG_PLAYER_OFF          (8)
#define XRC_PLAYER_CHANNELS_OFF     (0x38)
#define XRC_CHANNEL_ENTRY_PTR_OFF   (8)

// ---------------- FMOD：音乐变速用到的入口 ----------------
// 出处：FMOD 静态链入本二进制，各 API 自带调试串（`ChannelControl::addDSP` 等）→ 字符串 xref 定位。
//   路线：直接用 **FMOD 内置移调 DSP**：
//     ① setPitch(BGM 组, rate) 让音乐跟着速度走（音高随动）
//     ② 组上挂内置 Pitch Shifter，参数 1/rate 把音高补回来 ⇒ 时长随速度、音高不变
//     ③ 移调 DSP 有固有延迟（≈FFT 窗），把通道位置前移 rate·L 补偿
//   类型号**不写死**：运行时枚举 createDSPByType + DSP::getInfo 取名字含 "Pitch" 者（XRCAudio.m）。
#define XRC_OFF_FMOD_CC_SET_PITCH      (0x10E32F8ULL)   // ChannelControl::setPitch(cc, float)（乘数语义）
#define XRC_OFF_FMOD_CC_ADD_DSP        (0x10E5194ULL)   // ChannelControl::addDSP(cc, index, dsp)
#define XRC_OFF_FMOD_CREATE_DSP_BY_TYPE (0x10ABA64ULL)  // System::createDSPByType(sys, type, &dsp)
#define XRC_OFF_FMOD_DSP_SET_PARAM_FLOAT (0x1063D74ULL) // DSP::setParameterFloat(dsp, index, value)（C API 3 参）
// ⚠ **调试串 xref 的地址不是函数入口**：以 xref 地址（getParameterFloat +0x128 /
//   getInfo +0x158）调用会进函数中段 ⇒ 序言没跑 + 出参写到栈上 ⇒ __stack_chk_fail 崩
//   （首次变速、DSP 探测阶段）。以下地址均已回查函数起始。
#define XRC_OFF_FMOD_DSP_GET_PARAM_FLOAT (0x1064210ULL) // DSP::getParameterFloat(dsp, idx, &v, valuestr, valuestrlen)（**5 参**）
#define XRC_OFF_FMOD_DSP_GET_INFO      (0x1064C70ULL)   // DSP::getInfo(dsp, &name, &ver, &ch, &cw, &chh)（**6 参**）
#define XRC_OFF_FMOD_DSP_RELEASE       (0x1062658ULL)   // DSP::release(dsp)（1 参）
#define XRC_OFF_CH_SET_POSITION        (0x1033A94ULL)   // Channel::setPosition(ch, pos, unit)
#define XRC_PLAYER_BGM_GROUP_OFF       (0x18)           // AudioProviderFMODiOS + 0x18 = mainBGMGroup 句柄
#define XRC_OFF_FMOD_SYSTEM_GLOBAL     (0x164E678ULL)   // qword_10164E678：游戏自己存的 FMOD_SYSTEM*（免落桩取用）

// ---------------- BRK 桩（第二种插桩形态）----------------
// 原理：注入器把目标指令原地改成 `BRK #0`（4B，长度
// 不变），dylib 用 SIGTRAP 处理器接住，跑完自己的逻辑后把 ucontext 的 PC 指到
// 预建的"重放跳板"（原始指令 + B 回 site+4），执行流无感继续。
//
// 与既有 trampoline v2 的取舍：
//   trampoline v2 = 改函数入口前 12B 为 ADRP/ADD/BR，跳板重放前 3 条 —— 仅适用
//                   函数入口，且要吃满入口 12 字节。
//   BRK 桩        = 任意单条指令可打，补丁长度不变、不动入口结构；代价是引入
//                   SIGTRAP 处理器（必须正确 chain 给前一个处理器，否则会吞掉
//                   Swift 运行时 / Crashlytics 的陷阱）。
//
// 首个站点 = **applog 发送函数入口**（OnlineManager 槽 72）：观测 applog 触发。
#define XRC_HAS_BRK_HOOK            1
#define XRC_BRK_APPLOG_SITE_OFF     (0x623AECULL)   // sub_100623AEC 入口（VA 0x100623AEC）
#define XRC_BRK_APPLOG_REPLAY_OFF   (0x1468040ULL)  // 重放跳板（__TEXT 空白页，VA 0x101468040）
#define XRC_BRK_MAX_SLOTS           64

// 第二个桩点：log_blob 组装处（密文出口）。
// 出处: 静态定位 + 真机验证。
//   sub_100623AEC 在 0x1006399B0..0x1006399D8 把待发送的 std::string 从
//   sp+0x290(var_380) 拷到 sp+0x240(var_410)，随即 0x1006399DC `adrl x1, "log_blob"`
//   把它当表单字段的值送出。命中时刻的帧内容不做静态假定，整帧带走离线检索。
//   桩点 0x1006399E4（`add x0, sp, #0x1e8`，SP 相对、重放安全）；相邻的 0x1006399DC
//   是 ADRL（PC 相对），不能在重放跳板执行。
//   命中时 handler 从 ucontext 取 SP，整帧带走（离线再检索）。
#define XRC_BRK_APPLOG_BLOB_SITE_OFF   (0x6399E4ULL)
#define XRC_BRK_APPLOG_BLOB_REPLAY_OFF (0x1468050ULL)  // 紧邻上一个跳板，8B，已核对为全零
// 整帧捕获（XRC_APPLOG_BLOB_FRAME_LEN 字节）：不做单槽假定，离线检索密文段。
#define XRC_APPLOG_BLOB_FRAME_LEN      (0x700ULL)      // 从 SP 起抓这么多字节

// ---------------- 私服接入（XRCNet）----------------
// 出处: 真机内存转储分析。
// 7.0 的 API base 多了一层 codename + 版本号：
//     https://arcapi-v4.lowiro.com/coordinatedballetclock/42/<endpoint>
// **codename 不存在于静态二进制**（明文/UTF-16/片段均无），只出现在运行时拼好的
// URL 里（以 NSURLRequest 的 bplist 形式驻留内存）——来源未定，可能服务端下发。
// 因此 XRCNet 只改写 scheme/host/port，**保留 path 与 query**，服务端按版本段之后
// 的 suffix 路由即可，与该前缀解耦。
// pin：pin 表按域名查询，换到自有域名后返回 DomainNotPinned → 放行；故无需绕 pin。
#define XRC_NET_DEFAULT_MATCH \
    "arcapi-v4.lowiro.com,arcapi-v3.lowiro.com,auth-v2.lowiro.com,auth.lowiro.com"

// applog 明文的来源：
//   sub_100623AEC 内 0x100625434 处 `LDR X8,[SP,#var_5F8]`（= 入口 X0，OnlineManager）
//   紧接 `LDP X19,X21,[X8,#0x128]` —— X19/X21 即 payload 缓冲区的 begin/end，
//   随后用它们算区间长度并做内联 XXTEA。因此**入口处就能读到整段明文**，
//   无需在函数体内部另设桩点。
#define XRC_APPLOG_BUF_BEGIN_OFF    (0x128)   // OnlineManager → uint8* 明文起点
#define XRC_APPLOG_BUF_END_OFF      (0x130)   // OnlineManager → uint8* 明文终点
#define XRC_BRK_CAP_MAX             (1u << 20)  // 单次捕获上限 1MB（超出只记长度）

// ---------------- BRK 桩：拥有/解锁链（可控开关，功能账 §1）----------------
// 出处: research/notes/xrc-feature-hooks-ledger-2026-09-14.md §1.1。
// 逐字节对照（vs 6.13.10）：层1 全等；层2 仅 8 处 BL 目标重定位（22B 差）；层3 仅 BL 目标；
// 故事门重编译（47B 差，序言 16B 全等，尾 = return 层1查表(bool)）。
// 语义：开关（xrc_brk_set_unlock_own）置真 → handler 强制 `x0=1; PC=LR` 直返；
// 置假 → 走重放跳板，行为与未注入完全一致。
// ⚠ 本组（拥有链三层）：归属由 cb 三清单 + 服务器授予决定，仅覆盖"服务器未授予、
//   但本地已有内容"的情形。开关 unlockOwn 默认关。
//   2026-10-16 起 release 构建亦注入（归属复查是 start 门的上游，见下）：
//   点 START 的归属复查链 = sub_100C14898（L3/L1）→ 未拥有 → sub_100C0FEB4 离线门失败
//   → sub_100C0DDA8 弹「You must be online and logged in to unlock songs…」；
//   曲包状态机 sub_100CD0108 在两处消费同一 BE46A8（曲包锁与可玩性同源）。
//   消费点极性核验：0x100C15394 `TBZ W0,#0 → 未拥有分支`（**1 = 拥有**）。
#define XRC_BRK_UNLOCK_L1_SITE_OFF   (0xBE46ACULL)  // 层1 第 2 条指令（首条 CBZ X1 是
                                                    // PC 相关指令、不可重放；本条 LDR 安全）
#define XRC_BRK_UNLOCK_L1_REPLAY_OFF (0x1468058ULL)
#define XRC_BRK_UNLOCK_L2_SITE_OFF   (0xBE46ECULL)  // 层2 入口（SUB SP,SP,#0x80）
#define XRC_BRK_UNLOCK_L2_REPLAY_OFF (0x1468060ULL)
#define XRC_BRK_UNLOCK_L3_SITE_OFF   (0xBE4D38ULL)  // 层3 入口（STP X29,X30,[SP,#-0x10]!）
#define XRC_BRK_UNLOCK_L3_REPLAY_OFF (0x1468068ULL)

// ---------------- BRK 桩：cb 验证链（可开关，功能账 §3）----------------
// 出处: research/notes/xrc-feature-hooks-ledger-2026-09-14.md §3（6.13→7.0 逐函数字节/结构证据）。
// 开关（xrc_brk_set_cb_bypass）置真：
//   cb_ready             → 就绪位恒真（w0=1 直返；覆盖冷启动 caller 尾部的就绪判定）
//   cb_filehash/listhash → 校验恒通过（B.NE 恒不跳；成功块照常置 valid）
//   cb_wipe              → 清树入口直返（cb/meta* 与 cb/active 整树保持原样）
//   cb_dispatch          → 更新错码分发入口直返（错误弹窗/返回标题不发生）
//   cb_gate              → 内容更新强制门入口直返 w0=0（不弹窗、不换场回标题）
//   cb_fetch             → 内容包更新指令处理器入口直返（忽略服务器更新指令，设备内容即真值）
#define XRC_BRK_CB_READY_SITE_OFF    (0xF43274ULL)  // LDRB W0,[X0,#0x28]; RET（8B 函数；0x28 = cb 有效性字节）
#define XRC_BRK_CB_READY_REPLAY_OFF  (0x1468078ULL)
// cb 自由化：让校验结论恒为通过的三站点（开关 xrc_brk_set_cb_bypass）：
//   ① 逐文件 sha256 比较 B.NE（不跳=视为相等）  ② 三清单 HMAC 比较 B.NE（同上，成功块照常置 valid）
//   ③ 清树入口直返（cb/meta* 与 cb/active 整树保持原样）
// ⚠ ① ② 为 PC 相对条件分支：重放跳板会在别处算错目标 ⇒ replay=0，handler 按 NZCV 自行复现。
#define XRC_BRK_CB_FILEHASH_SITE_OFF   (0xF44F9CULL)   // B.NE loc_100F451C0
#define XRC_BRK_CB_FILEHASH_TARGET_OFF (0xF451C0ULL)   // 不等 → 失败路径（关开关时复现用）
#define XRC_BRK_CB_LISTHASH_SITE_OFF   (0xF450B0ULL)   // B.NE loc_100F451D4
#define XRC_BRK_CB_LISTHASH_TARGET_OFF (0xF451D4ULL)
// 清树函数 sub_100F43C08（0x43C08-0x43FA0 实读）：删 cb/meta_old.cb、cb/meta.cb、cb/meta_new.cb
// 三个文件（fs vtable+0x140），**rm -r 递归删 cb/active 整树**（vtable+0x138；"cb/active" 与 "cb/active/"
// 两次调用），再清内存态（meta map 清空 + 有效性字节 0x28=0 + 版本/uuid 串清空）。此处即
// research/notes/xrc-cb-merged-2026-09-15.md 行 28 所记"清 meta×3 + rm -r cb/active = 就地清理"——
// 此前两次"cb 被清"事件的执行体。校验任一环节失败都会调它 ⇒ 无 meta.cb / 校验不过时，
// meta 文件与整个 cb/active 内容树都会被删；"场景 1（有 meta 但校验不过）"被清后，
// 第二次启动即退化为"场景 2（无 meta.cb）"。入口 SUB SP,SP,#0x70，重放安全。
#define XRC_BRK_CB_WIPE_SITE_OFF       (0xF43C08ULL)
#define XRC_BRK_CB_WIPE_REPLAY_OFF     (0x1468120ULL)
// 更新错码分发 sub_10013C5E8（void）：v7==5「A new version of Arcaea is available…」、
// v7==9/11 → sub_100131678（在线时弹「This version of Arcaea is preparing for release…」）、
// 其余非零 →「Failed to get the latest content information…Error Code」。入口 SUB SP,SP,#0x100，重放安全。
#define XRC_BRK_CB_DISPATCH_SITE_OFF (0x13C5E8ULL)
#define XRC_BRK_CB_DISPATCH_REPLAY_OFF (0x1468088ULL)
// ---- cb 自由化 · 版本/更新链（无 meta.cb 情形；2026-10-12 补）----
// 场景：本机没有 meta.cb（用户手填内容包）→ cb 版本串恒为空（0x30/0x48 两串无值）+
// 校验器在版本比较失败时把有效性字节置 0 —— 版本/更新层还有两处会把用户挡在门外：
//   ①「内容更新强制门」sub_1001963D8（OnlineManager::tryHandleContentBundleOldError，长 0x268）：
//      服务端错误码 code 11（内容包过旧）→ 弹「A new content update is required. Returning to
//      title screen.」+ 换场回标题（tag 162411）⇒ 拒绝进入。调用者 = 68 个 HTTP 端点响应处理器
//      （0x1007FA490-0x100819C78 全家族；样本 sub_1007FFD84 行 31-33、sub_1008003C8：
//      code==11 → 调本门，返 0 则照常把错误码交给请求完成路径）。
//      开关开 → **只记不跳**（2026-10-12 晚改）：直返依赖调用方对 0 的合同解释
//      （"已在标题、无事可做"），其触发面未实测；同批 cb_fetch 直返已被证伪会打断启动链（见②）
//      ⇒ 宁缺毋假，重放原逻辑。入口序言 SUB SP,SP,#0xF0（SP 相对、重放安全）。
//   ②「内容包响应处理」sub_100815498（0x1B0 帧；+0xA0 处引 "orderedResults"）：
//      处理 /game/content_bundle 响应（orderedResults = 分片化更新清单）。
//      出处 research/notes/xrc-plugin-site-semantics-2026-09-19.md §3.1（原设计＝入口直返
//      「忽略服务器的内容包更新指令，设备内容即真值」）。
//      ⚠ 2026-10-12 晚实测证伪：入口直返会把 content_bundle 失败路径的收尾一并跳掉——
//      发布构建（联网阻断 → 该请求必 -1022）下 cb 自由化 on 的启动全部永挂"进菜单之前"
//      （停在 -1022 之后：无 compose/aggregate、无 unlock/me；cb 关则 1s 内续走；对照 c0fa5c6
//      五点集合同机同内容全程正常）⇒ 改为**只记不跳**，重放原逻辑（等价未注入）。
//      入口序言 SUB SP,SP,#0x1B0（SP 相对、重放安全）。函数身份证据=[高]（字符串引用+前作笔记）。
#define XRC_BRK_CB_GATE_SITE_OFF     (0x1963D8ULL)   // 内容更新强制门入口（SUB SP,SP,#0xF0）
#define XRC_BRK_CB_GATE_REPLAY_OFF   (0x1468128ULL)
#define XRC_BRK_CB_FETCH_SITE_OFF    (0x815498ULL)   // 内容包更新指令处理器入口（SUB SP,SP,#0x1B0）
#define XRC_BRK_CB_FETCH_REPLAY_OFF  (0x1468130ULL)

// ---------------- 未注册桩位还原表（自愈用）----------------
// cb_verify（= 校验函数 sub_100F43FFC 入口）不在当前桩表中，但既有二进制可能留有它的
// BRK：命中即"无处理器的 SIGTRAP"直接闪退（pc-base = 0xF43FFC，原指令
// STP X28,X27,[SP,#-0x60]!）。命中时就地写回原指令并重跑（自愈），见 XRCHook.m s_sigtrap。
#define XRC_RESTORE_CB_VERIFY_SITE_OFF (0xF43FFCULL)   // 原指令 STP X28,X27,[SP,#-0x60]!

// ---------------- BRK 桩：自动演奏（外部参考实现对齐；功能账 §5.2）----------------
// 出处: 外部参考实现实件（离线样本，BRK 就地打桩形态）——宿主双胞胎逐指令序列对齐
//   （外部参考实现 0x100871E00 (0x5E4) ↔ 7.0 sub_10091D9A0 (0x5E4)，258 条指令逐条配对；
//   其余站点按入口序言/字节模板唯一命中）。
// 机制要点（与 外部参考实现行为等价，实现按 7.0 布局重写）：
//   · 长条（hold/arc）：把 note+0x64（longTouchState 首字节）= 1 → 原版判定 pass 走"被触"
//     分支，由**游戏自己的 tick 循环**发 Pure（commit(0,0,now,-1) + fx[1]，7.0 原生代码）——
//     我们只改一个字节，落账/计数/视觉全走原版（与 6.x 的 +0x5C 同字段，7.0 漂移 +8）。
//   · 窗口点强判：谱面时刻到达 note+0x1C 即直调 commit(Pure, judge_time=note+0x1C) + fx[1]，
//     随后跳回原版汇合点（0x91DD44 / 0x91DF5C）——视觉时序 = 音符自身时刻。
//   · 触摸吞掉：三个输入入口（逐触消费/批处理/触摸批）恒返回 0（x0=0; PC=LR），
//     玩家真实触摸不干扰（外部参考实现三触控入口同款）。
//   · 弧线视觉：场景 tick 的清态点重新置"被触"（外部参考实现 on_arc_visual_clear 同款）。
// 开关：xrc_judge_set_autoplay（既有）。关 → 每站重放原指令，行为与未注入完全一致。
#define XRC_BRK_AP_LN_STATE_SITE_OFF     (0x91DBC8ULL) // LDRB W8,[X0,#0x64]（长条触摸态读取点，外部参考实现 on_long_state：0x100872028）
#define XRC_BRK_AP_LN_TICK_SITE_OFF      (0x91DC48ULL) // LDR X8,[X27]（长条判定派发前 vtable 装载，外部参考实现 on_long_tick：0x1008720A8）
#define XRC_BRK_AP_NOTE_WIN_SITE_OFF     (0x91DD70ULL) // CMP W2,W8（W8=note+0x1C+0xC8，外部参考实现 on_note_window：0x1008721D0）
#define XRC_BRK_AP_ARCTAP_WIN_SITE_OFF   (0x91DF34ULL) // CMP W2,W8（W8=note+0x1C+0x64，外部参考实现 on_arctap_window：0x100872394）
#define XRC_BRK_AP_SWALLOW_JUDGE_SITE_OFF (0x91EBC8ULL) // sub_10091EBC8 入口（逐触消费；SUB SP,#0x170，外部参考实现 on_touch_handler：0x100872F70）
#define XRC_BRK_AP_SWALLOW_BATCH_SITE_OFF (0x91F688ULL) // sub_10091F688 入口（输入批处理+漏扫；SUB SP,#0xA0，外部参考实现 on_touch_phase：0x100873A04）
#define XRC_BRK_AP_SWALLOW_TOUCH_SITE_OFF (0x921DC4ULL) // sub_100921DC4 入口（触摸批→消费 mode0；SUB SP,#0x80，外部参考实现 on_touch_batch：0x100875AB8）
#define XRC_BRK_AP_ARC_VISUAL_SITE_OFF   (0x91CC84ULL) // STRH WZR,[X0,#0x10]（场景 tick 弧清态，外部参考实现 on_arc_visual_clear：0x1008710B0）
#define XRC_BRK_AP_LN_STATE_REPLAY_OFF     (0x14680B0ULL)
#define XRC_BRK_AP_LN_TICK_REPLAY_OFF      (0x14680B8ULL)
#define XRC_BRK_AP_NOTE_WIN_REPLAY_OFF     (0x14680C0ULL)
#define XRC_BRK_AP_ARCTAP_WIN_REPLAY_OFF   (0x14680C8ULL)
#define XRC_BRK_AP_SWALLOW_JUDGE_REPLAY_OFF (0x14680D0ULL)
#define XRC_BRK_AP_SWALLOW_BATCH_REPLAY_OFF (0x14680D8ULL)
#define XRC_BRK_AP_SWALLOW_TOUCH_REPLAY_OFF (0x14680E0ULL)
#define XRC_BRK_AP_ARC_VISUAL_REPLAY_OFF   (0x14680E8ULL)
// 诊断计数站点：引擎 tick 助手的返回点（MOV X26,X0 → 重放安全），
// 用来量化"引擎自己发了多少 tick 判定"（对账物量/分数与原谱）。
#define XRC_BRK_AP_TICKCNT1_SITE_OFF    (0x91DCBCULL) // helper1(sub_10091E878, Pure tick) 返回后：X0 = 本次 Pure tick 数
#define XRC_BRK_AP_TICKCNT2_SITE_OFF    (0x91DDBCULL) // helper2(sub_10091E958, Lost tick) 返回后：X0 = 本次 Lost tick 数
#define XRC_BRK_AP_TICKCNT1_REPLAY_OFF  (0x14680F0ULL)
#define XRC_BRK_AP_TICKCNT2_REPLAY_OFF  (0x14680F8ULL)
// 曲目锁态覆盖站点（取证 research/notes/xrc-packlock-rootcause-2026-09-19.md；
// ⚠ 极性 2026-10-16 修正：五字节序 **1 = 锁、0 = 可玩**，详见下方"全条件放行"块）：
// 锁状态函数 sub_100919E5C 内的两个专属子分支，各自只有唯一调用方（锁态函数自身），
// 入口直返 0（普通歌曲的原生"干净"值）即可对齐显示；开关 = unlockFv / unlockDo。
//   · 0x991508 = FV 五曲 fast path（入口 STP X20,X19,[SP,#-0x20]!；重放安全）
//   · 0xAAE50C = DO(konzetsu) 分支（入口 SUB SP,#0xD0；重放安全）
#define XRC_BRK_LOCK_FV_SITE_OFF        (0x991508ULL)
#define XRC_BRK_LOCK_FV_REPLAY_OFF      (0x1468100ULL)
#define XRC_BRK_LOCK_DO_SITE_OFF        (0xAAE50CULL)
#define XRC_BRK_LOCK_DO_REPLAY_OFF      (0x1468108ULL)
// 终章链门覆盖：sub_10099156C 是 FV 五曲"锁标 + 开局门"的**共同上游**——
//   锁态函数 sub_100991508 与可玩性谓词 sub_100919874（选曲 cell / Play 门）都调它；
//   未推进终章链时返回 1 = 锁 → 既显示锁标也挡住 start。
//   入口直返 **1（放行）**（极性：0 是锁）；开关 = gateOpen。入口指令 SUB SP,#0xC0，重放安全。
#define XRC_BRK_FV_GATE_SITE_OFF        (0x99156CULL)
#define XRC_BRK_FV_GATE_REPLAY_OFF      (0x1468110ULL)
// 链进度覆盖（取证 research/notes/xrc-chain-regression-6.13-vs-7.0-2026-09-19.md）：
//   7.0 的「链」系统：InitFunc_194 建 rank→曲名表（finale 五曲 / konzetsu 五曲+arghena），
//   运行时把**硬编码名**拼成 "<名>|<难度>" 去 mgr+0x28 容器查节点对象；而对象是按 songlist 的
//   **id 字段**注册的（解析器 sub_100C7BAE0 @0x100C7E470 同一键式）→ 曲目 id 被改名（或 set 被挪，
//   注册不发生）时对不上 → sub_1001811C4 返回 NULL → sub_10098FB1C 不判空 → 读 [NULL+0x28] 崩
//   （崩溃链 sub_100CA118C → sub_10018A3A8 → sub_10098F5BC → sub_10098FB1C）。
//   6.13 无此系统（balor/cataclysmcry/konzetsu 字面量全无）→ 该崩因是 7.0 回归。
//   入口直返 100（= 该函数自身"无场景对象"路径的合法进度值）→ 不查表（改名/挪包均安全），
//   并令 sub_10099156C 的 v19=(98FB1C==0) 恒 0 = 可玩。**不设开关**（守崩，恒开）。
//   入口指令 SUB SP,#0xB0（重放安全）；配对标记 "chain-guard v1"。
#define XRC_BRK_CHAIN_PROG_SITE_OFF     (0x98FB1CULL)
#define XRC_BRK_CHAIN_PROG_REPLAY_OFF   (0x1468118ULL)

// ---------------- BRK 桩：全条件放行族（unlock_all / dl_ready；2026-10-12 取证）----------------
// 出处: 本版原生二进制（samples/arcaea/7.0.255/ios/work/stage1/Arc-mobile，md5 49fbbba8…）
//   逐函数反汇编 + 调用点扫描；与前作 xrc-packlock-rootcause / xrc-chain-regression /
//   xrc-download-state-rootcause 三笔记交叉一致。
// 目标（第一性原理）：**本地存在合法谱面（该难度在 songlist 声明，song+0x250[idx]!=0）时，
//   任何"条件"不得阻止其可见、可游玩**。四处判定源头（覆盖 44+70+37/19+2 个调用点）：
//   ① 锁态总源 sub_100919E5C（入口 SUB SP,#0xB0）——五字节打包 b0..b4 = 按难度锁态，
//      **1 = 锁、0 = 可玩**（2026-10-16 指令级四锚点修正；此前"1=可玩"是把本函数
//      「未声明难度→0x0101010101 早退」误读为"全解锁"，四锚点＝BDCD2C 阻塞谓词拷贝进字节 /
//      8660F8 放行判"非全 1" / 标题守卫 bit0=1→"???" / DO 分支构造 未满足=0x0101010101、满足=0）；
//      44 个调用点（选曲 cell/曲绘/横幅/世界/包页）全部读它。当前难度已声明则直返 (0,0)；
//      未声明难度保留原判定（守卫同上）。补：详情页评级"?"的消费点读 **bit24**（置位隐藏评级）；
//      x1 = 第二返回值"额外锁定原因"，门控放行分支（0x991530/34）同清 (x0,x1)=(0,0)。
//      （2026-10-16，与外部提交独立结论交叉一致。）
//   ② 可玩性总源 sub_100919874（入口 SUB SP,#0x60）——选曲 start 钮/开局链的唯一谓词，
//      70 个调用点且消费方按 CBNZ=可用 判（50 8EAF84、70 B60ECC L621 为典型）。直返 1。
//      ⚠ 守卫：仅当该难度"已声明"才放行（song+0x250[BDCD20(diff)]!=0）——没有谱面的难度
//      不硬开，避免开局加载失败 __cxa_throw（scene_run_7x.c L589-707 的崩点）。
//   ③ 难度条件 sub_100BDC5A8（入口 SUB SP,#0x90）/ sub_100BDC8D4（入口 SUB SP,#0x60）
//      ——"解锁条件"对象求值（SpellMagnolia/Arghena*/conditions 家族）。除两个总源内部调用外
//      另有 37/19 个独立调用点（cell 徽记、难度格可用性）。直返 1（条件恒满足）。
//   ④ 下载"需动作"谓词 sub_100850308（入口 STP X22,X21,[SP,#-0x30]!）——启动钮 download.png
//      图标与开局转"Download song?"弹窗的唯一谓词（仅 2 调用点：B60ECC、C117F4）。
//      直返 0（无需动作）。⚠ 不改 sub_100844774（下载机制本体，2026-09-28 教训），
//      仅旁路"UI/开局截流"；文件真实存在性仍由开局链亲自校验（缺文件 → 温和失败+重扫）。
//      补：原生键位——开局音频 = `<id>`（sub_10084DD38；**不带下划线**），谱面 = `<id>_<diff>`
//      （84D708→8429D0→84292C）。本地导入映射与排障按此键位（2026-10-16 交叉证据）。
// 开关：unlock_all（①②③；默认关）、dl_ready（④；默认关，纪律见 xrc-download-stack-cocos §8）。
// 另：锁绘分支族（四处，见下）随 unlock_all || unlock_do 联动（显示一致性）。
#define XRC_BRK_LOCK_ALL_SITE_OFF      (0x919E5CULL)   // ① sub_100919E5C 入口
#define XRC_BRK_LOCK_ALL_REPLAY_OFF    (0x1468138ULL)  // ⚠ 0x128/0x130 已被 cb_gate/cb_fetch 占用
#define XRC_BRK_PLAY_GATE_SITE_OFF     (0x919874ULL)   // ② sub_100919874 入口
#define XRC_BRK_PLAY_GATE_REPLAY_OFF   (0x1468140ULL)
#define XRC_BRK_COND_UNLOCK_A_SITE_OFF (0xBDC5A8ULL)   // ③ sub_100BDC5A8 入口
#define XRC_BRK_COND_UNLOCK_A_REPLAY_OFF (0x1468150ULL)
#define XRC_BRK_COND_UNLOCK_B_SITE_OFF (0xBDC8D4ULL)   // ③ sub_100BDC8D4 入口
#define XRC_BRK_COND_UNLOCK_B_REPLAY_OFF (0x1468158ULL)
#define XRC_BRK_DL_PLAY_SITE_OFF       (0x850308ULL)   // ④ sub_100850308 入口
#define XRC_BRK_DL_PLAY_REPLAY_OFF     (0x1468148ULL)
// ⑤ 包状态机 sub_100CD0108（0x268 长）——pack 级"可否进入/是否可见"的唯一来源（13 个调用点）：
//   返回 1 = 不可进（点击拦截 sub_100B17274 弹 `story_pack_lock_message.png` +
//   「Complete 'Black Fate' and see VS-8 to progress to this Pack」@0x1013A732C；封面
//   sub_100CCFE68 换 `pack_inaccessible.png`；歌列表 sub_10087DF94 跳过该包），2/3 = 可进（3 = 已拥有）。
//   FV 包（isFinale）判定 =（拥有 || 非 finale）→ 2/3；否则查世界进度字节 + 按名拥有 "vs"。
//   ——与 fv_gate(56C，歌曲级) 结构上无关（全调用点核对，2026-10-16）。
//   入口直返 3（已拥有）→ 包可进、封面正常、曲目不跳过；开关 = gateOpen（面板已 ||unlockAll）。
//   入口指令 SUB SP,SP,#0x50（SP 相对、重放安全）。出处：.idamcp/_hot_100CD0108.c、
//   _hot7_asm_cd0108_body.txt、_hot3_B17274.c、_hot3_CCFE68.c、_hot2_callers_CD0108.txt。
#define XRC_BRK_PACK_OPEN_SITE_OFF      (0xCD0108ULL)
#define XRC_BRK_PACK_OPEN_REPLAY_OFF    (0x1468160ULL)
// ⑥ 进歌在线检查完成位（TransitionShutter）：`scene+0x348` 的**唯一清零点** 0x976F68
//   （`strb wzr,[x19,#0x348]`；建厂期由 setter 置 1）。两个消费点均按 ==1 放行
//   （0x100979E60 调度端 / 0x10097A1AC 等待端）；离线时在线上报必失败、失败路径不置 1
//   ⇒ 逐帧等待吃满 7.0s 弹「Network Error / Retry / Continue Offline」。跳过清 0 ⇒
//   完成位恒 1 ⇒ 等待与弹窗结构性不可达（等效自动 Continue Offline）。开关 = gateOpen。
//   站点指令为非 PC 相对普通存储（重放安全）。出处 .idamcp/_login_inv/（2026-10-16 专项）。
#define XRC_BRK_SHUTTER_DONE_SITE_OFF   (0x976F68ULL)
#define XRC_BRK_SHUTTER_DONE_REPLAY_OFF (0x1468168ULL)
// arghena 专属锁绘旁路：sub_10084EE7C 内 0x84EF48 的 `TBNZ X0,#0x20`（X0 = sub_100919E5C
//   返回值，bit32）。置位（= 锁态标志之一）→ 落 0x84F05C → 调 sub_10084F0E8 →（包==konzetsu）
//   `img/jacket_locked_konzetsu.jpg`。锁态桩现值 0 ⇒ 本族与原生同侧（冗余保险）；
//   ON 时恒"不跳"（普通曲绘）、OFF 时按位复现原分支。
// 锁绘分支族（四处，均为 PC 相对条件分支 → no-replay，handler 按位复现；开关 = unlock_all ||
//   unlock_do）。全链证据：sub_10084F0E8 = 锁绘选择器（包 konzetsu/finale → jacket_locked_*；
//   id grievouslady/tempestissimo → "img/jacket_locked_"+id；undyingmacula 专属；其余 →
//   img/1080/jacket_locked_generic.jpg  @0x10137D770），触发器 = 锁态 b4 置位：
//   · ①0x84EF48（84EE7C 内，arghena 门）→ 落 0x84F05C；
//   · ②0x8EAFB4（选曲 cell，sub_1008EAB50）`TBNZ X8,#0x20`→0x8EAFDC（锁绘）；
//     不跳 = 0x8EAFB8（84EE7C 普通曲绘）。X8 = 该函数早段 919E5C 结果（存 [sp+0x18]）。
//   · ③0x94A57C（曲目信息面板）`TBNZ X0,#0x20`→0x94A59C（锁绘）；不跳 = 84EE7C 普通。
//   · ④0xB3F274（详情面板）`TBZ X24,#0x20`→0xB3F2A4（跳过 84F0E8 = 保留 84EE7C 普通结果，
//     0xB3F250 已先写好普通曲绘；置位则 84F0E8 结果覆写）→ 本族唯一"置位落锁绘"的 TBZ 形态。
//   OFF 时四处均按位复现（逐字节同原行为）；ON 时恒走普通曲绘侧。
#define XRC_BRK_JACKET_LOCK_SITE_OFF   (0x84EF48ULL)
#define XRC_BRK_JACKET_LOCK_TARGET_OFF (0x84F05CULL)   // 原 TBNZ 跳转目标（同函数内）
#define XRC_BRK_JACKET_CELL_SITE_OFF   (0x8EAFB4ULL)
#define XRC_BRK_JACKET_CELL_TARGET_OFF (0x8EAFDCULL)
#define XRC_BRK_JACKET_INFO_SITE_OFF   (0x94A57CULL)
#define XRC_BRK_JACKET_INFO_TARGET_OFF (0x94A59CULL)
#define XRC_BRK_JACKET_PANEL_SITE_OFF  (0xB3F274ULL)
#define XRC_BRK_JACKET_PANEL_TARGET_OFF (0xB3F2A4ULL)

// ---------------- 弧/绘制观测桩（只观测；站点语义见 XRCHook.m）----------------
// 三处都打在**入口 +4**（第二条指令），入口的 SUB SP 照常执行 ⇒ SP 自然正确；
// replay=0：handler 只需 PC=site+4（B 够不到 0x101468xxx）。见 XRCHook.m s_arcr_entry_exit。
// 绘制趟入口：X0 = TrackLayer，X1 = *(track+0x288) = 音符表 {begin,end}（0x100b23584 / 0x100b236b4）
// 弧 tick / 头过线入口：X0 = 该弧渲染对象（logic = *(X0+0x268)）
#define XRC_BRK_RPF_DRAW_SITE_OFF      0xB23668ULL     // 入口+4：第二条 STP（VA 0x100B23668）
#define XRC_BRK_RPF_DRAW_REPLAY_OFF    0ULL
#define XRC_BRK_RPF_ARCTICK_SITE_OFF   0xAFFC14ULL     // 入口+4（VA 0x100AFFC14）
#define XRC_BRK_RPF_ARCTICK_REPLAY_OFF 0ULL
#define XRC_BRK_RPF_ARCPASS_SITE_OFF   0xAFFA94ULL     // 入口+4（VA 0x100AFFA94）
#define XRC_BRK_RPF_ARCPASS_REPLAY_OFF 0ULL
// ---- 弧分段「藏」的两处 ----
// 症状：弧带下端被整齐切掉 = 弧的**开头**不显示（起手点不可见）。
// 两处唯一的藏动作都是 `MOV W1,#0` 紧接 `setVisible(child,0)`（slot 42 = vtable+0x150）：
//   A 0x100AFFB60 in sub_100AFFA90（头过线）；B 0x100AFFE80 in sub_100AFFC10（弧 tick，
//   它跳到共享尾声 0x100B00048 才 BLR）。打在 `MOV W1,#0` 上而不是那条 BLR 上，是因为
//   ① 两处共用同一条编码 `52800001`，断言简单；② handler 只需改一个寄存器，不碰 PC、
//   不调游戏函数、不需要跳板（B 的 ±128MB 也够不到我们的 __TEXT 空页）。
// 行为：handler 平时**一个字都不改**（⇒ 与未打桩逐字节同行为），仅在插件置位的
//   「回跳窗口」内把 W1 改成 1 ⇒ 引擎自己把分段显回来。窗口 = 回跳起 → 播放头涨回旧水位 P。
#define XRC_BRK_ARC_HIDE_A_SITE_OFF    0xAFFB60ULL     // MOV W1,#0（VA 0x100AFFB60）
#define XRC_BRK_ARC_HIDE_A_REPLAY_OFF  0ULL
#define XRC_BRK_ARC_HIDE_B_SITE_OFF    0xAFFE80ULL     // MOV W1,#0（VA 0x100AFFE80）
#define XRC_BRK_ARC_HIDE_B_REPLAY_OFF  0ULL
// ⚠ 站点值一律是**文件偏移**，不是完整 VA：分发处是 `pc == mb + site_off`（XRCHook.m s_sigtrap）。
//   写成 VA 的后果：分发永不匹配 ⇒ BRK 落进无处理器路径 ⇒ 开歌 SIGTRAP 秒崩；自检读越界 ⇒ brk_sites 少 3。
// 自动演奏站点处理器引用的 7.0 布局常量（出处见上节）。
#define XRC_NOTE_TIME_END_OFF       28            // note+0x1C = 窗口时刻（判定 pass 两处 CMP 的依据）
#define XRC_NOTE_ACTIVE_OFF         84            // note+0x54 = active 字节（与 Android/6.x 同偏移）
#define XRC_NOTE_LNSTATE_OFF        100           // note+0x64 = longTouchState 首字节（6.x 0x5C 漂移 +8）
#define XRC_LN_VOID_OFF             164           // note+0xA4 = 弧 isVoid（弧 vtable[11]=sub_100187C78 读的字段；
                                                  // 6.x 0x9C 漂移 +8，与 Android 7.0 一致）
#define XRC_LN_VPTR_ARC             0x149C020ULL  // _ZTV12LogicArcNote + 16（对象 vptr）
#define XRC_LN_VPTR_HOLD            0x14B7980ULL  // _ZTV13LogicHoldNote + 16
#define XRC_AP_NOTE_WIN_CONT_OFF    (0x91DD44ULL) // 窗口强判后的原版汇合点（W19=0;W26=1 → 弧态更新+子扫描）
#define XRC_AP_ARCTAP_WIN_CONT_OFF  (0x91DD44ULL) // 弧子音符强判后同一汇合点（对齐 外部参考实现：其 success 走 0x100872180
                                                  // → 7.0 0x91DD20 的等价落点；跳 0x91DF5C 会丢弧"被触"视觉）
// ---- 引擎自身的"被触"标记函数 ----
#define XRC_OFF_FN_MARK_HOLD   (0x8E4864ULL)   // 长条被触：事件派发(sub_100B69644 ev=2, note 时刻) + note+0x64 字 = 0x0101
                                               // （= 引擎真触路径用的函数；x1 由 hold vtable 槽直接引用）
#define XRC_OFF_FN_ARC_SPRITE  (0x187618ULL)   // 弧"子对象/sprite"getter：sub_100187618(note)（8B，LDR+RET）
                                               // 引擎在弧清态/置触处均用它取目标后写 +0x10/+0x12/+0x14
// 弧/长条"被接住"语义。出处 = 外部参考实现 handler 转储（离线样本）+ 两侧 vtable 槽位对齐
// （hold/arc vtable[12] = sub_1008E4864 / sub_100187620；外部参考实现 0x10084A2D8 / 0x1001264A4）。
#define XRC_OFF_FN_ARC_CONSUME (0x187620ULL)   // 弧被触消费（弧 vtable[12]）：按弧上最近段时刻算 sprite+0x14
                                               // 到期值、置 note+0x64 字、派发事件(ev=0)、调弧对象 vtable 刷新；
                                               // 第 2 参 = 0x40B 事件结构（仅 +0x34 被读；-1 = 无手指哨兵）
#define XRC_NOTE_HOLD_POS_OFF  (48)            // note+0x30 = hold 位置/时刻对（slot3 重置方法写它；
                                               // 外部参考实现 hold 分支每帧把低 32 位置 0）
#define XRC_NOTE_HELD_OFF      (168)           // note+0xA8 bit0 = "被接住/保持中"（sub_10091E58C 与尾部时刻
                                               // 联合读取；外部参考实现 hold 分支每帧置 1——不写则长条显示为未接住）

// ---------------- note 组判定总闸（练习暂停用）----------------
// 出处：note 组每帧函数 sub_10091BC44 反汇编（.idamcp/_c70_10091BC44.c L183/L209）：
//   L183 入场/位置刷新 sub_10091C47C **无门控**（拖动预览依赖它）；
//   L209 if(!(ng+312&1)) { if(!(ng+313&1)) sub_10091D2F4; sub_10091D9A0; }
//        ⇒ 312 bit0 = 「判定+自动漏扫」块总闸；313 = "歌曲结束"闩（引擎在越过曲长时自置）。
//   312 全二进制唯一写者 = note 组初始化（sub_10091AE78：`*(_WORD*)(a1+312)=0`）⇒
//   无运行期写者与我们竞争；实现仍按「保存-恢复 + 每帧断言 + 防场景重建」处理。
#define XRC_NG_JUDGE_GATE_OFF   312

// ---------------- 弧「判定面残点」（height_indicator）----------------
// 症状：回跳重放后，弧与判定面接触处残留一个点（矮光柱快照）。
// 机制（出处 research/notes/ios-7.0.255-04-arc-indicator-seek.md，2026-10-02 静态定案）：
//   指示器 = 弧**首段** ArcSegment 上的 height_indicator 精灵（每弧最多一个，AFDD64 的
//   `if (a6)` i==0 门）；形状 = 子精灵顶点区 4×12B 的快照，唯一写者 sub_100AFE624
//   （创建尾 / 头段摆位）；可见性随父段、自身无 setVisible 路径 ⇒ 「快照几何 + 单向棘轮」
//   ⇒ 回跳后没有任何路径把旧快照翻篇 = 残点。
// 清理（方案 1，幂等）：4 组顶点清零 = 回到引擎 ctor bzero 的「从未写过」态；凡「该显示」
//   的时刻（创建 / 头段摆位）引擎自己会重写 ⇒ 自愈。不写可见性位、不碰任何 seg 字段。
#define XRC_ARC_SEG_CONTAINER_OFF   0x278      // RenderArcNote+0x278 = 段容器节点（vt[68] 返回子表）
#define XRC_ARC_SEG_INDICATOR_OFF   0x290      // ArcSegment+0x290 = height_indicator 精灵（AFDD64 @0x100AFE534）
#define XRC_ARC_IND_QUAD0_OFF       0x39C      // 指示器精灵顶点组 ×4（AFE624 写点；12B/组）
#define XRC_ARC_IND_QUAD1_OFF       0x3B4
#define XRC_ARC_IND_QUAD2_OFF       0x3CC
#define XRC_ARC_IND_QUAD3_OFF       0x3E4

// ---------------- OnlineManager 探针 / applog 强发（XRCOMLog）----------------
// 出处: 真机内存转储 + 静态复核。
//   vtable: 0x10149C100 起（[0]=offset-to-top=0、[8]=typeinfo、0x10149C110 起为槽 0）；
//           对象的 vptr 指向**地址点** 0x10149C110（= _ZTV + 0x10，与 lambda 那套同构）。
//   typeinfo 名实测 "13OnlineManager"；槽 72 = sub_100623AEC = applog 发送。
//   单例定位：真机 dump 里 vptr 值全进程**唯一命中**（对象在堆上、每次启动地址变，
//             所以运行时按值扫描，不写死地址）。
//   载荷: +0x128/+0x130 = begin/end —— sub_100623AEC 在 0x100625438 处
//         `LDP X19,X21,[X8,#0x128]` 实证（X8 = 入口 X0）。
//         注意：**该区间只在调用期间有效**（空闲态 dump 里是非指针垃圾），
//         所以空闲期转储看不到载荷，只有入口桩能抓。
//   累加器候选: dump 实测 +0xf0=250 / +0xf8,+0x100,+0x108 = ptr,ptr,30，
//         (end-begin)/24 = 24 → 疑似 std::vector<std::string>（元素 24B），
//         capacity 30 ≥ size 24。语义待 XRCOMLog 探针实测确认。
#define XRC_OM_VTABLE_OFF           (0x149C110ULL)  // vtable 地址点（vptr 值）
#define XRC_OM_APPLOG_SLOT          (72)            // applog 发送（虚槽）
#define XRC_OM_OFF_ACC_COUNT        (0xf0)          // 疑似累计计数
#define XRC_OM_OFF_VEC_BEGIN        (0xf8)          // 疑似 vector<string> begin
#define XRC_OM_OFF_VEC_END          (0x100)         // 同上 end
#define XRC_OM_OFF_VEC_CAP          (0x108)         // 同上 capacity
#define XRC_OM_OFF_USER_ID          (0x140)         // 账号 user_id（字段语义已核对）
#define XRC_OM_OFF_FIFTY            (0x148)         // dump 实测 50（= sub_10000A7F0 的 0x32）
