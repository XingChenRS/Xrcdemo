// © 雾月星辰 & MLXC · github@XingChenRS
// XRCHook.m — BRK 桩实现：SIGTRAP 分发 + 重放跳板。
//
// 注入器把 site 处的一条指令写成 `BRK #0`（D4200000）。执行到那里触发 SIGTRAP，
// 本模块的处理器按 PC 查表命中后，把 ucontext 的 PC 改成 replay 跳板地址——跳板
// 内容是「原始指令 + B 回 site+4」，于是执行流无感续上。
//
// 处理器内**只允许 async-signal-safe 操作**：查表 + 原子计数 + 改 PC。
// 任何日志/Objective-C 一律留给主线程定时器读取统计后落盘。
//
// 安全要点：查不到自己的桩点时**必须 chain 给前一个 SIGTRAP 处理器**，否则会
// 吞掉 Swift 运行时的 BRK #1 陷阱与 Crashlytics 的崩溃捕获。
// ucontext.h 在 Darwin 被标为 deprecated，需先定义 _XOPEN_SOURCE 才暴露
// ucontext_t / mcontext_t；取完立即 undef，避免影响后续 Foundation / Mach 头。
//
// ---- 文件地图（编译轴隔离说明）----
//   · 核心（恒编译）：槽表 {site,replay,handler,hits} + install/register + SIGTRAP
//     分发（PC 覆写协议）+ 未注册桩位还原自愈 + 静态补丁自检。
//   · 功能处理器（恒编译）：cb 验证链 / 锁态 / 链门 / autoplay / 弧分段「不藏」。
//   · 开发构建专属（XRC_DEBUG_BUILD）：applog 明文/密文捕获（2×1MB 缓冲）、弧/绘制
//     观测环（arcr）、观测桩处理器、观测桩轻量；发布构建下各处理器为空操作桩。
//     隔离采用编译轴：物理拆分需跨文件重组 static，风险高、收益低。
#define _XOPEN_SOURCE 700
#include <ucontext.h>
#undef _XOPEN_SOURCE

#import <Foundation/Foundation.h>

#include <signal.h>
#include <stdatomic.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>              // mprotect：未注册桩位自愈要短暂改代码页属性
#include <libkern/OSCacheControl.h> // sys_icache_invalidate：写完指令必须刷 i-cache
#include <mach/mach_time.h>
#include <mach/arm/thread_status.h>
#include <mach-o/dyld.h>

#include "XRCHook.h"
#include "XRCProfile.h"
#include "XRCJudge.h"   // autoplay 站点处理器复用 xrc_judge_autoplay/_pure
#import "XRCLog.h"

#if XRC_HAS_BRK_HOOK

typedef struct {
    _Atomic(uint64_t) site;
    _Atomic(uint64_t) replay;
    void (*handler)(void *);
    _Atomic(uint32_t) hits;
    _Atomic(uint64_t) last_us;   // mach_absolute_time 折算微秒
    const char *name;
} xrc_brk_slot_t;

static xrc_brk_slot_t s_slots[XRC_BRK_MAX_SLOTS];
static _Atomic(int)   s_count = 0;
static struct sigaction s_prev;
static bool s_installed = false;
// 主程序基址（分发器兜底路径用，PC 相关、不能现算）。
// 注意：必须用 xrc_image_base()（按名字扫 dyld 找 "Arc-mobile"）——
// _dyld_get_image_header(0) 在越狱环境（Dopamine）下不是主程序，用它注册会全部
// 落到错误地址 → 真正的 BRK 命中反而链默认 → 崩。
extern uint64_t xrc_image_base(void);
static _Atomic(uint64_t) s_main_base = 0;
// mach_timebase 在安装时算好，处理器内不做非安全调用
static uint64_t s_tb_num = 1, s_tb_den = 1;

static inline uint64_t s_now_us(void) {
    uint64_t t = mach_absolute_time();
    // ns = t * numer / denom；先乘后除保精度。timebase 不可用时退化返回原始 ticks。
    return s_tb_den ? (t * s_tb_num) / s_tb_den : t;
}

#if XRC_DEBUG_BUILD

// ---------------- applog 明文捕获（开发构建）----------------
// 缓冲放在 dylib 自己的 BSS，不占栈；处理器内只 memcpy + 原子写。
static uint8_t        s_cap[XRC_BRK_CAP_MAX];
static _Atomic(size_t)   s_cap_len = 0;
static _Atomic(uint32_t) s_cap_seq = 0;
static _Atomic(bool)     s_cap_on  = false;
static uint32_t          s_cap_taken = 0;

void xrc_brk_capture_enable(bool on) { atomic_store(&s_cap_on, on); }
uint32_t xrc_brk_capture_seq(void)   { return atomic_load(&s_cap_seq); }

size_t xrc_brk_capture_take(void *buf, size_t cap) {
    uint32_t seq = atomic_load(&s_cap_seq);
    if (seq == s_cap_taken) return 0;
    s_cap_taken = seq;
    size_t n = atomic_load(&s_cap_len);
    if (!n) return 0;
    if (n > cap) n = cap;
    __builtin_memcpy(buf, s_cap, n);
    return n;
}

// applog 桩点的处理器：入口 X0 = OnlineManager，+0x128/+0x130 = 明文 begin/end。
// 必须在加密之前拿到——入口即满足。
static void s_applog_capture(void *vctx) {
    if (!atomic_load(&s_cap_on)) return;
    ucontext_t *uc = (ucontext_t *)vctx;
    if (!uc || !uc->uc_mcontext) return;
    uint64_t self = uc->uc_mcontext->__ss.__x[0];
    // 轻量健全性检查：指针必须在用户空间且对齐，避免处理器内二次缺页
    if (self < 0x100000000ULL || (self & 7)) return;
    uint64_t begin = *(volatile uint64_t *)(self + XRC_APPLOG_BUF_BEGIN_OFF);
    uint64_t end   = *(volatile uint64_t *)(self + XRC_APPLOG_BUF_END_OFF);
    if (!begin || end <= begin || (begin & 7) || (end & 7)) { return; }
    uint64_t n = end - begin;
    if (n > XRC_BRK_CAP_MAX) n = XRC_BRK_CAP_MAX;
    __builtin_memcpy(s_cap, (const void *)begin, (size_t)n);
    atomic_store(&s_cap_len, (size_t)n);
    atomic_fetch_add(&s_cap_seq, 1);
}

// ---------------- log_blob 密文捕获 ----------------
// 第二个桩点（载荷加密出口）：**整帧捕获**（从 SP 起 0x700 字节）离线再搜。
// 独立缓冲，免得和入口那份明文互相覆盖。
static uint8_t        s_cap2[XRC_BRK_CAP_MAX];
static _Atomic(size_t)   s_cap2_len = 0;
static _Atomic(uint32_t) s_cap2_seq = 0;
static _Atomic(uint64_t) s_cap2_sp  = 0;
static uint32_t          s_cap2_taken = 0;

uint32_t xrc_brk_blob_seq(void) { return atomic_load(&s_cap2_seq); }
uint64_t xrc_brk_blob_sp(void)  { return atomic_load(&s_cap2_sp); }

size_t xrc_brk_blob_take(void *buf, size_t cap) {
    uint32_t seq = atomic_load(&s_cap2_seq);
    if (seq == s_cap2_taken) return 0;
    s_cap2_taken = seq;
    size_t n = atomic_load(&s_cap2_len);
    if (!n) return 0;
    if (n > cap) n = cap;
    __builtin_memcpy(buf, s_cap2, n);
    return n;
}

static void s_applog_blob_capture(void *vctx) {
    if (!atomic_load(&s_cap_on)) return;
    ucontext_t *uc = (ucontext_t *)vctx;
    if (!uc || !uc->uc_mcontext) return;
    uint64_t sp = (uint64_t)__darwin_arm_thread_state64_get_sp(uc->uc_mcontext->__ss);
    if (sp < 0x100000000ULL || (sp & 7)) return;
    // 直接整帧捕获（从 SP 起 0x700 字节），不做偏移假设：
    //   · 字面量 "log_blob" 在帧内可检索
    //   · 密文是高熵段，熵值/肉眼都能挑出来
    // 帧大小 0x700 覆盖该函数 SUB SP,SP,#0x5A0 + 保存区。
    uint64_t n = XRC_APPLOG_BLOB_FRAME_LEN;
    __builtin_memcpy(s_cap2, (const void *)sp, (size_t)n);
    atomic_store(&s_cap2_len, (size_t)n);
    atomic_store(&s_cap2_sp, sp);
    atomic_fetch_add(&s_cap2_seq, 1);
}

#else
// 发布构建：以下捕获接口为空操作（2×1MB 缓冲不占 BSS）。
void     xrc_brk_capture_enable(bool on) { (void)on; }
uint32_t xrc_brk_capture_seq(void) { return 0; }
size_t   xrc_brk_capture_take(void *buf, size_t cap) { (void)buf; (void)cap; return 0; }
uint32_t xrc_brk_blob_seq(void) { return 0; }
uint64_t xrc_brk_blob_sp(void)  { return 0; }
size_t   xrc_brk_blob_take(void *buf, size_t cap) { (void)buf; (void)cap; return 0; }
static void s_applog_capture(void *vctx) { (void)vctx; }
static void s_applog_blob_capture(void *vctx) { (void)vctx; }
#endif

// ---------------- 开关组：拥有链 + 锁态/链门（功能账 §1）----------------
// 直返桩通用出口：写 x0 = val、PC = LR（函数体不执行、栈帧未建立，直返安全），并计数。
static _Atomic(uint32_t) s_lock_hits = 0;
uint32_t xrc_brk_lock_hits(void) { return atomic_load(&s_lock_hits); }
static void s_ret(uint64_t val, void *vctx) {
    ucontext_t *uc = (ucontext_t *)vctx;
    if (!uc || !uc->uc_mcontext) return;
    __typeof__(uc->uc_mcontext->__ss) *ss = &uc->uc_mcontext->__ss;
    ss->__x[0] = val;
    __darwin_arm_thread_state64_set_pc_fptr(*ss,
        (void *)__darwin_arm_thread_state64_get_lr(*ss));
    atomic_fetch_add(&s_lock_hits, 1);
}

// 六个独立开关：
//   own  → unlock_l1/l2/l3（拥有链；覆盖"服务器未授予、本地已有内容"的离线场景）
//   fv   → lock_fv（FV 五曲 fast path → 五难度全解）
//   do   → lock_do（DO/konzetsu 分支 → 同上）
//   gate → fv_gate + pack_open + shutter_done（终章链门/包状态机/进歌在线检查；gate 族放行档）
//   all  → lock_all/play_gate/cond_unlock_*（全条件放行：锁态/可玩性/条件判定源头恒真；
//          另与 do 联动旁路锁绘族（含 arghena 专属曲绘）——见 s_jacket_branch）
//   dl   → dl_play（下载"需动作"谓词恒 0：开局不转"Download song?"弹窗；文件存在性开局链亲验）
// 另有 chain_prog（守崩桩）**不设开关、恒生效**，见下。
static _Atomic(bool) s_unlock_own = false;
static _Atomic(bool) s_unlock_fv  = false;
static _Atomic(bool) s_unlock_do  = false;
static _Atomic(bool) s_gate_open  = false;
static _Atomic(bool) s_unlock_all = false;
static _Atomic(bool) s_dl_ready   = false;

void xrc_brk_set_unlock_own(bool on) { atomic_store(&s_unlock_own, on); }
void xrc_brk_set_unlock_fv(bool on)  { atomic_store(&s_unlock_fv, on); }
void xrc_brk_set_unlock_do(bool on)  { atomic_store(&s_unlock_do, on); }
void xrc_brk_set_gate_open(bool on)  { atomic_store(&s_gate_open, on); }
void xrc_brk_set_unlock_all(bool on) { atomic_store(&s_unlock_all, on); }
void xrc_brk_set_dl_ready(bool on)   { atomic_store(&s_dl_ready, on); }
bool xrc_brk_unlock_own(void) { return atomic_load(&s_unlock_own); }
bool xrc_brk_unlock_fv(void)  { return atomic_load(&s_unlock_fv); }
bool xrc_brk_unlock_do(void)  { return atomic_load(&s_unlock_do); }
bool xrc_brk_gate_open(void)  { return atomic_load(&s_gate_open); }
bool xrc_brk_unlock_all(void) { return atomic_load(&s_unlock_all); }
bool xrc_brk_dl_ready(void)   { return atomic_load(&s_dl_ready); }

static void s_unlock_force_true(void *vctx) {     // unlock_l1/l2/l3 共用
    if (!atomic_load(&s_unlock_own)) return;
    s_ret(1, vctx);
}

// ---------------- cb 验证链开关（功能账 §3）----------------
static _Atomic(bool) s_cb_bypass = false;

void xrc_brk_set_cb_bypass(bool on) { atomic_store(&s_cb_bypass, on); }
bool xrc_brk_cb_bypass(void)        { return atomic_load(&s_cb_bypass); }

// 就绪位 getter 桩：恒真直返
static void s_cb_ready_true(void *vctx) {
    if (!atomic_load(&s_cb_bypass)) return;
    ucontext_t *uc = (ucontext_t *)vctx;
    if (!uc || !uc->uc_mcontext) return;
    __typeof__(uc->uc_mcontext->__ss) *ss = &uc->uc_mcontext->__ss;
    ss->__x[0] = 1;
    __darwin_arm_thread_state64_set_pc_fptr(*ss,
        (void *)__darwin_arm_thread_state64_get_lr(*ss));
}

// ---- cb 自由化 ----
// ① ② 共用：B.NE（逐文件 sha256 / 三清单 HMAC）——开=恒"相等"（不跳失败路径）；关=按 NZCV 复现原分支。
// 不能走重放跳板：B.NE 是 PC 相对指令，在跳板处执行会算错目标地址。
static void s_cb_cond_skip(void *vctx) {
    ucontext_t *uc = (ucontext_t *)vctx;
    if (!uc || !uc->uc_mcontext) return;
    __typeof__(uc->uc_mcontext->__ss) *ss = &uc->uc_mcontext->__ss;
    uint64_t pc = (uint64_t)__darwin_arm_thread_state64_get_pc(*ss);
    if (atomic_load(&s_cb_bypass)) {                       // 开：视为相等，继续循环
        __darwin_arm_thread_state64_set_pc_fptr(*ss, (void *)(pc + 4));
        return;
    }
    uint32_t cpsr = (uint32_t)ss->__cpsr;                  // 关：复现原 B.NE
    bool z = ((cpsr >> 30) & 1u) != 0;                     // Z=1 → 相等 → 不跳
    uint64_t mb = atomic_load(&s_main_base);
    uint64_t target = 0;
    if (mb) {
        if (pc == mb + XRC_BRK_CB_FILEHASH_SITE_OFF)
            target = mb + XRC_BRK_CB_FILEHASH_TARGET_OFF;
        else if (pc == mb + XRC_BRK_CB_LISTHASH_SITE_OFF)
            target = mb + XRC_BRK_CB_LISTHASH_TARGET_OFF;
    }
    __darwin_arm_thread_state64_set_pc_fptr(*ss, (void *)((!z && target) ? target : pc + 4));
}

// ③ 清树入口（删 cb/meta_old.cb / cb/meta.cb / cb/meta_new.cb + rm -r cb/active 整树 + 清内存态）：
//    开=直返（meta 文件、内容树与内存态原样保留）；关=照常执行（重放跳板跑原序言）。
static void s_cb_wipe_guard(void *vctx) {
    if (!atomic_load(&s_cb_bypass)) return;
    s_ret(0, vctx);
}

// ④ 内容更新强制门（sub_1001963D8 = OnlineManager::tryHandleContentBundleOldError）：
//    服务端错误码 code 11（内容包过旧）时弹「A new content update is required. Returning to
//    title screen.」并换场回标题（tag 162411）—— 68 个 HTTP 端点响应处理器共用此门。
//    ⚠ 2026-10-12 晚起改为**只记不跳**：x0=0 直返依赖调用方对返回值的合同解释
//    （"已在标题、无事可做"），其真实触发面本轮无法实测；同批 cb_fetch 的直返已被实测证伪
//    会打断启动链（见 ⑤b 实测记录）⇒ 本门一并退化为观测点，重放原逻辑（等价于未注入）。
static void s_cb_gate_observe(void *vctx) {
    if (!atomic_load(&s_cb_bypass)) return;
    xrc_logi(XRCLC_BRK, @"cb_gate hit (cb_bypass=on) → replay（只记不跳）");
    (void)vctx;
}

// ⑤ 内容包更新指令处理器（sub_100815498，+0xA0 处引响应字段 orderedResults）：开 = 整体跳过
//    （忽略服务器的内容包更新指令，设备内容即真值）；关 = 重放原序言。
//    与 cb_gate 互补：前者管"远端更新"，后者管"错误呈现"。
//    ⚠ 函数身份证据=[高]（字符串引用+前作笔记），内部动作未逐行核实=[中] ⇒ 桩只做入口直返、
//      不做内部手术；本函数为回调注册形态（全二进制无直接调用者，仅数据引用）。
//    s_cb_skip_void 为 void 函数整体跳过桩（错码分发 cb_dispatch 与本站共用）：x0 不动、
//    直接按 LR 返回（函数体不执行、栈帧未建立，直返安全）。
static void s_cb_skip_void(void *vctx) {
    if (!atomic_load(&s_cb_bypass)) return;
    ucontext_t *uc = (ucontext_t *)vctx;
    if (!uc || !uc->uc_mcontext) return;
    __typeof__(uc->uc_mcontext->__ss) *ss = &uc->uc_mcontext->__ss;
    __darwin_arm_thread_state64_set_pc_fptr(*ss,
        (void *)__darwin_arm_thread_state64_get_lr(*ss));
}

// XRCNet 导出（观测日志用；两模式均存在）
extern bool xrc_net_enabled(void);

// ⑤b 内容包响应处理（sub_100815498，引 "orderedResults"）：**只记不跳**。
//     2026-10-12 晚实测证伪原"入口直返"设计：发布构建（联网阻断 → content_bundle 请求必 -1022）
//     下 cb 自由化 on 的启动全部永挂"进菜单之前"（停在 -1022 之后，无 compose/aggregate、
//     无 unlock/me；cb 关则同点 1s 内续走；对照 c0fa5c6 五点集同机同内容全程正常）——
//     直返把失败路径的收尾一并跳掉，启动链永等"内容包检查完成"。该函数内部动作未逐行核实，
//     跳过与代执行都无法保证调用方合同 ⇒ 桩退化为观测点：重放原逻辑（等价于未注入）＋ info 留痕。
static void s_cb_fetch_observe(void *vctx) {
    if (!atomic_load(&s_cb_bypass)) return;
    xrc_logi(XRCLC_BRK, @"cb_fetch hit (cb_bypass=on net=%d) → replay（只记不跳，防启动链中断）",
             (int)xrc_net_enabled());
    (void)vctx;
}

// ---------------- 曲目锁态覆盖 ----------------
// 锁状态函数 `sub_100919E5C` 内的两个专属子分支（各自唯一调用方 = 锁态函数自身）：
//   · 0x100991508 = FV 五曲 fast path（硬编码集合经 song+0x257 开关；id 改名后该路不再命中）；
//   · 0x100AAE50C = DO(konzetsu) 分支（读存档 insightPrechallengeRevealIndex；未推进时只放行 FTR/INS）。
// 二者都返回"五字节打包"的按难度锁态（b0..b4 = PST/PRS/FTR/BYD/INS）。
// ⚠ 极性（2026-10-16 修正，四组指令级锚点见 XRCProfile.h 同名块）：**1 = 锁、0 = 可玩**。
//   早前"全 1 = 全解"是把 919E5C「未声明难度→0x0101010101 早退」误读为"全解锁"所致；
//   直返 0x0101010101 实为"五难度全锁死"（真机现象：锁标曲绘 + 标题"???"）。
//   现直返 (0,0) = 普通歌曲的原生"干净"返回值。b4(=bit32) 同时是锁绘触发器：0 时不再触发锁绘，
//   旧"专属曲绘与挂锁不可兼得"的取舍随之作废。
// 锁态直返 (0,0)：x1 是原生"额外锁定原因"第二返回值——门控放行分支 @0x991530/34
// （MOV X9,#0；MOV X1,#0）同清两值（2026-10-16 复核）。注意 x1 在入口是难度实参，
// 只清 x0 会把"难度序数"当锁定原因漏给调用方。
static void s_lock_clear(void *vctx) {
    ucontext_t *uc = (ucontext_t *)vctx;
    if (!uc || !uc->uc_mcontext) return;
    uc->uc_mcontext->__ss.__x[1] = 0;
    s_ret(0, vctx);
}
static void s_lock_fv(void *vctx) {
    if (!atomic_load(&s_unlock_fv)) return;
    s_lock_clear(vctx);
}
static void s_lock_do(void *vctx) {
    if (!atomic_load(&s_unlock_do)) return;
    s_lock_clear(vctx);
}

// 终章链门覆盖（开关 gateOpen）：
// `sub_10099156C` 的返回语义经两处消费点钉死——
//   ① `sub_100919874`（可玩性谓词）直返它的值，消费点 sub_1008660F8 的 `CBNZ W0`（选中该难度）
//      把非零当"可用"；
//   ② `sub_100991508` 里 `if (56C & 1) → 返回全 0 字节（全解锁）`——与锁态字节方向相反
//      （门控 1 = 放行；锁态 0 = 解锁），2026-10-16 极性修正时一并订正。
//   ⇒ **1 = 放行、0 = 锁**（返 0 会把全曲钉死）；入口直返 **1**。
static void s_finale_gate_open(void *vctx) {
    if (!atomic_load(&s_gate_open)) return;
    s_ret(1, vctx);
}

// 包状态机覆盖（开关 gateOpen，面板处已 ||unlockAll）：sub_100CD0108 恒返 3（= 已拥有）。
// 语义：包状态 1 = 不可进（FV 包弹「Complete 'Black Fate' and see VS-8…」/ 封面 pack_inaccessible /
//   歌列表跳过），2/3 = 可进（3 = 已拥有）。站点与证据见 XRCProfile.h 同名块（2026-10-16 专项）。
static void s_pack_open(void *vctx) {
    if (!atomic_load(&s_gate_open)) return;
    s_ret(3, vctx);
}

// 进歌在线检查等待（开关 gateOpen）：`scene+0x348`「在线检查完成」位的**唯一清零点**
// 0x100976F68（`strb wzr,[x19,#0x348]`，2026-10-16 登录门专项核验）。跳过该清 0 ⇒
// 完成位保持建厂值 1 ⇒ TransitionShutter 的逐帧等待（7.0s 超时）与
// 「Network Error / Retry / Continue Offline」弹窗结构性不可达（等效自动 Continue Offline）。
// 关：重放原存储（slot 0x1468168），逐字节同原行为。
static void s_shutter_done(void *vctx) {
    if (!atomic_load(&s_gate_open)) return;
    ucontext_t *uc = (ucontext_t *)vctx;
    if (!uc || !uc->uc_mcontext) return;
    __typeof__(uc->uc_mcontext->__ss) *ss = &uc->uc_mcontext->__ss;
    __darwin_arm_thread_state64_set_pc_fptr(*ss,
        (void *)((uint64_t)__darwin_arm_thread_state64_get_pc(*ss) + 4));
}

// 链进度覆盖：`sub_10098FB1C` 是 7.0 新增「链」系统的查表点——硬编码曲名（InitFunc_194 表）
//   拼 `"<名>|<难度>"` 去 mgr+0x28 容器查节点对象，而对象按 songlist 的 **id** 注册 → id 改名或
//   set 挪位即查不到 → 该函数不判空直接读 [NULL+0x28]（实测崩溃链 CA118C → 18A3A8 → 98F5BC → 98FB1C）。
//   直返 100（其自身"无场景对象"路径的合法进度值）→ 不查表（改名/挪包安全），
//   并让链门 v19=(98FB1C==0) 恒为 0。**不设开关**：资源改名的守崩桩，必须常开。
static void s_chain_prog_neutral(void *vctx) {
    s_ret(100, vctx);
}


// ---------------- 自动演奏站点处理器（外部参考实现对齐；功能账 §5.2）----------------
// 全部受 xrc_judge_autoplay() 开关：关 → 处理器直接返回（不改 PC）→ 分发器送回重放跳板，
// 行为与未注入完全一致。命中时寄存器即现场（ucontext），按站点约定读 X20/X27/X28/X2 等。
// 站点语义与 外部参考实现实件的逐条对照见 XRCProfile.h 的出处注释。
static inline uint64_t s_ap_ld64(uint64_t a) { return *(volatile uint64_t *)a; }
static inline uint32_t s_ap_ld32(uint64_t a) { return *(volatile uint32_t *)a; }
static inline uint8_t  s_ap_ld8 (uint64_t a) { return *(volatile uint8_t  *)a; }
static inline bool     s_ap_ptr_ok(uint64_t p) { return p >= 0x100000000ULL && (p & 7u) == 0; }

// 自动演奏内部计数（mark = 逐帧标志写次数，disp = 引擎标记函数实际调用次数）。
static _Atomic(uint32_t) s_ap_stat_mark = 0, s_ap_stat_dispatch = 0;
static _Atomic(uint32_t) s_ap_stat_win_note = 0, s_ap_stat_win_tap = 0;
static _Atomic(uint32_t) s_ap_stat_tick1 = 0, s_ap_stat_tick2 = 0;

// 谱面时刻（与判定核/判定 pass 同一公式：clock = ng+0x30）。
static int32_t s_ap_chart_now(uint64_t ng) {
    if (!s_ap_ptr_ok(ng)) return -1;
    uint64_t clk = s_ap_ld64(ng + XRC_CLOCK_IN_NOTEGROUP_OFF);
    if (!s_ap_ptr_ok(clk)) return -1;
    if (s_ap_ld8(clk + XRC_CLK_FLAG45_OFF) == 1)
        return (int32_t)((int32_t)s_ap_ld32(clk + XRC_CLK_ALT_START_OFF) -
                         (int32_t)s_ap_ld32(clk + XRC_CLK_BASE_OFF));
    int32_t cur  = (int32_t)s_ap_ld32(clk + XRC_CLK_CUR_OFF);
    int32_t base = (int32_t)s_ap_ld32(clk + XRC_CLK_BASE_OFF);
    return cur - base + (cur > 0 ? 0 : XRC_CLK_NEG_LEAD_MS);
}

// 长条/弧"被触"标记（与 外部参考实现 mark_long_note_touched 逐条对齐；出处见 XRCProfile.h）。
// 设计要点：逐帧标志 + 每音符一次调用（每帧重调引擎标记函数会致事件派发 ~840/s、
//       音效/特效积压——真机日志定量）。两处关键语义：
//         · hold 须写 note+0x30=0 / note+0xA8=1（后者 = "被接住"，引擎 sub_10091E58C 联合尾部时刻读
//           → 不写则长条/弧显示为"未接住、直接穿过判定线"）；
//         · arc 走弧消费 sub_100187620（按最近段时刻算 sprite 到期、派发事件 0、调弧对象 vtable 刷新），
//           不能用 hold 的标记函数。
// 语义：
//   守卫：active==1；弧须非 void；now >= 音符头部；now <= 尾部 +100ms；hold 还须 now >= 头部 +16ms；
//   每音符一次（门闩）：arc → sub_100187620(note, {…,+0x34=-1}, now)；hold → sub_1008E4864(note)
//                        （之后补 note+0x30 低字=0、note+0xA8=1）；
//   逐帧：note+0x64 字 = 0x0101（维持引擎 Pure tick 路径；弧另写 sprite +0x10/+0x12/+0x14）。
static _Atomic(uint64_t) s_ap_latch_ptr[256];
static _Atomic(uint32_t) s_ap_latch_t[256];

static bool s_ap_dispatch_once(uint64_t note, int32_t t0) {
    uint32_t h = (uint32_t)((note >> 4) ^ (uint64_t)(uint32_t)t0) & 255u;
    if (atomic_load(&s_ap_latch_ptr[h]) == note && atomic_load(&s_ap_latch_t[h]) == (uint32_t)t0)
        return false;
    atomic_store(&s_ap_latch_ptr[h], note);
    atomic_store(&s_ap_latch_t[h], (uint32_t)t0);
    atomic_fetch_add(&s_ap_stat_dispatch, 1);
    return true;
}

// 清「每音符一次」闩 —— **回跳后必须清**。
// 守卫的是"一次性引擎调用"（弧 → sub_100187620 消费；长条 → sub_1008E4864 标记"被接住"），
// 也就是建立"被触 / 被接住"状态的那一笔。闩按 (note,t0) 记账，无复位时：
// 回跳后播放头再次经过同一批音符，闩还记着"已派发" ⇒ 那一笔不再跑 ⇒
// 弧的"被触"状态建立不起来 ⇒ 重放后 **弧超界 / 天地双押连线消失**。
// 判别：① 手打不出现（手打不走 autoplay，闩不参与）；② 第一遍完全正常（闩初始为空）；
// ③ 只有 autoplay + 重播才坏。
// 场景切换也要清：新歌里 note 指针与 t0 可能与旧歌重合（分配器复用）⇒ 误闩，autoplay 直接哑掉。
void xrc_ap_latch_reset(void) {
    for (int i = 0; i < 256; i++) {
        atomic_store(&s_ap_latch_ptr[i], (uint64_t)0);
        atomic_store(&s_ap_latch_t[i], 0u);
    }
}

// 守卫（外部参考实现同款）：vtable ∈ {arc,hold}、active==1、弧须非 void（note+0xA4==0）。
static void s_ap_mark_ln(uint64_t note, uint64_t ng) {
    uint64_t mb = atomic_load(&s_main_base);
    if (!mb || !s_ap_ptr_ok(note)) return;
    uint64_t vt = s_ap_ld64(note);
    bool is_arc  = (vt == mb + XRC_LN_VPTR_ARC);
    bool is_hold = (vt == mb + XRC_LN_VPTR_HOLD);
    if (!is_arc && !is_hold) return;
    if (s_ap_ld8(note + XRC_NOTE_ACTIVE_OFF) != 1) return;
    if (is_arc && s_ap_ld32(note + XRC_LN_VOID_OFF) != 0) return;   // void/trace 弧不标记
    int32_t now = s_ap_chart_now(ng);
    if (now < 0) return;
    int32_t t0  = (int32_t)s_ap_ld32(note + XRC_NOTE_TIME_OFF);
    int32_t t1  = (int32_t)s_ap_ld32(note + XRC_NOTE_TIME_END_OFF);
    if (now < t0) return;                 // 头部之前不标记（外部参考实现）
    if (now > t1 + 100) return;           // 尾部之后 +100ms 停止（外部参考实现）
    if (is_hold && now < t0 + 16) return; // hold 头部 16ms 内不标记（外部参考实现）
    // 1) 每音符一次的引擎调用（touch-begin 语义）
    if (s_ap_dispatch_once(note, t0)) {
        if (is_arc) {
            uint8_t ctx[0x40] = {0};
            *(int32_t *)(ctx + 0x34) = -1;   // 事件结构：仅 +0x34 被读（-1 = 无手指哨兵，外部参考实现同款）
            ((void (*)(uint64_t, void *, int32_t))(mb + XRC_OFF_FN_ARC_CONSUME))(note, ctx, now);
        } else {
            ((void (*)(uint64_t))(mb + XRC_OFF_FN_MARK_HOLD))(note);
        }
    }
    // 2) hold 的"被接住"状态（外部参考实现 hold 分支专属；缺它则显示未接住）
    if (is_hold) {
        *(volatile uint32_t *)(note + XRC_NOTE_HOLD_POS_OFF) = 0;
        *(volatile uint8_t  *)(note + XRC_NOTE_HELD_OFF)     = 1;
    }
    // 3) 逐帧维持"被触"（引擎每帧清；只写字段，不派发事件）
    *(volatile uint16_t *)(note + XRC_NOTE_LNSTATE_OFF) = 0x0101;
    // 4) 弧：sprite 触摸态字段（+0x10/+0x12/+0x14=now+500，外部参考实现配方）
    if (is_arc) {
        uint64_t spr = ((uint64_t (*)(uint64_t))(mb + XRC_OFF_FN_ARC_SPRITE))(note);
        if (s_ap_ptr_ok(spr)) {
            *(volatile uint16_t *)(spr + 0x10) = 0x0101;
            *(volatile uint8_t  *)(spr + 0x12) = 1;
            *(volatile float    *)(spr + 0x14) = (float)(now + 500);
        }
    }
    atomic_fetch_add(&s_ap_stat_mark, 1);
}

// 长条触摸态读取点（命中时 X0 = 长条 note、X20 = note group）：标记后不改 PC → 重放原 LDRB。
static void s_ap_ln_state(void *vctx) {
    if (!xrc_judge_autoplay()) return;
    ucontext_t *uc = (ucontext_t *)vctx;
    if (!uc || !uc->uc_mcontext) return;
    __typeof__(uc->uc_mcontext->__ss) *ss = &uc->uc_mcontext->__ss;
    s_ap_mark_ln(ss->__x[0], ss->__x[20]);
}

// 长条判定派发前的 vtable 装载点（命中时 X27 = 长条 note）：同上（兜底标记）。
static void s_ap_ln_tick(void *vctx) {
    if (!xrc_judge_autoplay()) return;
    ucontext_t *uc = (ucontext_t *)vctx;
    if (!uc || !uc->uc_mcontext) return;
    __typeof__(uc->uc_mcontext->__ss) *ss = &uc->uc_mcontext->__ss;
    s_ap_mark_ln(ss->__x[27], ss->__x[20]);
}

// 窗口点强判（note_win / arctap_win 共用）：note = 音符寄存器、ng = X20、now = X2。
// 谱面时刻 >= note+0x1C（窗口时刻）→ 直调 commit(Pure, judge_time=窗口时刻) + fx[1]，
// PC 跳至原版汇合点；未到窗口 → 不改 PC → 重放原 CMP（NZCV 由真实执行产生，分支语义不变）。
static void s_ap_window(void *vctx, int note_reg, uint64_t cont_off, _Atomic(uint32_t) *ctr) {
    if (!xrc_judge_autoplay()) return;
    ucontext_t *uc = (ucontext_t *)vctx;
    if (!uc || !uc->uc_mcontext) return;
    __typeof__(uc->uc_mcontext->__ss) *ss = &uc->uc_mcontext->__ss;
    uint64_t note = ss->__x[note_reg];
    uint64_t ng   = ss->__x[20];
    int32_t  now  = (int32_t)ss->__x[2];
    uint64_t mb   = atomic_load(&s_main_base);
    if (!mb || !s_ap_ptr_ok(note) || !s_ap_ptr_ok(ng) || now < 0) return;
    if (s_ap_ld8(note + XRC_NOTE_ACTIVE_OFF) != 1) return;   // active（外部参考实现同款守卫）
    int32_t t_end = (int32_t)s_ap_ld32(note + XRC_NOTE_TIME_END_OFF);
    if (t_end > now) return;   // 窗口未到：原版比较继续（重放）
    xrc_judge_autoplay_pure(ng, note, t_end);
    atomic_fetch_add(ctr, 1);
    __darwin_arm_thread_state64_set_pc_fptr(*ss, (void *)(mb + cont_off));
}

static void s_ap_note_win(void *vctx)   { s_ap_window(vctx, 28, XRC_AP_NOTE_WIN_CONT_OFF, &s_ap_stat_win_note); }
static void s_ap_arctap_win(void *vctx) { s_ap_window(vctx, 27, XRC_AP_ARCTAP_WIN_CONT_OFF, &s_ap_stat_win_tap); }

// 引擎 tick 计数（诊断；命中点 = 两个 tick 助手的返回后 MOV X26,X0，X0 = 本次 tick 数）。
// 不改 PC → 分发器重放该 MOV。用来对账"引擎自己发了多少 tick 判定"。
static void s_ap_tickcnt(void *vctx, _Atomic(uint32_t) *ctr) {
    if (!xrc_judge_autoplay()) return;
    ucontext_t *uc = (ucontext_t *)vctx;
    if (!uc || !uc->uc_mcontext) return;
    int32_t n = (int32_t)uc->uc_mcontext->__ss.__x[0];
    if (n > 0) atomic_fetch_add(ctr, (uint32_t)n);
}
static void s_ap_tickcnt1(void *vctx) { s_ap_tickcnt(vctx, &s_ap_stat_tick1); }
static void s_ap_tickcnt2(void *vctx) { s_ap_tickcnt(vctx, &s_ap_stat_tick2); }

// 触摸吞掉（三个输入入口共用）：x0 = 0 并直接按 LR 返回（函数体不执行 = 触摸不进游戏逻辑）。
static void s_ap_swallow(void *vctx) {
    if (!xrc_judge_autoplay()) return;
    ucontext_t *uc = (ucontext_t *)vctx;
    if (!uc || !uc->uc_mcontext) return;
    __typeof__(uc->uc_mcontext->__ss) *ss = &uc->uc_mcontext->__ss;
    ss->__x[0] = 0;
    __darwin_arm_thread_state64_set_pc_fptr(*ss, (void *)__darwin_arm_thread_state64_get_lr(*ss));
}

// 弧线视觉（场景 tick 清态点；命中时 X0 = 弧子对象 = sub_100187618(note)、X22 = note）：
// 代执行原版两条清态（STRH/STRB）后重写"被触"值，PC 直接 +8（跳过原版 STRB）。
static void s_ap_arc_visual(void *vctx) {
    if (!xrc_judge_autoplay()) return;
    ucontext_t *uc = (ucontext_t *)vctx;
    if (!uc || !uc->uc_mcontext) return;
    __typeof__(uc->uc_mcontext->__ss) *ss = &uc->uc_mcontext->__ss;
    uint64_t mb = atomic_load(&s_main_base);
    if (!mb) return;
    uint64_t child = ss->__x[0];
    if (s_ap_ptr_ok(child)) {
        *(volatile uint16_t *)(child + 0x10) = 0;      // 原版 STRH WZR,[X0,#0x10]
        *(volatile uint8_t  *)(child + 0x12) = 0;      // 原版 STRB WZR,[X0,#0x12]
        *(volatile uint16_t *)(child + 0x10) = 0x0101; // 重写"被触"（外部参考实现 on_arc_visual_clear 同款）
        *(volatile uint8_t  *)(child + 0x12) = 1;
    }
    s_ap_mark_ln(ss->__x[22], ss->__x[19]);   // X22 = 弧 note，X19 = note group（场景 tick 簇的 self）
    __darwin_arm_thread_state64_set_pc_fptr(*ss,
        (void *)(mb + XRC_BRK_AP_ARC_VISUAL_SITE_OFF + 8));
}

// ---------------- 全条件放行（unlock_all / dl_ready；站点/出处见 XRCProfile.h 同名块）----------------
// 目标（第一性原理）：**本地存在合法谱面（该难度在 songlist 声明，song+0x250[idx]!=0）时，
// 任何"条件"不得阻止其可见、可游玩**。四处判定源头：
//   ① sub_100919E5C 锁态总源（44 调用点：选曲 cell/曲绘/横幅/世界/包页）→ 直返五字节全解；
//   ② sub_100919874 可玩性总源（70 调用点：start 钮/开局链）→ 直返 1（放行）。
//      ⚠ 仅当该难度"已声明"才放行：没有谱面的难度不硬开（开局会 load 失败 __cxa_throw）。
//   ③ sub_100BDC5A8 / sub_100BDC8D4 难度条件求值（解锁条件对象家族）→ 恒真（1）。
//   ④ sub_100850308 下载"需动作"谓词（仅 2 调用点：start 钮图标/开局弹窗分流）→ 直返 0。
//      ⚠ 不动 sub_100844774（下载机制本体，2026-09-28 教训）；缺文件仍由开局链温和失败+重扫。
static void s_lock_all(void *vctx) {           // 已声明难度解锁（直返 (0,0)）；未声明难度保留原判定
    if (!atomic_load(&s_unlock_all)) return;
    ucontext_t *uc = (ucontext_t *)vctx;
    if (!uc || !uc->uc_mcontext) return;
    __typeof__(uc->uc_mcontext->__ss) *ss = &uc->uc_mcontext->__ss;
    uint64_t song = ss->__x[0];
    uint32_t diff = (uint32_t)ss->__x[1];
    if (!s_ap_ptr_ok(song)) return;                    // 指针防御：异常形态空转回放原逻辑
    uint32_t idx = diff >= 5 ? 1 : diff;               // = sub_100BDCD20（≥5 归 1；0x84CE2C 内同式）
    if (s_ap_ld8(song + 0x250 + idx) == 0) return;     // 该难度未声明（本地无谱面）：不硬开、保留锁定
    s_lock_clear(vctx);
}

static void s_play_gate(void *vctx) {          // 可玩性总源：声明过难度 → 恒放行
    if (!atomic_load(&s_unlock_all)) return;
    ucontext_t *uc = (ucontext_t *)vctx;
    if (!uc || !uc->uc_mcontext) return;
    __typeof__(uc->uc_mcontext->__ss) *ss = &uc->uc_mcontext->__ss;
    uint64_t song = ss->__x[0];
    uint64_t diff = (uint32_t)ss->__x[1];
    if (!s_ap_ptr_ok(song)) return;                    // 指针防御：异常形态空转回放原逻辑
    uint64_t idx = diff >= 5 ? 1 : diff;               // = sub_100BDCD20（≥5 归 1；0x84CE2C 内同式）
    if (s_ap_ld8(song + 0x250 + idx) == 0) return;     // 该难度未声明（无谱面）：不硬放行
    s_ret(1, vctx);
}

static void s_cond_unlock(void *vctx) {        // BDC5A8/BDC8D4 共用：解锁条件恒满足
    if (!atomic_load(&s_unlock_all)) return;
    s_ret(1, vctx);
}

static void s_dl_play_ready(void *vctx) {      // "需要下载/更新"谓词 → 无需动作
    if (!atomic_load(&s_dl_ready)) return;
    s_ret(0, vctx);
}

// 锁绘分支族（四处，站点/出处见 XRCProfile.h 同名块）：
//   触发器 = 锁态打包值 bit32 置位（**该位是"锁定"标志之一**；极性修正后见 XRCProfile.h）。
//   置位 → 走 sub_10084F0E8 锁绘选择器（包 konzetsu/finale → jacket_locked_*；arghena→konzetsu 绘；
//   其余 → jacket_locked_generic）。锁态桩现值 0 ⇒ bit32=0，本族与原生同侧（冗余保险）；
//   开关开时恒走普通曲绘侧：TBNZ 站点→不跳；TBZ 站点（B3F274）→跳。
//   开关关 → 按位复现原分支（逐字节同原行为）。均为 PC 相对条件分支：replay=0（no-replay）。
static void s_jacket_branch(void *vctx, int reg, uint64_t target_off, bool tbz) {
    ucontext_t *uc = (ucontext_t *)vctx;
    if (!uc || !uc->uc_mcontext) return;
    __typeof__(uc->uc_mcontext->__ss) *ss = &uc->uc_mcontext->__ss;
    uint64_t pc = (uint64_t)__darwin_arm_thread_state64_get_pc(*ss);
    if (atomic_load(&s_unlock_all) || atomic_load(&s_unlock_do)) {
        // 普通曲绘侧：TBNZ（b4 置位本该跳）→ 不跳；TBZ（b4 清零本该跳）→ 跳。
        uint64_t mb = atomic_load(&s_main_base);
        uint64_t tgt = (tbz && mb) ? mb + target_off : 0;
        __darwin_arm_thread_state64_set_pc_fptr(*ss, (void *)(tgt ? tgt : pc + 4));
        return;
    }
    uint64_t mb = atomic_load(&s_main_base);
    uint64_t tgt = mb ? mb + target_off : 0;
    bool bit = (((uint64_t)ss->__x[reg] >> 32) & 1u) != 0;   // TBZ/TBNZ Xn,#0x20（bit32 = b4 的 LSB）
    bool take = tbz ? !bit : bit;
    __darwin_arm_thread_state64_set_pc_fptr(*ss, (void *)((take && tgt) ? tgt : pc + 4));
}
static void s_jacket_lock(void *vctx)  { s_jacket_branch(vctx, 0,  XRC_BRK_JACKET_LOCK_TARGET_OFF,  false); }  // 84EF48 TBNZ X0
static void s_jacket_cell(void *vctx)  { s_jacket_branch(vctx, 8,  XRC_BRK_JACKET_CELL_TARGET_OFF,  false); }  // 8EAFB4 TBNZ X8
static void s_jacket_info(void *vctx)  { s_jacket_branch(vctx, 0,  XRC_BRK_JACKET_INFO_TARGET_OFF,  false); }  // 94A57C TBNZ X0
static void s_jacket_panel(void *vctx) { s_jacket_branch(vctx, 24, XRC_BRK_JACKET_PANEL_TARGET_OFF, true);  }  // B3F274 TBZ X24

// 桩表（site/replay/handler 同源 XRCProfile.h；加桩 = 这里加一行 + inject.py 同步）。
// 放在分发器之前：分发器用它做"未注册兜底"（早期命中时注册可能还没跑，见 xrc_brk_setup_early）。
typedef struct {
    const char *name;
    uint64_t    site_off;
    uint64_t    replay_off;
    void      (*handler)(void *);
} xrc_brk_entry_t;

// ================================================================ 弧/绘制 观测桩（只观测，不改行为）
// 设计依据（全部在本版 7.0.255 二进制里静态坐实，出处附在每行）：
//   · 绘制趟 sub_100B23664 入口:
//       0x100b23584  LDR X1,[X23,#0x288]   ⇒ **arg1 = *(track+0x288) = 音符表 {begin,end}**
//       0x100b236b4  LDP X21,X22,[X25]     ⇒ 表就是个 vector<LogicNote*>
//       0x100b236ac  LDR W8,[X19,#0x39C]   ⇒ 脏检查计数（与 sub_100E52360()+0x134 比）
//       0x100b236e0  CMP W8,W9 / B.EQ      ⇒ **脏检查 gate 的是每音符 tick(vt[0x518])，不是绘制本身**
//     ⇒ 这一帧引擎会考虑的全部音符都在这张表里，直接就是"全局真值"。
//   · 弧 tick  sub_100AFFC10 入口: X0 = 该弧渲染对象（内部的 logic = *(X0+0x268)）
//   · 头过线   sub_100AFFA90 入口: 同上；只有 `arc+0x18 < now` 时才会被 tick 调
// 三个 handler **一律不碰 PC** ⇒ 分发器自动送回重放跳板（重放原首指令 + B 回 site+4）⇒ 零行为改变。
//
// 记录什么（只读，不做任何引擎调用）：
//   note+0x18/0x1C = start/end(ms)；note+0x30 = 位置 int 对低半（弧的 head 就是这个）；
//   note+0x0C/0x0D = 消费/判定闩；note+0x99、+0xA8 = 运行期态；note+0xA4 = 弧类型位。
#if XRC_DEBUG_BUILD

#define XRC_ARCR_RING   4096
typedef struct { uint32_t tag, a, b, c, d, e, f, g; } xrc_arcr_t;
static xrc_arcr_t s_arcr[XRC_ARCR_RING];
static _Atomic(uint32_t) s_arcr_tail_seen = 0;
static _Atomic(uint32_t) s_arcr_head = 0, s_arcr_lost = 0;
static _Atomic(uint32_t) s_arcr_draw_n = 0, s_arcr_tick_n = 0, s_arcr_pass_n = 0;

static inline void s_arcr_push(uint32_t tag, uint32_t a, uint32_t b, uint32_t c,
                               uint32_t d, uint32_t e, uint32_t f, uint32_t g) {
    uint32_t i = atomic_fetch_add(&s_arcr_head, 1);
    if ((i - atomic_load(&s_arcr_tail_seen)) >= XRC_ARCR_RING) { atomic_fetch_add(&s_arcr_lost, 1); return; }
    xrc_arcr_t *r = &s_arcr[i & (XRC_ARCR_RING - 1)];
    r->tag = tag; r->a = a; r->b = b; r->c = c; r->d = d; r->e = e; r->f = f; r->g = g;
}

// 供诊断读取：把环形缓冲里的记录搬出来（返回条数）
size_t xrc_brk_arcr_drain(uint32_t *out, size_t max_recs) {
    uint32_t head = atomic_load(&s_arcr_head);
    uint32_t tail = atomic_load(&s_arcr_tail_seen);
    size_t n = 0;
    while (tail != head && n < max_recs) {
        const xrc_arcr_t *r = &s_arcr[tail & (XRC_ARCR_RING - 1)];
        uint32_t *o = out + n * 8;
        o[0]=r->tag; o[1]=r->a; o[2]=r->b; o[3]=r->c; o[4]=r->d; o[5]=r->e; o[6]=r->f; o[7]=r->g;
        tail++; n++;
    }
    atomic_store(&s_arcr_tail_seen, tail);
    return n;
}
void xrc_brk_arcr_stats(uint32_t out[4]) {
    out[0] = atomic_load(&s_arcr_head);
    out[1] = atomic_load(&s_arcr_lost);
    out[2] = atomic_load(&s_arcr_draw_n);
    out[3] = atomic_load(&s_arcr_tick_n) + atomic_load(&s_arcr_pass_n);
}

#else
// 发布构建：观测环不启用（以下 API 为空实现）。
size_t xrc_brk_arcr_drain(uint32_t *out, size_t max_recs) { (void)out; (void)max_recs; return 0; }
void   xrc_brk_arcr_stats(uint32_t out[4]) { out[0] = out[1] = out[2] = out[3] = 0; }
#endif

// 桩的收尾：只把 PC 推到 site+4。
// 不需要补 SP：**BRK 打在入口的第二条指令上**（入口 +4），入口那条 `SUB SP,SP,#N`
// 照常执行 ⇒ SP 自然是对的。处理器只需跳过被换成 BRK 的那条 STP。
// 不用重放跳板：`B` 只有 ±128MB，而 __TEXT 空白页 0x101468xxx 离站点 271MB，够不到
//（inject.py 的 encode_b 会 assert）⇒ 这三条在 inject.py 侧用 replay_va=0 的
// handler-emulated 形态，PC 覆写由 handler 负责。
// 代价：被跳过的是一条 `STP Dn,Dm,[SP,#...]`（保存 callee-saved 浮点寄存器）——
// 那个函数本来就不返回我们关心的值，且我们只读寄存器/内存，无副作用。
// 分发器协议：handler 改了 PC ⇒ 它只管返回，分发器不再动 PC。
static inline void s_arcr_entry_exit(void *vctx) {
    ucontext_t *uc = (ucontext_t *)vctx;
    if (!uc || !uc->uc_mcontext) return;
    __typeof__(uc->uc_mcontext->__ss) *ss = &uc->uc_mcontext->__ss;
    __darwin_arm_thread_state64_set_pc_fptr(*ss,
        (void *)((uint64_t)__darwin_arm_thread_state64_get_pc(*ss) + 4));
}

// ---- 观测桩「轻量模式」----
// 这三个观测桩是高频负载源：每次命中 = 一次内核 SIGTRAP + 我们的 C handler，而 handler
// 干的是重活（绘制趟每命中一次就遍历整张音符表，实测 2619 条；日志显示它每 50ms 就撑满
// 512 条记录的环形缓冲 ⇒ 每秒上万次陷阱，全在**游戏自己的线程**上同步陷入）。代价随
// 屏幕上的弧/音符数浮动 ⇒ **帧时间不稳定**。
// 轻量模式：handler 只推进 PC、不做任何观测（仍有 SIGTRAP 成本，去掉重活）。
// 关闭这些站点请用不带 rpf_arcprobe 的构建（inject.py --features）。
#if XRC_DEBUG_BUILD
static _Atomic(int) s_stub_lite = 0;
void xrc_arc_stubs_lite_set(int on) { atomic_store(&s_stub_lite, on ? 1 : 0); }
int  xrc_arc_stubs_lite_get(void)   { return atomic_load(&s_stub_lite); }
#else
void xrc_arc_stubs_lite_set(int on) { (void)on; }
int  xrc_arc_stubs_lite_get(void)   { return 1; }
#endif

#if XRC_DEBUG_BUILD

// ---- 站点 1：绘制趟入口（每帧一次）—— 全谱表逐条快照 ----
// 站点 = 入口 0x100B23664 + 4（第二条 STP，被换成 BRK）。
// X0 = track，X1 = 音符表 {begin,end}。把表里**每一条**（上限 96）的标量写进环形缓冲，
// 弧的 head 就是 note+0x30（logic 层），不经过任何虚调用。
static _Atomic(uint32_t) s_draw_frame = 0;
static void s_rpf_draw(void *vctx) {
    ucontext_t *uc = (ucontext_t *)vctx;
    if (!uc || !uc->uc_mcontext) { s_arcr_entry_exit(vctx); return; }
    if (atomic_load(&s_stub_lite)) { s_arcr_entry_exit(vctx); return; }   /* 轻量模式 */
    __typeof__(uc->uc_mcontext->__ss) *ss = &uc->uc_mcontext->__ss;
    uint64_t track = ss->__x[0], tbl = ss->__x[1];
    uint32_t fr = atomic_fetch_add(&s_draw_frame, 1) + 1;
    atomic_fetch_add(&s_arcr_draw_n, 1);
    if (!s_ap_ptr_ok(tbl)) { s_arcr_entry_exit(vctx); return; }
    uint64_t b = s_ap_ld64(tbl), e = s_ap_ld64(tbl + 8);
    if (!s_ap_ptr_ok(b) || e <= b || (e - b) > 0x40000) { s_arcr_entry_exit(vctx); return; }
    uint64_t n = (e - b) / 8;
    uint32_t dirty = s_ap_ptr_ok(track) ? s_ap_ld32(track + 0x39C) : 0;
    uint32_t arc_n = 0, note_n = (uint32_t)(n > 0xFFFF ? 0xFFFF : n);
    for (uint64_t i = 0; i < n && arc_n < 96; i++) {
        uint64_t nt = s_ap_ld64(b + 8 * i);
        if (!s_ap_ptr_ok(nt)) continue;
        uint64_t vt = s_ap_ld64(nt);
        if (vt != (atomic_load(&s_main_base) + XRC_LN_VPTR_ARC)) continue;
        arc_n++;
        uint32_t head = s_ap_ld32(nt + 0x30), st = s_ap_ld32(nt + 0x18),
                 en = s_ap_ld32(nt + 0x1C), a4 = s_ap_ld32(nt + 0xA4);
        uint32_t f99 = s_ap_ld8(nt + 0x99), fA8 = s_ap_ld8(nt + 0xA8),
                 c0c = s_ap_ld8(nt + 0x0C), c0d = s_ap_ld8(nt + 0x0D);
        uint32_t flags = (f99 & 1) | ((fA8 & 1) << 1) | ((c0c & 1) << 2) |
                         ((c0d & 1) << 3) | ((a4 & 0xF) << 4);
        s_arcr_push(1, fr, (uint32_t)(nt & 0xFFFFFFFFu), head, st, en, flags, dirty);
    }
    s_arcr_push(0x100, fr, note_n, arc_n, dirty, 0, 0, 0);
    s_arcr_entry_exit(vctx);
}

// ---- 站点 2/3：弧 tick 与头过线入口 —— 引擎"此刻"的输入 ----
// X0 = 该弧渲染对象 ⇒ logic = *(X0+0x268)。只记标量，不枚举子节点。
static void s_rpf_arc_x(void *vctx, uint32_t tag) {
    ucontext_t *uc = (ucontext_t *)vctx;
    if (!uc || !uc->uc_mcontext) { s_arcr_entry_exit(vctx); return; }
    if (atomic_load(&s_stub_lite)) { s_arcr_entry_exit(vctx); return; }   /* 轻量模式 */
    __typeof__(uc->uc_mcontext->__ss) *ss = &uc->uc_mcontext->__ss;
    uint64_t rp = ss->__x[0];
    if (!s_ap_ptr_ok(rp)) { s_arcr_entry_exit(vctx); return; }
    uint64_t lg = s_ap_ld64(rp + 0x268);
    if (!s_ap_ptr_ok(lg)) { s_arcr_entry_exit(vctx); return; }
    uint32_t head = s_ap_ld32(lg + 0x30), st = s_ap_ld32(lg + 0x18),
             en = s_ap_ld32(lg + 0x1C), a4 = s_ap_ld32(lg + 0xA4),
             f99 = s_ap_ld8(lg + 0x99), fA8 = s_ap_ld8(lg + 0xA8);
    // 记录布局：
    //   tag, rp_lo32(弧渲染对象), head, start, end, flags(a4|f99<<4|fA8<<5), lg_lo32(logic), 0
    uint32_t flags = (a4 & 0xF) | ((f99 & 1) << 4) | ((fA8 & 1) << 5);
    s_arcr_push(tag, (uint32_t)((uintptr_t)rp & 0xFFFFFFFFu), head, st, en, flags,
                (uint32_t)((uintptr_t)lg & 0xFFFFFFFFu), 0);
    s_arcr_entry_exit(vctx);
}
static void s_rpf_arctick(void *vctx) {   // 入口 SUB SP,SP,#0xA0
    atomic_fetch_add(&s_arcr_tick_n, 1);
    s_rpf_arc_x(vctx, 2);
}
static void s_rpf_arcpass(void *vctx) {   // 入口 SUB SP,SP,#0x70
    atomic_fetch_add(&s_arcr_pass_n, 1);
    s_rpf_arc_x(vctx, 3);
}

#else
// 发布构建：观测桩处理器只推进 PC（站点不随发布构建注入；旧产物残留时保持零行为）。
static void s_rpf_draw(void *vctx)    { s_arcr_entry_exit(vctx); }
static void s_rpf_arctick(void *vctx) { s_arcr_entry_exit(vctx); }
static void s_rpf_arcpass(void *vctx) { s_arcr_entry_exit(vctx); }
#endif

// ---- 弧分段「藏」→「显」的两处桩（只在 seek 回跳窗口内开启）----
// 桩打在 `MOV W1,#0`（52800001）这条上 —— 它的 W1 就是紧接着 setVisible(child, W1) 的参数。
// 站点的选择见 XRCProfile.h 的长注释：不碰 PC、不调游戏函数、不需要跳板。
//
// ⚠️ 关键：handler 把 BRK 顶掉的那条 MOV **复现**出来 —— 平时写 W1=0（=原行为，逐字节等价），
//    「回跳窗口」内置位后写 W1=1 ⇒ 引擎自己把分段显回来。窗口由回跳状态机驱动（回跳起 → 涨回旧水位）。
// 只改 X1 一个寄存器，PC 推到 site+4；无重入、无分配、无锁。
static _Atomic(int) s_arc_nohide = 0;

void xrc_arc_nohide_set(int on) { atomic_store(&s_arc_nohide, on ? 1 : 0); }
int  xrc_arc_nohide_get(void)    { return atomic_load(&s_arc_nohide); }

static void s_arc_hide_x(void *vctx) {
    ucontext_t *uc = (ucontext_t *)vctx;
    if (!uc || !uc->uc_mcontext) return;
    __typeof__(uc->uc_mcontext->__ss) *ss = &uc->uc_mcontext->__ss;
    /* 复现 `MOV W1,#0`；回跳窗口内改成 1（显） */
    ss->__x[1] = atomic_load(&s_arc_nohide) ? 1u : 0u;
    __darwin_arm_thread_state64_set_pc_fptr(*ss,
        (void *)((uint64_t)__darwin_arm_thread_state64_get_pc(*ss) + 4));
}
static void s_arc_hide_a(void *vctx) { s_arc_hide_x(vctx); }
static void s_arc_hide_b(void *vctx) { s_arc_hide_x(vctx); }

static const xrc_brk_entry_t k_brk_entries[] = {
    { "applog_send", XRC_BRK_APPLOG_SITE_OFF,     XRC_BRK_APPLOG_REPLAY_OFF,     s_applog_capture },
    { "applog_blob", XRC_BRK_APPLOG_BLOB_SITE_OFF, XRC_BRK_APPLOG_BLOB_REPLAY_OFF, s_applog_blob_capture },
    { "unlock_l1",   XRC_BRK_UNLOCK_L1_SITE_OFF,  XRC_BRK_UNLOCK_L1_REPLAY_OFF,  s_unlock_force_true },
    { "unlock_l2",   XRC_BRK_UNLOCK_L2_SITE_OFF,  XRC_BRK_UNLOCK_L2_REPLAY_OFF,  s_unlock_force_true },
    { "unlock_l3",   XRC_BRK_UNLOCK_L3_SITE_OFF,  XRC_BRK_UNLOCK_L3_REPLAY_OFF,  s_unlock_force_true },
    { "cb_ready",    XRC_BRK_CB_READY_SITE_OFF,   XRC_BRK_CB_READY_REPLAY_OFF,   s_cb_ready_true },
    // cb 自由化：三站点 = "校验结论恒通过"（语义见 XRCProfile.h）
    { "cb_filehash", XRC_BRK_CB_FILEHASH_SITE_OFF, 0,                            s_cb_cond_skip },
    { "cb_listhash", XRC_BRK_CB_LISTHASH_SITE_OFF, 0,                            s_cb_cond_skip },
    { "cb_wipe",     XRC_BRK_CB_WIPE_SITE_OFF,     XRC_BRK_CB_WIPE_REPLAY_OFF,   s_cb_wipe_guard },
    { "cb_dispatch", XRC_BRK_CB_DISPATCH_SITE_OFF, XRC_BRK_CB_DISPATCH_REPLAY_OFF, s_cb_skip_void },
    // cb 自由化 · 版本/更新链（无 meta.cb 情形；语义与证据链见 XRCProfile.h 同名块）
    { "cb_gate",     XRC_BRK_CB_GATE_SITE_OFF,     XRC_BRK_CB_GATE_REPLAY_OFF,   s_cb_gate_observe },
    { "cb_fetch",    XRC_BRK_CB_FETCH_SITE_OFF,    XRC_BRK_CB_FETCH_REPLAY_OFF,  s_cb_fetch_observe },
    // ---- 自动演奏（外部参考实现对齐；功能账 §5.2）----
    { "ap_ln_state",      XRC_BRK_AP_LN_STATE_SITE_OFF,     XRC_BRK_AP_LN_STATE_REPLAY_OFF,     s_ap_ln_state },
    { "ap_ln_tick",       XRC_BRK_AP_LN_TICK_SITE_OFF,      XRC_BRK_AP_LN_TICK_REPLAY_OFF,      s_ap_ln_tick },
    { "ap_note_win",      XRC_BRK_AP_NOTE_WIN_SITE_OFF,     XRC_BRK_AP_NOTE_WIN_REPLAY_OFF,     s_ap_note_win },
    { "ap_arctap_win",    XRC_BRK_AP_ARCTAP_WIN_SITE_OFF,   XRC_BRK_AP_ARCTAP_WIN_REPLAY_OFF,   s_ap_arctap_win },
    { "ap_swallow_judge", XRC_BRK_AP_SWALLOW_JUDGE_SITE_OFF, XRC_BRK_AP_SWALLOW_JUDGE_REPLAY_OFF, s_ap_swallow },
    { "ap_swallow_batch", XRC_BRK_AP_SWALLOW_BATCH_SITE_OFF, XRC_BRK_AP_SWALLOW_BATCH_REPLAY_OFF, s_ap_swallow },
    { "ap_swallow_touch", XRC_BRK_AP_SWALLOW_TOUCH_SITE_OFF, XRC_BRK_AP_SWALLOW_TOUCH_REPLAY_OFF, s_ap_swallow },
    { "ap_arc_visual",    XRC_BRK_AP_ARC_VISUAL_SITE_OFF,   XRC_BRK_AP_ARC_VISUAL_REPLAY_OFF,   s_ap_arc_visual },
    // ---- 自动演奏诊断计数：引擎两个 tick 助手的返回点（MOV X26,X0；只计数+重放）----
    { "ap_tickcnt1",      XRC_BRK_AP_TICKCNT1_SITE_OFF,     XRC_BRK_AP_TICKCNT1_REPLAY_OFF,     s_ap_tickcnt1 },
    { "ap_tickcnt2",      XRC_BRK_AP_TICKCNT2_SITE_OFF,     XRC_BRK_AP_TICKCNT2_REPLAY_OFF,     s_ap_tickcnt2 },
    // ---- 曲目锁态覆盖 + 链守卫 ----
    { "lock_fv",          XRC_BRK_LOCK_FV_SITE_OFF,         XRC_BRK_LOCK_FV_REPLAY_OFF,         s_lock_fv },
    { "lock_do",          XRC_BRK_LOCK_DO_SITE_OFF,         XRC_BRK_LOCK_DO_REPLAY_OFF,         s_lock_do },
    { "fv_gate",          XRC_BRK_FV_GATE_SITE_OFF,         XRC_BRK_FV_GATE_REPLAY_OFF,         s_finale_gate_open },
    { "pack_open",        XRC_BRK_PACK_OPEN_SITE_OFF,       XRC_BRK_PACK_OPEN_REPLAY_OFF,       s_pack_open },
    { "shutter_done",     XRC_BRK_SHUTTER_DONE_SITE_OFF,    XRC_BRK_SHUTTER_DONE_REPLAY_OFF,    s_shutter_done },
    { "chain_prog",       XRC_BRK_CHAIN_PROG_SITE_OFF,      XRC_BRK_CHAIN_PROG_REPLAY_OFF,      s_chain_prog_neutral },
    // ---- 全条件放行（unlock_all / dl_ready；站点/出处见 XRCProfile.h 同名块）----
    { "lock_all",         XRC_BRK_LOCK_ALL_SITE_OFF,        XRC_BRK_LOCK_ALL_REPLAY_OFF,        s_lock_all },
    { "play_gate",        XRC_BRK_PLAY_GATE_SITE_OFF,       XRC_BRK_PLAY_GATE_REPLAY_OFF,       s_play_gate },
    { "dl_play",          XRC_BRK_DL_PLAY_SITE_OFF,         XRC_BRK_DL_PLAY_REPLAY_OFF,         s_dl_play_ready },
    { "cond_unlock_a",    XRC_BRK_COND_UNLOCK_A_SITE_OFF,   XRC_BRK_COND_UNLOCK_A_REPLAY_OFF,   s_cond_unlock },
    { "cond_unlock_b",    XRC_BRK_COND_UNLOCK_B_SITE_OFF,   XRC_BRK_COND_UNLOCK_B_REPLAY_OFF,   s_cond_unlock },
    { "jacket_lock",      XRC_BRK_JACKET_LOCK_SITE_OFF,     0,                                  s_jacket_lock },
    { "jacket_cell",      XRC_BRK_JACKET_CELL_SITE_OFF,     0,                                  s_jacket_cell },
    { "jacket_info",      XRC_BRK_JACKET_INFO_SITE_OFF,     0,                                  s_jacket_info },
    { "jacket_panel",     XRC_BRK_JACKET_PANEL_SITE_OFF,    0,                                  s_jacket_panel },
    // 弧/绘制观测桩（只观测不改行为；见本文件顶部"弧/绘制 观测桩"长注释）
    { "rpf_draw",         XRC_BRK_RPF_DRAW_SITE_OFF,        0,                                   s_rpf_draw },
    { "rpf_arctick",      XRC_BRK_RPF_ARCTICK_SITE_OFF,     0,                                   s_rpf_arctick },
    { "rpf_arcpass",      XRC_BRK_RPF_ARCPASS_SITE_OFF,     0,                                   s_rpf_arcpass },
    // 弧分段「藏」→「显」（handler 只改 W1；见上方 s_arc_hide_x 注释）
    { "arc_hide_a",       XRC_BRK_ARC_HIDE_A_SITE_OFF,      0,                                   s_arc_hide_a },
    { "arc_hide_b",       XRC_BRK_ARC_HIDE_B_SITE_OFF,      0,                                   s_arc_hide_b },
};

// ---- 未注册桩位自愈 ----
// 主程序里可能残留本桩表不含的 BRK（还原逻辑只遍历当前表）——dylib 没有对应处理器时，
// 命中即"无处理器的 SIGTRAP"直接闪退。这里带原指令：命中就**就地写回原指令并原地
// 重跑**（PC 不动），之后该处再无 BRK。处理器内只做 syscall 级操作
//（mprotect/memcpy/icache flush），日志交给主线程读计数。
typedef struct {
    uint64_t site_off;
    uint32_t orig;
} xrc_restore_site_t;

static const xrc_restore_site_t k_restore_sites[] = {
    { XRC_RESTORE_CB_VERIFY_SITE_OFF, 0xA9BA6FFC },   // STP X28,X27,[SP,#-0x60]!
};

static _Atomic(int)      s_selfheal_hits;         // 自愈次数（主线程读走记日志）
static _Atomic(uint64_t) s_selfheal_last_off;     // 最后一次自愈的 pc-base
static uintptr_t         s_page_size = 0x4000;    // install 时取一次（sysconf 非信号安全）

// 把主程序代码页上的 4 字节写回原指令。成功返回 1（调用方让 PC 原地重跑）。
static int s_restore_code(uint64_t va, uint32_t insn) {
    uintptr_t page = (uintptr_t)va & ~(uintptr_t)(s_page_size - 1);
    if (mprotect((void *)page, s_page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        return 0;
    memcpy((void *)(uintptr_t)va, &insn, sizeof(insn));
    sys_icache_invalidate((void *)(uintptr_t)va, sizeof(insn));
    mprotect((void *)page, s_page_size, PROT_READ | PROT_EXEC);   // 恢复只读可执行
    return 1;
}

static void s_sigtrap(int sig, siginfo_t *info, void *vctx) {    ucontext_t *uc = (ucontext_t *)vctx;
    if (uc && uc->uc_mcontext) {
        __typeof__(uc->uc_mcontext->__ss) *ss = &uc->uc_mcontext->__ss;
        uint64_t pc = (uint64_t)__darwin_arm_thread_state64_get_pc(*ss);
        int n = atomic_load(&s_count);
        for (int i = 0; i < n; i++) {
            uint64_t site = atomic_load(&s_slots[i].site);
            if (site && site == pc) {
                atomic_fetch_add(&s_slots[i].hits, 1);
                atomic_store(&s_slots[i].last_us, s_now_us());
                if (s_slots[i].handler) s_slots[i].handler(vctx);
                // PC 覆写协议：handler 若自行改了 PC（直返/跳转）则尊重之；
                // 未改（仍等于 site）才送回重放跳板。直返桩依赖这条。
                uint64_t pc1 = (uint64_t)__darwin_arm_thread_state64_get_pc(*ss);
                if (pc1 == pc) {
                    uint64_t rp = atomic_load(&s_slots[i].replay);
                    // no-replay 桩（rp=0）：安全落穿（跳过该条件分支）
                    __darwin_arm_thread_state64_set_pc_fptr(*ss,
                        (void *)(rp ? rp : pc + 4));
                }
                return;
            }
        }
        // 兜底：注册表没匹配上，但 PC 命中已知桩表（早期命中，注册尚未跑）——
        // 走该桩的重放跳板（原行为）。绝不把自家的 BRK 链给默认处理器。
        uint64_t mb = atomic_load(&s_main_base);
        if (mb) {
            for (size_t k = 0; k < sizeof(k_brk_entries) / sizeof(k_brk_entries[0]); k++) {
                if (pc == mb + k_brk_entries[k].site_off) {
                    uint64_t ro = k_brk_entries[k].replay_off;
                    // no-replay 桩（ro=0）：安全落穿
                    __darwin_arm_thread_state64_set_pc_fptr(*ss,
                        (void *)(ro ? mb + ro : pc + 4));
                    return;
                }
            }
            // 未注册桩位：就地还原原指令并**原地重跑**（自愈；只做一次，之后该处再无 BRK）
            for (size_t k = 0; k < sizeof(k_restore_sites) / sizeof(k_restore_sites[0]); k++) {
                if (pc == mb + k_restore_sites[k].site_off) {
                    if (s_restore_code(pc, k_restore_sites[k].orig)) {
                        atomic_fetch_add(&s_selfheal_hits, 1);
                        atomic_store(&s_selfheal_last_off, pc - mb);
                        return;   // PC 不变 → 重跑刚写回的原指令
                    }
                    break;        // 还原失败（mprotect 被拒）：交给后续兜底，至少留个计数
                }
            }
        }
    }
    // 不是我们的桩点 —— 原样交给前一个处理器（Swift trap / Crashlytics）
    if (s_prev.sa_flags & SA_SIGINFO) {
        if (s_prev.sa_sigaction) { s_prev.sa_sigaction(sig, info, vctx); return; }
    } else if (s_prev.sa_handler == SIG_IGN) {
        return;
    } else if (s_prev.sa_handler && s_prev.sa_handler != SIG_DFL) {
        s_prev.sa_handler(sig);
        return;
    }
    // SIG_DFL：恢复默认并重抛，避免在同一个 BRK 上死循环
    sigaction(SIGTRAP, &s_prev, NULL);
    raise(SIGTRAP);
}

void xrc_brk_install(void) {
    if (s_installed) return;
    long ps = sysconf(_SC_PAGESIZE);
    if (ps > 0) s_page_size = (uintptr_t)ps;   // 自愈写代码页用（信号处理器里不能调 sysconf）
    mach_timebase_info_data_t tb = {0};
    if (mach_timebase_info(&tb) == KERN_SUCCESS && tb.denom) {
        s_tb_num = tb.numer; s_tb_den = tb.denom;
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = s_sigtrap;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGTRAP, &sa, &s_prev) != 0) {
        xrc_logw(XRCLC_BOOT, @"[brk] sigaction(SIGTRAP) FAILED");
        return;
    }
    atomic_store(&s_main_base, xrc_image_base());
    s_installed = true;
    xrc_logi(XRCLC_BOOT, @"[brk] SIGTRAP handler installed (prev=%p, main=%p)",
            (void *)s_prev.sa_sigaction, (void *)atomic_load(&s_main_base));
}

bool xrc_brk_register(uint64_t site_va, uint64_t replay_va, void (*handler)(void *)) {
    if (!site_va) return false;   // replay_va = 0 合法（no-replay 桩：处理器自设 PC）
    int n = atomic_load(&s_count);
    // 同 site 重复注册 = 换 handler（重注册只换 handler，便于调试替换）
    for (int i = 0; i < n; i++) {
        if (atomic_load(&s_slots[i].site) == site_va) {
            atomic_store(&s_slots[i].replay, replay_va);
            s_slots[i].handler = handler;
            return true;
        }
    }
    if (n >= XRC_BRK_MAX_SLOTS) return false;
    atomic_store(&s_slots[n].site, site_va);
    atomic_store(&s_slots[n].replay, replay_va);
    s_slots[n].handler = handler;
    atomic_store(&s_slots[n].hits, 0);
    atomic_store(&s_slots[n].last_us, 0);
    atomic_store(&s_count, n + 1);
    return true;
}

// ---------------- 静态补丁自检 ----------------
// **凡改了主程序行为的静态补丁，都必须在启动日志里自证（含副作用）**。
// 判定规则（按 8 字节原/补丁值比对）：PATCHED = 补丁在生效；original = 未打；其余 = UNKNOWN（版本不符？）。
typedef struct {
    const char *name;
    uint64_t    off;        // 主程序内偏移（VA - 0x100000000）
    const char *orig;       // 原始 8 字节 hex
    const char *patched;    // 补丁后 8 字节 hex
    const char *effect;     // 生效时的副作用（一句话）
} xrc_static_patch_t;

static const xrc_static_patch_t k_static_patches[] = {
    { "dl_state_ready_merged", 0x844774, "ff4302d1fa6704a9", "00008052c0035fd6",
      "下载态总查询恒返就绪：全 App 下载/更新提示消失，接线上服务器时=曲目下载全失败" },
};

// ---- 构建期功能集（与 inject.py 的 FEATURES 一一对应）----
// 站点是否真的在（= 本次构建是否注入了该功能）在启动时算一次；面板据此只显示本构建含有的项。
typedef struct { const char *feature; const char *sites[10]; int n; } xrc_feature_sites_t;
static const xrc_feature_sites_t k_feature_sites[] = {
    { "unlock_own",     { "unlock_l1", "unlock_l2", "unlock_l3" }, 3 },
    { "unlock_lock",    { "lock_fv", "lock_do", "fv_gate", "pack_open", "shutter_done" }, 5 },
    { "chain_guard",    { "chain_prog" }, 1 },
    { "unlock_all",     { "lock_all", "play_gate", "cond_unlock_a", "cond_unlock_b",
                          "jacket_lock", "jacket_cell", "jacket_info", "jacket_panel" }, 8 },
    { "dl_ready",       { "dl_play" }, 1 },
    { "cb_free",        { "cb_ready", "cb_filehash", "cb_listhash", "cb_wipe", "cb_dispatch",
                          "cb_gate", "cb_fetch" }, 7 },
    { "autoplay",       { "ap_ln_state", "ap_ln_tick", "ap_note_win", "ap_arctap_win",
                          "ap_swallow_judge", "ap_swallow_batch", "ap_swallow_touch",
                          "ap_arc_visual", "ap_tickcnt1", "ap_tickcnt2" }, 10 },
    { "applog_capture", { "applog_send", "applog_blob" }, 2 },
};
#define XRC_FEATURE_N (sizeof(k_feature_sites) / sizeof(k_feature_sites[0]))
static int  s_feature_hits[XRC_FEATURE_N];     // 该功能的在位站点数
static bool s_features_ready = false;

static void s_feature_scan(uint64_t base) {
    NSMutableString *on = [NSMutableString string], *off = [NSMutableString string];
    for (size_t i = 0; i < XRC_FEATURE_N; i++) {
        const xrc_feature_sites_t *f = &k_feature_sites[i];
        int hits = 0;
        for (int j = 0; j < f->n; j++) {
            for (size_t k = 0; k < sizeof(k_brk_entries) / sizeof(k_brk_entries[0]); k++) {
                if (strcmp(k_brk_entries[k].name, f->sites[j]) != 0) continue;
                if (*(volatile uint32_t *)(base + k_brk_entries[k].site_off) == 0xD4200000u) hits++;
                break;
            }
        }
        s_feature_hits[i] = hits;
        [(hits > 0 ? on : off) appendFormat:@"%s ", f->feature];
    }
    s_features_ready = true;
    // 本构建的功能集（排查第一眼：哪些功能在里面）
    xrc_logi(XRCLC_BOOT, @"[patch] features · 启用：%@ · 未含：%@",
             [on stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]],
             [off stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]]);
}

bool xrc_feature_present(const char *feature) {
    if (!feature) return true;
    if (!s_features_ready) return true;        // 自检还没跑：不隐藏（宁可多显示）
    for (size_t i = 0; i < XRC_FEATURE_N; i++) {
        if (strcmp(k_feature_sites[i].feature, feature) == 0)
            return s_feature_hits[i] > 0;      // 至少一个站点在位 = 本构建含有该功能
    }
    return true;                               // 未登记的名字：不隐藏
}

static void s_hex8(const uint8_t *b, char *out /* >=17 */) {
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {
        out[i * 2]     = H[(b[i] >> 4) & 0xF];
        out[i * 2 + 1] = H[b[i] & 0xF];
    }
    out[16] = 0;
}

void xrc_brk_static_report(uint64_t base) {
    if (!base) { xrc_logd(XRCLC_BRK, @"[patch] no image base; static report skipped"); return; }
    int n_patched = 0;
    for (size_t i = 0; i < sizeof(k_static_patches) / sizeof(k_static_patches[0]); i++) {
        const xrc_static_patch_t *p = &k_static_patches[i];
        char hex[17];
        s_hex8((const uint8_t *)(base + p->off), hex);
        const char *state, *note;
        if (strcmp(hex, p->patched) == 0)      { state = "PATCHED";  note = p->effect; n_patched++; }
        else if (strcmp(hex, p->orig) == 0)    { state = "original"; note = "-"; }
        else                                   { state = "UNKNOWN";  note = "字节与已知原/补丁值都不符（版本不符？）"; }
        xrc_logi(XRCLC_BOOT, @"[patch] static %s @0x%llx = %s | %s", p->name,
                (unsigned long long)p->off, state, note);
    }
    // BRK 站点在位计数：dylib 与二进制不配对时（重刷了旧包/漏了 --brk），这里立刻可见。
    int patched = 0, total = 0;
    for (size_t i = 0; i < sizeof(k_brk_entries) / sizeof(k_brk_entries[0]); i++) {
        const xrc_brk_entry_t *e = &k_brk_entries[i];
        total++;
        if (*(volatile uint32_t *)(base + e->site_off) == 0xD4200000u) patched++;
        // 缺桩降为 debug：未选入构建的功能本就该缺（见 s_feature_scan）
        else xrc_logd(XRCLC_BRK, @"[patch] brk absent: %s @0x%llx", e->name, (unsigned long long)e->site_off);
    }
    xrc_logi(XRCLC_BOOT, @"[patch] static report: static_patches=%d/%lu brk_sites=%d/%d",
            n_patched,
            (unsigned long)(sizeof(k_static_patches) / sizeof(k_static_patches[0])),
            patched, total);
    s_feature_scan(base);
}

void xrc_brk_setup(uint64_t image_base) {
    xrc_brk_install();
    if (!image_base) { xrc_logw(XRCLC_BOOT, @"[brk] no image base, skipping registration"); return; }
    for (size_t i = 0; i < sizeof(k_brk_entries) / sizeof(k_brk_entries[0]); i++) {
        const xrc_brk_entry_t *e = &k_brk_entries[i];
        uint64_t site   = image_base + e->site_off;
        uint64_t replay = e->replay_off ? image_base + e->replay_off : 0;   // 0 = no-replay 桩
        // 注入校验：site 处必须是 BRK #0，否则说明二进制没打桩 / 版本不符
        uint32_t insn = *(volatile uint32_t *)site;
        bool patched = (insn == 0xD4200000u);
        bool ok = xrc_brk_register(site, replay, e->handler);
        if (ok) {
            int idx = atomic_load(&s_count) - 1;
            // 重复注册路径（idx 不变）时找 slot：register 内部已处理，这里只补名字
            for (int k = 0; k < atomic_load(&s_count); k++) {
                if (atomic_load(&s_slots[k].site) == site) { idx = k; break; }
            }
            if (!s_slots[idx].name) s_slots[idx].name = e->name;
        }
        xrc_logd(XRCLC_BRK, @"[brk] %s slot reg=%d site=%p(insn=%08X patched=%d) replay=%p",
                e->name, ok, (void *)site, insn, patched, (void *)replay);
    }
    // 配对标记 ①：自动演奏站点（ap_*）由本 dylib 处理；旧 dylib 无此表 → 注入脚本拒配。
    // ⚠ **必须纯 ASCII**：inject.py 按 UTF-8 原字节搜标记串；而含非 ASCII 的 @"..." 会被
    // clang 编成 UTF-16（CFString），字节层面搜不到 → 假阴性拒配。
    xrc_logi(XRCLC_BOOT, @"[brk] autoplay-eve v1 ready (mark=arc-consume/hold-held, finale-gate=1 allow, chain-guard; autoplay=%d)", (int)xrc_judge_autoplay());
    // 配对标记 ②：链进度覆盖桩（chain_prog，7.0 新增「链」系统的查表点）由本 dylib 处理；
    // 旧 dylib 命中该站点会重放原指令 → 崩因依旧，注入脚本据此拒配。此桩**不设开关、恒生效**。
    xrc_logi(XRCLC_BOOT, @"[brk] chain-guard v1 ready (chain_prog -> 100, always-on)");
    // 配对标记 ③：全条件放行族（lock_all/play_gate/cond_unlock_*/jacket_*/dl_play/pack_open/shutter_done）。
    // jacket_* 是 no-replay 条件分支桩（旧 dylib 无处理器时落兜底/默认陷阱）→ 注入脚本据此拒配。
    // v2→v3（2026-10-16）：新增 shutter_done（进歌在线检查等待）；旧 dylib 无该处理器 ⇒ 换代拒配。
    xrc_logi(XRCLC_BOOT, @"[brk] unlock-policy v3 ready (lock_all/play_gate/cond_unlock/jacket_* -> unlockAll; dl_play -> dlReady; pack_open/shutter_done -> gateOpen)");
    // 开关组（策略/plist 驱动）
    xrc_logi(XRCLC_BOOT, @"[brk] switches: own=%d fv=%d do=%d gate=%d all=%d dl=%d (slots=%d)",
            (int)atomic_load(&s_unlock_own), (int)atomic_load(&s_unlock_fv),
            (int)atomic_load(&s_unlock_do),  (int)atomic_load(&s_gate_open),
            (int)atomic_load(&s_unlock_all), (int)atomic_load(&s_dl_ready),
            atomic_load(&s_count));
#if XRC_DEBUG_BUILD
    xrc_brk_capture_enable(true);   // applog 明文/密文捕获（开发构建）
#endif
    xrc_brk_static_report(image_base);
}

void xrc_brk_setup_early(void) {
    // 在 %ctor 里调用：安装处理器 + 立即注册全部桩点。
    // 时序：cb 校验在 didFinishLaunching 前 ~0.5s 就有后台线程命中；注册若晚于命中，
    // 分发器空表 → 链给默认处理器 → EXC_BREAKPOINT 崩。注册与处理器安装必须同刻。
    xrc_brk_install();   // 幂等
    uint64_t mb = atomic_load(&s_main_base);
    if (mb) xrc_brk_setup(mb);
}

uint32_t xrc_brk_hits(int slot_index) {
    if (slot_index < 0 || slot_index >= atomic_load(&s_count)) return 0;
    return atomic_load(&s_slots[slot_index].hits);
}

int xrc_brk_slot_count(void) { return atomic_load(&s_count); }

const char *xrc_brk_slot_name(int slot_index) {
    if (slot_index < 0 || slot_index >= atomic_load(&s_count)) return "?";
    return s_slots[slot_index].name ? s_slots[slot_index].name : "?";
}

uint64_t xrc_brk_last_hit_us(int slot_index) {
    if (slot_index < 0 || slot_index >= atomic_load(&s_count)) return 0;
    return atomic_load(&s_slots[slot_index].last_us);
}

// 未注册桩位自愈报告：处理器里只写原子计数（保持 async-signal-safe），主线程读走记日志。
// >0 说明主程序与当前桩表不一致（含未注册桩），本次运行已就地还原；建议重新注入。
int xrc_brk_selfheal_count(void) { return atomic_load(&s_selfheal_hits); }
uint64_t xrc_brk_selfheal_last_off(void) { return atomic_load(&s_selfheal_last_off); }

#endif  // XRC_HAS_BRK_HOOK
