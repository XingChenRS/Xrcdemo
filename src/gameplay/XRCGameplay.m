// © 雾月星辰 & MLXC · github@XingChenRS
// XRCGameplay.m — gp.update hook + 谱面钟 retime + seek（含循环）。
// seek 平移 = 音频 seek + 谱面钟 base 平移（判定比较 |note - (cur - base)|，
// 所以 base -= (cur - target) 即整体平移）。
// 循环 / 重打 / 换歌的玩法语义见文件尾部「循环 / retry 回位」区块的注释。

#import <Foundation/Foundation.h>
#import "XRCLog.h"    // xrc_log
#include <limits.h>
#include <objc/runtime.h>
#include <sys/mman.h>
#include <errno.h>
#include <mach/vm_map.h>
#include <mach/mach_init.h>
#include "XRCGameplay.h"
#include "XRCRuntime.h"
#include "XRCProbe.h"
#include "XRCClock.h"
#include "XRCAudio.h"   // 音乐变速：每帧去重 tick（rate/组变了才动手）
#include "XRCPlayer.h"
#include "XRCProfile.h"

#if __has_include(<ptrauth.h>)
#  include <ptrauth.h>
#endif

_Atomic(void *) xrc_gp_instance = NULL;

static void (*s_orig_gp_update)(void *, uint64_t, uint64_t, uint64_t, uint64_t) = NULL;
static void *s_gp_last_clock = NULL;
static uint64_t s_gp_last_real_us = 0;
// retime 的两个分数余量：任何一环按整数截断，累积起来都会变成"越到后面越不同步"。
static uint64_t s_retime_rem_us = 0;    // 微秒→毫秒的余量
static double   s_retime_acc    = 0.0;  // (1−rate)·delta 的小数余量

// ---- deferred 操作状态机 ----
// 转场函数内部读 note_group+48（谱面钟），note_group 为 NULL 时 far=0x30 崩溃。
// 所有执行路径必须先做**两级非空校验**：
//   scene != NULL && *(scene + XRC_GP_NOTEGROUP_OFF) != NULL
// 且请求在场景指针变化（换场/重开）时自动作废——旧场景的请求在新场景上无意义。
static _Atomic(uint32_t) s_pending_op    = XRC_OP_NONE;
static _Atomic(uint32_t) s_pending_ms    = 0;
static _Atomic(uint64_t) s_pending_scene = 0;   // 登记请求时的 scene 指针
static _Atomic(uint64_t) s_last_exec_us  = 0;   // 冷却起点（真实时间 us）
#define XRC_OP_COOLDOWN_US  (1500 * 1000ULL)    // seek/回位冷却 1.5s
#define XRC_OP_MAX_IDLE_US  (4000 * 1000ULL)    // 请求超过 4s 未执行 → 丢弃

bool xrc_gameplay_request(xrc_op_t op, uint32_t param_ms) {
    void *scene = atomic_load(&xrc_gp_instance);
    if (!scene) {
        xrc_logd(XRCLC_JUDGE, @"request rejected: no live scene");
        return false;
    }
    uint32_t cur = atomic_load(&s_pending_op);
    if (cur != XRC_OP_NONE) {
        /* 同族（seek / 回位）后到者**覆盖**前项：拖动提交/循环回位在冷却窗口内
           可能连来两笔——若拒绝后到者，冷却结束后会按**旧目标**执行，把用户
           拉回上一个位置。最后一次意愿为准。 */
        if (op == XRC_OP_SEEK || op == XRC_OP_SEEK_REPLAY || op == XRC_OP_LOOP_REWIND) {
            atomic_store(&s_pending_scene, (uint64_t)scene);
            atomic_store(&s_pending_ms, param_ms);
            atomic_store(&s_pending_op, op);
            return true;
        }
        xrc_logd(XRCLC_JUDGE, @"request rejected: pending op=%u", cur);
        return false;
    }
    atomic_store(&s_pending_scene, (uint64_t)scene);
    atomic_store(&s_pending_ms, param_ms);
    atomic_store(&s_pending_op, op);
    return true;
}

// 两级非空校验：返回可用 note_group，否则 NULL。
static void *s_valid_note_group(void *scene) {
    if (!scene) return NULL;
    void *ng = *(void **)((char *)scene + XRC_GP_NOTEGROUP_OFF);
    if (!ng) return NULL;
    // 谱面钟必须可读（转场内部第一步就读 +48）
    void *clk = *(void **)((char *)ng + XRC_CLOCK_IN_NOTEGROUP_OFF);
    if (!clk) return NULL;
    return ng;
}



// ---- retry 监视器 ----
// 场景：开启循环或 seek 定位后，游戏中暂停 → Retry（引擎重建场景）。
// 判据：**音频位置的帧间大回跳**——retry 重建场景会让音频
// 从曲尾/当前点回到曲首（jump < -10s），单点演奏不可能产生。
// 触发后写一个 pending seek（目标=capture）；deferred 状态机在**新场景**的下一帧
// 才执行（旧场景已被 retry 销毁，同一帧不可用）。执行后解除（一次性）。
// 阈值说明：retry/换歌重建后音频必然从曲中/曲尾回到 0ms 附近，单点演奏的
// 帧间正常波动不可能超过 10 秒 → -10s 是"重建类事件"的可靠判据。
#define XRC_RETRY_AUDIO_JUMP_MS  (-10000)   // 音频帧间回跳阈值
static _Atomic(bool)     s_cap_valid = false;   // 音频基准是否已建立
static int32_t           s_prev_audio_ms = -1;
// **自家 seek 标记**。帧内时序（见下）：s_exec_pending 下完 seek 后，音频位置要到下一帧
// 才真的落位（真机实测："pos 25045 -> 25045" 立即读是旧值）⇒ watcher 在下一帧必然看到
// 一次大回落。没有这个标记，循环开着时会把它当成外部 retry 再补一次 seek；有标记则
// 只消账、不动作。
static _Atomic(uint64_t) s_own_seek_us = 0;
#define XRC_OWN_SEEK_WIN_US  (3000 * 1000ULL)   // 自家 seek 的豁免窗：3s

// 帧内调用（note_group 有效时）：音频位置回跳检测。
static void s_retry_watch_tick(void) {
    // 监视常开（回位点由"循环是否开启"在触发时刻决定）。
    int32_t pos = (int32_t)xrc_player_position_ms();
    if (pos < 0) return;
    if (!atomic_load(&s_cap_valid)) {
        s_prev_audio_ms = pos;
        atomic_store(&s_cap_valid, true);
        return;
    }
    int32_t jump = pos - s_prev_audio_ms;
    s_prev_audio_ms = pos;
    if (jump < XRC_RETRY_AUDIO_JUMP_MS) {
        // 先问「这一跳是不是我们自己 seek 出来的」——是则只消账，不动作。
        uint64_t own = atomic_load(&s_own_seek_us);
        if (own && xrc_real_now_us() - own < XRC_OWN_SEEK_WIN_US) {
            atomic_store(&s_own_seek_us, 0);
            xrc_logd(XRCLC_JUDGE, @"audio jump %d = 自家 seek（豁免，不外补）", jump);
            return;
        }
        // 手动 retry（或异常回跳）回位：**仅循环开启时**回 A 点。
        // 未开循环 = 不干预（不得锁到任何残留位置）。
        uint32_t a = 0, b = 0;
        xrc_loop_get_range(&a, &b);
        if (xrc_loop_get_enabled() && b > a + 1000) {
            if (xrc_gameplay_request(XRC_OP_SEEK, a)) {
                xrc_logd(XRCLC_JUDGE, @"retry detected (audio jump %d) -> seek loop A %u", jump, a);
            }
        } else {
            xrc_logd(XRCLC_JUDGE, @"audio jump %d ignored (loop off)", jump);
        }
    }
}

// ---- 冻结式 seek（外部参考实现统一时钟模型落地）----
// 设计全链（含反编译证据）：内部设计纪要（离线记录）
// 事务：暂停音频 → 音频 seek → 钟 base 平移 → 重置链在冻结窗内跑完（世界冻住：无声 + 钟被
// 每帧钉住，无竞态、无“卡顿”感知）→ xrc_freeze_end 收口 → 以实测音频位置再写
// 一次 → 收敛窗 → 恢复音频。冻结期 stall 监视豁免。
#define XRC_FRZ_OFF     0
#define XRC_FRZ_FROZEN  1
#define XRC_FRZ_RESYNC  2
#define XRC_FRZ_MAX_US   (1500 * 1000ULL)   // 1.5s 强制解冻兜底（**按时间**：帧数兜底不可靠——
                                            // 引擎追赶循环一次可调数百遍 gp.update，"90 帧"194ms 就烧完）
#define XRC_RESYNC_US    (60 * 1000ULL)     // 收敛窗 ≈60ms（外部参考实现=2 帧@60fps≈33ms，多留余量）
static _Atomic(int) s_frz_state  = 0;
static _Atomic(int) s_frz_target = 0;
static _Atomic(uint64_t) s_frz_deadline_us = 0;

static inline int32_t xrc_sat_add32(int32_t a, int32_t b) {
    int64_t v = (int64_t)a + b;
    if (v > 2147483647LL) return 2147483647;
    if (v < (-2147483647LL - 1)) return (-2147483647 - 1);
    return (int32_t)v;
}

// **定位写法必须用 base 平移**（唯一经充分验证的写）。时钟字段是引擎**自己连续时钟域**
// 的时间戳（真机 base≈310,164,256ms，与系统 uptime 不同域——含睡眠计时）；跨域直接写
// （+16/+32/+52）会触发引擎重归一化，把 (base, +32) 拆散 ⇒ 读法爆炸 ⇒ 超过曲长 ⇒
// 引擎立即收歌。**+3000 常数背后是整个域约定，不可只抄数字。**
// base 平移天然域无关：只加「同域两个量的差」，不引入任何跨域常数。
static void xrc_clock_shift_to(void *note_group, int32_t target) {
    if (!note_group) return;
    void *clk = *(void **)((char *)note_group + XRC_CLOCK_IN_NOTEGROUP_OFF);
    if (!clk) return;
    int32_t cur = xrc_chart_clock_ms(note_group);
    int32_t *base_off = (int32_t *)((char *)clk + XRC_CLK_BASE_OFF);
    *base_off = xrc_sat_add32(*base_off, xrc_sat_add32(cur, -target));
}

// 冻结窗收口（重建链末尾调用；时间兜底在 s_frz_tick）。
// 顺序照搬 外部参考实现 finish_scrub：先以当前（暂停中的）落位平移一次 → 恢复音频 → 进收敛窗。
// 落位守卫：暂停期间游戏不调 getpos，位置缓存可能还是旧值（如 61952 vs target 44992）——
// 把这笔 stale 平移进钟会弹回高位 ⇒ 循环 tick 二度触发 ⇒ **AB 循环多跳一次**。
// 超窗就不平移，交给收敛窗（音频恢复后缓存随即刷新）落位。
void xrc_freeze_end(void) {
    if (atomic_load(&s_frz_state) != XRC_FRZ_FROZEN) return;   // 幂等
    void *scene = atomic_load(&xrc_gp_instance);
    void *ng = scene ? *(void **)((char *)scene + XRC_GP_NOTEGROUP_OFF) : NULL;
    int32_t tgt = atomic_load(&s_frz_target);
    if (ng) {
        int32_t pos = (int32_t)xrc_player_position_ms();
        if (pos < 0) pos = 0;
        int32_t d = pos - tgt;
        if (d < 0) d = -d;
        if (d <= 5000) {
            xrc_clock_shift_to(ng, pos);
        } else {
            xrc_logd(XRCLC_JUDGE, @"冻结窗收口：pos=%d 未落位（target=%d）——本次不平移，交给收敛窗", pos, tgt);
        }
    }
    xrc_player_pause_hold(false);   /* 持有计数释放：面板「练习暂停」仍持有时不恢复音频 */
    xrc_clock_freeze_dec();
    atomic_store(&s_frz_deadline_us, xrc_real_now_us() + XRC_RESYNC_US);
    atomic_store(&s_frz_state, XRC_FRZ_RESYNC);
    xrc_logd(XRCLC_JUDGE, @"冻结窗收口：恢复音频，进入收敛窗");
}

// 每帧（gp.update，主线程）：冻结窗钉钟 / 收敛窗按实测音频位置拉回。
static void s_frz_tick(void *note_group) {
    int st = atomic_load(&s_frz_state);
    if (st == XRC_FRZ_OFF) return;
    if (!note_group) {
        xrc_player_pause_hold(false);
        xrc_clock_freeze_dec();
        atomic_store(&s_frz_state, XRC_FRZ_OFF);
        return;
    }
    uint64_t now_us = xrc_real_now_us();
    if (st == XRC_FRZ_FROZEN) {
        xrc_clock_shift_to(note_group, atomic_load(&s_frz_target));   // 钉住
        if (now_us > atomic_load(&s_frz_deadline_us)) {
            xrc_logd(XRCLC_JUDGE, @"冻结窗：**兜底解冻**（超 %.1fs 未见重置收口）",
                     (double)XRC_FRZ_MAX_US / 1e6);
            xrc_freeze_end();
        }
    } else if (st == XRC_FRZ_RESYNC) {
        int32_t pos = (int32_t)xrc_player_position_ms();
        if (pos < 0) pos = 0;
        // 未落位守卫：音频 seek 失败/未生效时 pos 仍是旧位置 —— 平移下去会把钟拉回旧处，
        // 反而制造一次假回跳。仅当 pos 已接近本次目标（±5s）才跟随。
        int32_t tgt = atomic_load(&s_frz_target);
        int32_t dpos = pos - tgt;
        if (dpos < 0) dpos = -dpos;
        if (dpos <= 5000) xrc_clock_shift_to(note_group, pos);
        // 软截止（60ms）后**落位即收**（≤300ms 差）；未落位最多再等 600ms 兜底。
        uint64_t ddl = atomic_load(&s_frz_deadline_us);
        if (now_us > ddl && (dpos <= 300 || now_us > ddl + 600000ULL)) {
            s_prev_audio_ms = (int32_t)xrc_player_position_ms();
            atomic_store(&s_cap_valid, true);
            atomic_store(&s_frz_state, XRC_FRZ_OFF);
            xrc_logd(XRCLC_JUDGE, @"收敛窗结束：pos=%d（target=%d，%s）", pos, tgt,
                     dpos <= 300 ? "已落位" : "超时未落位");
        }
    }
}

// XRCReplay 导出（暂停驻停提交用）
extern void xrc_replay_request_reset(uint32_t T);

#pragma mark - 练习暂停 / 拖动 seek

// 练习暂停（面板开 = 暂停）：音频持有计数 + warp 冻结计数的组合。
// 语义与边界（细粒度排查见 research/notes/ios-panel-pause-seek-interplay-2026-10-11.md）：
//   · 与 seek 冻结窗**可共存**：两边各持一份音频 hold 与 freeze 计数，互不误解除；
//   · 暂停期间循环 tick 抑制（s_practice_paused 门控在 xrc_gameplay_update 里）——
//     拖动浏览越过了 B 点也不会被自动回位打断；
//   · 卡死监视/retry 监视天然豁免（钟静止=暂停态；自家 seek 有 own-seek 标记）；
//   · retime 在冻结计数>0 时自动跳过（暂停不该被 retime 补差）。
static _Atomic(int)      s_practice_paused = 0;
static _Atomic(uint32_t) s_scrub_ms   = 0;
static _Atomic(int)      s_scrub_pend = 0;
static _Atomic(uint64_t) s_scrub_us   = 0;      // 最近一次拖动落笔（真实时间）
// 暂停期间的「谱面钟钉点」：warp 冻结管不住谱面钟的推进（v10 冻结窗的钉住同样靠
// 每帧 base 平移实现）——暂停期间每帧把钟平移回 pin，拖动落笔即更新 pin。
static _Atomic(int32_t)  s_pin_ms    = 0;
static _Atomic(int)      s_pin_valid = 0;

void xrc_gameplay_pause(bool on) {
    int prev = atomic_exchange(&s_practice_paused, on ? 1 : 0);
    if (prev == (on ? 1 : 0)) return;                     /* 幂等 */
    if (on) {
        atomic_store(&s_pin_valid, 0);            // 首帧由 s_pause_tick 取当前钟值作 pin
        xrc_player_pause_hold(true);
        xrc_clock_freeze_inc();
        xrc_logd(XRCLC_JUDGE, @"练习暂停：开（音频 hold + 钟冻结，freeze=%d）",
                 xrc_clock_freeze_count());
    } else {
        xrc_clock_freeze_dec();
        xrc_player_pause_hold(false);
        xrc_logd(XRCLC_JUDGE, @"练习暂停：关（钟解冻 + 音频 hold 释放）");
    }
}

uint64_t xrc_gameplay_scrub_us(void) { return atomic_load(&s_scrub_us); }

// 拖动 seek 受理（UI 线程只登记；落笔在下一帧 gp.update，与游戏 tick 串行）。
bool xrc_gameplay_scrub(uint32_t ms) {
    if (!atomic_load(&xrc_gp_instance)) return false;
    /* 拖动 = 冻结的不变量：受理即确保暂停（幂等）。调用方（面板三段式）在按下时
       已调 pause(true)；这里是防未来调用方漏调的第一道保险——拖动绝不能在
       "播放中"发生（步进的钟平移会让引擎把路过的音符逐个判成 LOST）。 */
    if (!atomic_load(&s_practice_paused)) xrc_gameplay_pause(true);
    atomic_store(&s_scrub_ms, ms);
    atomic_store(&s_scrub_pend, 1);
    return true;
}

// 拖动落笔（gp.update 内、s_exec_pending 之前）：轻量「音频 seek + base 平移」。
// 不开冻结窗、不触发重播、不受冷却/去抖限制——每帧至多一笔，UI 无需节流。
static void s_scrub_tick(void *self) {
    if (!atomic_load(&s_scrub_pend)) return;
    atomic_store(&s_scrub_pend, 0);
    if (atomic_load(&s_frz_state)) return;      /* 事务进行中：本次忽略，下一次移动即恢复 */
    uint32_t ms = atomic_load(&s_scrub_ms);
    void *ng = s_valid_note_group(self);
    if (!ng) return;
    int32_t cur = xrc_chart_clock_ms(ng);
    if (cur < 0) return;                        /* 前导/加载中：拖动无意义 */
    uint32_t dur = xrc_player_song_length_ms();
    if (dur && ms > dur) ms = dur;
    void *player = xrc_player_get();
    if (player) {
        xrc_player_seek_ms(player, ms);
        atomic_store(&s_own_seek_us, xrc_real_now_us());   /* retry 监视豁免 */
    }
    xrc_clock_shift_to(ng, (int32_t)ms);
    atomic_store(&s_pin_ms, (int32_t)ms);
    atomic_store(&s_pin_valid, 1);
    s_gp_last_real_us = 0;                      /* 钟被移动：retime 基准作废 */
    atomic_store(&s_scrub_us, xrc_real_now_us());
}

// ---- 暂停护栏（练习暂停期间的引擎判定总闸 + 路过跳过 + 冻结看护）----
// 机制出处（sub_10091BC44 反汇编，.idamcp/_c70_10091BC44.c；偏移登记见 XRCProfile.h）：
//   · L209：`if(!(ng+312&1)) { if(!(ng+313&1)) sub_10091D2F4; sub_10091D9A0; }`
//     ⇒ ng+312 bit0 = 「判定 + 自动漏扫」块总闸；入场/位置刷新（L183 sub_10091C47C）
//     无门控 ⇒ 关闸不影响拖动预览。
//   · 为什么必须关：拖动把谱面钟按步平移，引擎每帧在**新位置**上跑「入场＋漏扫」——
//     每步刚入场的音符 end < cur，会被漏扫当场判 LOST（冻结时特效计时不走，
//     判定文字不会自行消退）。312 无运行期写者 ⇒ 断言写 1 安全；
//     仍按「保存-恢复 + 每帧断言 + 防场景重建（换 ng）」的纪律处理。
//   · 路过跳过：暂停期间把**窗口内已越过的未消费音符**按引擎自己的快进语义标记
//     "跳过"（vtable idx7 = 写 note+0x0C=1；引擎快进 sub_1009204E4 同款调用）——
//     否则恢复播放瞬间会对被"路过"的音符补一波 miss。排除 SceneControl（谱面命令，
//     标它不是"跳过"是"吞指令"）。
//   · 冻结看护：驻停期间冻结计数被扣减到 0 时当场补回并留痕——冻结与音频持有
//     必须成对（谱面静止期间两者任何一方脱钩都会破坏音画一致）。
typedef int  (*s_pj_f5_t)(uint64_t note);
typedef void (*s_pj_f7_t)(uint64_t note, uint64_t v);

static _Atomic(uint64_t) s_pj_ng    = 0;    // 已被施写 312 的 note 组
static uint8_t           s_pj_saved = 0;    // 首见时的 312 原值
static int               s_pj_marked;       // 诊断：累计"路过跳过"标记数

static bool s_pj_isptr(uint64_t v) { return v >= 0x100000000ULL && v < 0x7000000000ULL; }
static bool s_pj_ishp(uint64_t v)  { return s_pj_isptr(v) && (v & 7) == 0; }

// 只对"即将标记"的候选做类名检查（低频）：LogicSceneControl 不标。
static bool s_pj_is_scenecontrol(uint64_t vt) {
    uint64_t ti = 0, nm = 0;
    if (!s_pj_isptr(vt)) return false;
    memcpy(&ti, (void *)(vt - 8), 8);
    if (!s_pj_isptr(ti)) return false;
    memcpy(&nm, (void *)(ti + 8), 8);
    if (!s_pj_isptr(nm)) return false;
    char buf[64];
    memcpy(buf, (void *)nm, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;
    for (int i = 0; i < (int)sizeof(buf); i++) {
        char c = buf[i];
        if (!c) break;
        if (c < 0x20 || c > 0x7e) { buf[i] = 0; break; }
    }
    return strstr(buf, "SceneControl") != NULL;
}

static void s_pause_pass_skip_tick(uint64_t ng, int32_t cur) {
    uint64_t b = 0, e = 0;
    memcpy(&b, (void *)(ng + 0xA0), 8);   // 活动窗口（与 XRCReplay 的 RPF_VEC_BEGIN 同源）
    memcpy(&e, (void *)(ng + 0xA8), 8);
    if (!s_pj_ishp(b) || !s_pj_ishp(e) || e < b || (e - b) > 0x100000) return;
    for (uint64_t p = b; p < e; p += 8) {
        uint64_t note = 0;
        memcpy(&note, (void *)p, 8);
        if (!s_pj_ishp(note)) continue;
        int32_t te = 0;
        memcpy(&te, (void *)(note + 0x1C), 4);
        if (te == 0 || (int64_t)cur - (int64_t)te <= 100) continue;   // 未越过终点
        uint64_t vt = 0;
        memcpy(&vt, (void *)note, 8);
        if (!s_pj_ishp(vt)) continue;
        uint64_t f5 = 0, f7 = 0;
        memcpy(&f5, (void *)(vt + 40), 8);
        memcpy(&f7, (void *)(vt + 56), 8);
        if (!s_pj_isptr(f5) || !s_pj_isptr(f7)) continue;
        if (s_pj_is_scenecontrol(vt)) continue;
        if (((s_pj_f5_t)f5)(note) & 1) continue;                      // 已消费：跳过
        ((s_pj_f7_t)f7)(note, 1);
        s_pj_marked++;
    }
}

// 每帧（gp.update、note_group 有效、先于引擎 tick）：
static void s_pause_tick(void *ngp) {
    uint64_t ng = (uint64_t)ngp;
    if (atomic_load(&s_practice_paused)) {
        if (atomic_load(&s_pj_ng) != ng) {           // 首见（或场景重建换 ng）：记录原值
            atomic_store(&s_pj_ng, ng);
            s_pj_saved = *(uint8_t *)((char *)ng + XRC_NG_JUDGE_GATE_OFF);
        }
        uint8_t g = *(uint8_t *)((char *)ng + XRC_NG_JUDGE_GATE_OFF);
        if (!(g & 1)) *(uint8_t *)((char *)ng + XRC_NG_JUDGE_GATE_OFF) = (uint8_t)(g | 1);
        int32_t cur = xrc_chart_clock_ms(ngp);
        /* **钟钉**：暂停期间每帧把谱面钟平移回 pin（warp 冻结之外的第二道，也是真正
           管住谱面钟的一道——拖动不松手时"播放一小段再回跳"即缺它所致）。 */
        if (cur >= 0) {
            if (!atomic_load(&s_pin_valid)) {
                atomic_store(&s_pin_ms, cur);      // 首帧取当前值
                atomic_store(&s_pin_valid, 1);
                xrc_logd(XRCLC_JUDGE, @"练习暂停：钟钉住 pin=%d（freeze=%d）",
                         cur, xrc_clock_freeze_count());
            } else {
                int32_t pin = atomic_load(&s_pin_ms);
                if (cur != pin) xrc_clock_shift_to(ngp, pin);
                cur = pin;
            }
        }
        if (cur >= 0) s_pause_pass_skip_tick(ng, cur);
        /* 驻停看护：冻结计数归零即当场补回（日志上方 [clock] freeze 行可点名来源） */
        if (!atomic_load(&s_frz_state) && xrc_clock_freeze_count() == 0) {
            xrc_logw(XRCLC_JUDGE, @"[clock] 驻停冻结计数被扣到 0——当场补回（见上方 freeze 日志）");
            xrc_clock_freeze_inc();
        }
    } else {
        uint64_t old = atomic_exchange(&s_pj_ng, 0);
        if (old && old == ng) {
            /* 关闸前收尾：先补一遍路过跳过（覆盖最后一帧的入场），再恢复 312 */
            int32_t cur = xrc_chart_clock_ms(ngp);
            if (cur >= 0) s_pause_pass_skip_tick(ng, cur);
            uint8_t g = *(uint8_t *)((char *)ng + XRC_NG_JUDGE_GATE_OFF);
            if (g & 1) *(uint8_t *)((char *)ng + XRC_NG_JUDGE_GATE_OFF) = s_pj_saved;
            xrc_logd(XRCLC_JUDGE, @"暂停护栏解除：判定总闸还原（路过跳过累计 %d）", s_pj_marked);
        }
    }
}

bool xrc_gameplay_in_song(void) {
    return s_valid_note_group((void *)atomic_load(&xrc_gp_instance)) != NULL;
}

// 在游戏循环内执行 pending（self = 当前活场景）。
static void s_exec_pending(void *self) {
    uint32_t op = atomic_load(&s_pending_op);
    if (op == XRC_OP_NONE) return;

    uint64_t now = xrc_real_now_us();

    // 场景变更 → 丢弃陈旧请求（旧场景的 seek 在新场景无意义）
    uint64_t req_scene = atomic_load(&s_pending_scene);
    if (req_scene != (uint64_t)self) {
        atomic_store(&s_pending_op, XRC_OP_NONE);
        xrc_logd(XRCLC_JUDGE, @"pending op=%u dropped (scene changed %llx -> %p)", op, req_scene, self);
        return;
    }

    uint64_t last = atomic_load(&s_last_exec_us);
    if (last && now - last < XRC_OP_COOLDOWN_US) return;  // 冷却中

    // 过期丢弃
    static uint64_t s_req_time = 0;
    if (s_req_time == 0) s_req_time = now;
    if (now - s_req_time > XRC_OP_MAX_IDLE_US) {
        atomic_store(&s_pending_op, XRC_OP_NONE);
        s_req_time = 0;
        return;
    }

    uint32_t ms = atomic_load(&s_pending_ms);

    // 执行前最终校验（崩溃 guard）
    void *note_group = s_valid_note_group(self);
    if (!note_group) {
        xrc_logd(XRCLC_JUDGE, @"pending op=%u aborted: note_group/clock null (scene=%p)", op, self);
        atomic_store(&s_pending_op, XRC_OP_NONE);
        return;
    }

    atomic_store(&s_pending_op, XRC_OP_NONE);   // 先清（防执行内重入）
    atomic_store(&s_last_exec_us, now);
    s_req_time = 0;

    if (op == XRC_OP_SEEK || op == XRC_OP_SEEK_REPLAY || op == XRC_OP_LOOP_REWIND) {
        int32_t cur_ms = xrc_chart_clock_ms(note_group);

        /* 前导期/加载中的 seek **整笔丢弃**：cur=-3000（新场景加载中）时执行 seek 会
           半生效 + 场景随即重建 ⇒ 卡死监视误判、1.5s 一次强拉、垃圾回落。前导期
           "找位置"本身无意义（歌还没开始）⇒ 丢弃是正确语义。 */
        if (cur_ms < 0) {
            xrc_logd(XRCLC_JUDGE, @"seek 丢弃：前导/加载中（cur=%d ms=%u）", cur_ms, ms);
            return;
        }

        // ① 去抖（外部参考实现 PRAC_7seek_to 的 16ms 窗）：同目标重复请求合并，防连击风暴。
        {
            static int32_t  s_dbd_ms = 0;
            static uint64_t s_dbd_us = 0;
            uint64_t nowu = xrc_real_now_us();
            int32_t d = (int32_t)ms - s_dbd_ms;
            if (d < 0) d = -d;
            if (op == XRC_OP_SEEK && d < 16 && nowu - s_dbd_us < 500000ULL) {
                xrc_logd(XRCLC_JUDGE, @"seek debounced: ms=%u（与上次目标同区，16ms 窗）", ms);
                return;
            }
            s_dbd_ms = (int32_t)ms;
            s_dbd_us = nowu;
        }
        // ② 曲长钳制（外部参考实现同款时长守卫）
        {
            uint32_t dur = xrc_player_song_length_ms();
            if (dur && ms > dur) ms = dur;
        }
        // ③ 方向判定：回退幅度超过快路径检测阈（300ms）⇒ 预期触发回跳重置 ⇒ 全程冻结。
        // **练习暂停（拖动会话/驻停）期间跳过冻结窗**：钟已被暂停钉住、音频已被 hold，
        // 再开窗只会多一层计数与收敛窗扰动；重播事务由提交侧显式触发（见下）。
        int frz = ((cur_ms - (int32_t)ms) > 300) && !atomic_load(&s_practice_paused);

        // 音频 seek（player 可能已换歌，重新取）
        void *player = xrc_player_get();
        if (!player) frz = 0;    // 没有播放器就不进冻结窗（否则 freeze_inc/dec 配不平）
        if (player) {
            int32_t pos_before = (int32_t)xrc_player_position_ms();
            if (frz) {
                xrc_clock_freeze_inc();          // 停 retime（它写 base）
                xrc_player_pause_hold(true);     // 音频暂停（持有计数：与面板「练习暂停」共存，见头文件）
            }
            xrc_player_seek_ms(player, ms);
            /* 给 watcher 记一笔「这一跳是我们自己干的」（音频下一帧才落位，
               落位时 watcher 必然看到大回落 —— 见 s_own_seek_us 注释）。 */
            atomic_store(&s_own_seek_us, xrc_real_now_us());
            int32_t pos_after = (int32_t)xrc_player_position_ms();
            xrc_logd(XRCLC_JUDGE, @"audio seek: target=%u, pos %d -> %d（%s）", ms, pos_before, pos_after,
                     frz ? "回退→冻结" : "前进→导航");
        } else {
            xrc_logd(XRCLC_JUDGE, @"audio seek SKIPPED: player null (target=%u)", ms);
        }
        // 定位用 **base 平移**（唯一验证过的写；理由见 xrc_clock_shift_to 注释）。
        // 前导期已在上面闸门整笔丢弃 ⇒ 这里 cur≥0。
        xrc_clock_shift_to(note_group, (int32_t)ms);
        s_gp_last_real_us = 0;

        if (frz) {
            atomic_store(&s_frz_target, (int32_t)ms);
            atomic_store(&s_frz_deadline_us, xrc_real_now_us() + XRC_FRZ_MAX_US);
            atomic_store(&s_frz_state, XRC_FRZ_FROZEN);
            xrc_logd(XRCLC_JUDGE, @"seek executed: ms=%u (cur was %d)｜冻结窗开（等重置链收口/1.5s 兜底）",
                     ms, cur_ms);
        } else {
            // 前进/近距：纯导航 —— 无冻结无收敛窗（绝对写已就位；音频将精确落在 target）。
            xrc_logd(XRCLC_JUDGE, @"seek executed: ms=%u (cur was %d)｜导航", ms, cur_ms);
        }
    }

    if (op == XRC_OP_SEEK_REPLAY) {
        /* 暂停驻停提交：**显式触发**重播事务——暂停态下钟不再动，自动检出要等
           拖动豁免窗（500ms）过期且依赖时序，慢且脆；这里直接走同一入口，
           并由 xrc_replay_request_reset 把水位线消化到 T（防检出双触发）。 */
        xrc_replay_request_reset(ms);
        xrc_logd(XRCLC_JUDGE, @"replay commit (paused park): T=%u", ms);
    } else if (op == XRC_OP_LOOP_REWIND) {
        // 音频基准不在这里对齐（seek 后立即读是旧值）；冻结窗/收敛窗收口时已对齐。
        xrc_logd(XRCLC_JUDGE, @"replay executed via seek (op=%u)", op);
    }
}

// ---- vtable swizzle（PAC 感知）----
int xrc_swizzle_vtable(uint64_t vtable_addr, uint64_t orig_fn_off, void *new_fn, void **out_orig) {
    extern uint64_t xrc_image_base(void);
    uint64_t base = xrc_image_base();
    if (!base) return INT_MIN;
    uint64_t target = base + orig_fn_off;
    void **vt = (void **)vtable_addr;
    // 同 6.13：地址合理性检查 + [-4, 64) 槽搜索
    if ((uintptr_t)vt < 0x100000000ULL || ((uintptr_t)vt & 7) != 0) return INT_MIN;
    for (int i = 0; i < 200; i++) {
        void *cur = vt[i];
        if (!cur) continue;
#if __has_feature(ptrauth_calls)
        void *stripped = ptrauth_strip(cur, ptrauth_key_asia);
#else
        void *stripped = cur;
#endif
        if ((uint64_t)stripped != target) continue;
        uintptr_t page = (uintptr_t)&vt[i] & ~(uintptr_t)0x3FFF;
        bool wrote = false;
        if (mprotect((void *)page, 0x4000, PROT_READ | PROT_WRITE) == 0) {
            wrote = true;
        } else {
            kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)page, 0x4000,
                                          0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
            wrote = (kr == KERN_SUCCESS);
        }
        if (!wrote) return INT_MIN;
        if (out_orig) *out_orig = stripped;
#if __has_feature(ptrauth_calls)
        void *signed_new = ptrauth_sign_unauthenticated(new_fn,
                              ptrauth_key_asia,
                              ptrauth_blend_discriminator(&vt[i], 0));
        vt[i] = signed_new;
#else
        vt[i] = new_fn;
#endif
        mprotect((void *)page, 0x4000, PROT_READ);
        return i;
    }
    return INT_MIN;
}

// ---- 谱面钟 ----
int32_t xrc_chart_clock_ms(void *note_group) {
    if (!note_group) return -1;
    void *clk = *(void **)((char *)note_group + XRC_CLOCK_IN_NOTEGROUP_OFF);
    if (!clk) return -1;
    if (*(uint8_t *)((char *)clk + XRC_CLK_FLAG45_OFF) & 1)
        return *(int32_t *)((char *)clk + XRC_CLK_ALT_START_OFF) - *(int32_t *)((char *)clk + XRC_CLK_BASE_OFF);
    int32_t v = *(int32_t *)((char *)clk + XRC_CLK_CUR_OFF);
    int32_t off = (v <= 0) ? XRC_CLK_NEG_LEAD_MS : 0;
    return v - *(int32_t *)((char *)clk + XRC_CLK_BASE_OFF) + off;
}

// ---- gp.update retime（6.13 语义）----
static void s_gp_retime_logic_clock(void *note_group) {
    if (!note_group) return;
    if (xrc_clock_freeze_count() > 0) return;
    void *clk = *(void **)((char *)note_group + XRC_CLOCK_IN_NOTEGROUP_OFF);
    if (!clk) return;
    uint64_t now_us = xrc_real_now_us();
    if (!now_us) return;
    if (clk != s_gp_last_clock || s_gp_last_real_us == 0 || now_us <= s_gp_last_real_us) {
        s_gp_last_clock = clk;
        s_gp_last_real_us = now_us;
        s_retime_rem_us = 0;      // 换钟/时间回退：余量作废，否则会把旧增量带进新歌
        s_retime_acc = 0.0;
        return;
    }
    uint64_t delta_us = now_us - s_gp_last_real_us;
    if (delta_us > 200000ULL) delta_us = 200000ULL;
    s_gp_last_real_us = now_us;
    // 微秒→毫秒也要带余量：60fps 的 16667µs 直接截成 16ms，每秒少 40µs×60 = 2.4ms 基准。
    uint64_t acc_us = delta_us + s_retime_rem_us;
    int32_t delta_ms = (int32_t)(acc_us / 1000ULL);
    s_retime_rem_us = acc_us % 1000ULL;
    if (delta_ms <= 0) return;
    double rate = xrc_clock_get_rate();
    int32_t adjust = 0;
    if (rate < 0.999 || rate > 1.001) {
        // 分数部分必须累积：逐帧截断是有系统性偏差的。
        // 60fps 时 delta_ms 被截成 16（真值 16.67），rate=0.8 每帧要补 3.33ms，
        // 截断后只补 3ms —— 每帧少 0.33ms，一秒就是 20ms，三分钟的歌累计漂 3.6 秒。
        // 这就是系统性漂移的来源。
        s_retime_acc += (1.0 - rate) * (double)delta_ms;
        adjust = (int32_t)s_retime_acc;
        s_retime_acc -= (double)adjust;
    }
    if (adjust == 0) return;
    int32_t *base_off = (int32_t *)((char *)clk + XRC_CLK_BASE_OFF);
    int64_t after = (int64_t)(*base_off) + (int64_t)adjust;
    if (after > INT_MAX) after = INT_MAX;
    if (after < INT_MIN) after = INT_MIN;
    *base_off = (int32_t)after;
}

uint64_t xrc_gameplay_instance(void) { return (uint64_t)atomic_load(&xrc_gp_instance); }

// ---- 音画倍率自测（1 Hz，只读）----
// 变速有**两条独立通路** —— ① gettimeofday fishhook 把"游戏看到的
// 墙上时间"按 rate 缩放（管视觉/Cocos 逻辑），② gp.update 里对谱面钟 base_off 的
// 累积 retime（管音符时序）。若游戏自身的钟也走被 warp 的时间域，两者就会**叠加**，
// 谱面实际倍率变成 2·rate−1，而音频（FMOD 自有音频钟）仍是 rate —— 这就是
// "音画倍率不同步"。日志里把 设定值 / 谱面实际斜率 / 音频实际斜率 一起打出来，
// 直接看出是哪条路多算或少算。
static void s_rate_probe_tick(void *note_group) {
    static uint64_t last_us = 0;
    static int32_t  last_chart = 0;
    static uint32_t last_chan = 0;
    static int      have = 0;
    uint64_t now = xrc_real_now_us();
    if (!now || now - last_us < 1000000ULL) return;
    int32_t  chart = xrc_chart_clock_ms(note_group);
    uint32_t chan  = xrc_player_position_ms();
    double   rate  = xrc_clock_get_rate();
    if (have && chart >= 0 && last_chart >= 0) {
        double dt     = (double)(now - last_us) / 1000000.0;
        double dchart = (double)(chart - last_chart) / 1000.0;
        double dchan  = (double)((int32_t)chan - (int32_t)last_chan) / 1000.0;
        xrc_logd(XRCLC_BOOT, @"[rate] set=%.3f 谱面×%.3f 音频×%.3f (Δt=%.2fs)",
                 rate, dchart / dt, dchan / dt, dt);
    }
    last_us = now; last_chart = chart; last_chan = chan; have = 1;
}

void xrc_gameplay_update(void *self, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    if (self) {
        atomic_store(&xrc_gp_instance, self);
        void *note_group = *(void **)((char *)self + XRC_GP_NOTEGROUP_OFF);
        if (note_group) {
            s_pause_tick(note_group);      // 暂停护栏（判定总闸/路过跳过/冻结看护）
            s_gp_retime_logic_clock(note_group);
            s_rate_probe_tick(note_group);      // 音画倍率自测（1 Hz，只读）
            int32_t pos = xrc_chart_clock_ms(note_group);
            // 冻结/收敛窗内钟不是真实播放时间（钉住/落位中）——循环 tick 抑制，
            // 防事务中间态二次触发回跳（收口缺守卫会把钟弹回旧位 → 循环二跳）。
            // 练习暂停（面板开）期间同样抑制：拖动浏览越过 B 点不应被自动回位打断。
            if (pos > 0 && !atomic_load(&s_frz_state) && !atomic_load(&s_practice_paused))
                xrc_loop_tick(self, (uint32_t)pos);
        }
        s_scrub_tick(self);     // 拖动 seek 落笔（轻量对齐；先于常规 deferred 操作）
        s_exec_pending(self);   // deferred 操作（seek/循环回位）在活场景循环内执行

        // retry 监视（音频回跳）；循环卡死恢复。
        if (note_group) {
            s_frz_tick(note_group);   // 冻结窗钉钟 / 收敛窗按实测音频位置拉回
            s_retry_watch_tick();
            // 循环卡死恢复：pos 停滞超 1.5s 且位于 [A,B) 内 → 强制回 A
            int32_t pos = xrc_chart_clock_ms(note_group);
            static int32_t s_stall_pos = 0;
            static int32_t s_stall_audio_prev = -1;
            static uint64_t s_stall_audio_us = 0;    /* 音频最近一次变化的时间 */
            static uint64_t s_stall_since = 0;
            uint64_t now_us = xrc_real_now_us();
            {
                int32_t apos = (int32_t)xrc_player_position_ms();
                if (apos != s_stall_audio_prev) { s_stall_audio_prev = apos; s_stall_audio_us = now_us; }
            }
            if (atomic_load(&s_frz_state)) {
                // 冻结窗内钟是**故意钉住**的（停滞是预期行为）——监视豁免，
                // 防冻结满 1.5s 时误触发一次「卡死回绕」。
                s_stall_pos = pos;
                s_stall_since = now_us;
            } else if (pos != s_stall_pos) {
                s_stall_pos = pos;
                s_stall_since = now_us;
            } else if (now_us - s_stall_audio_us > 700000ULL) {
                // 钟静止但**音频 ≥0.7s 没动** ⇒ 暂停菜单/加载冻结，不是卡死——不计时。
                // （判据必须用「音频最后一次变化距今」，不能用帧间比较——音频缓存本身就是
                //   跳变更新的，帧间比较会把真实卡死误判成暂停、计时器永远攒不起来。）
                s_stall_since = now_us;
            } else if (s_stall_since && now_us - s_stall_since > 1500000ULL) {
                uint32_t a = 0, b = 0;
                xrc_loop_get_range(&a, &b);
                if (xrc_loop_get_enabled() && pos < (int32_t)b - 200) {
                    if (xrc_gameplay_request(XRC_OP_LOOP_REWIND, a))
                        xrc_logd(XRCLC_JUDGE, @"loop stall at %d -> forced rewind to %u", pos, a);
                }
                s_stall_since = now_us;
            }
        }
    }
    // 音乐变速：低频去重 tick —— 速度变了/换歌了/组刚建才动作。
    // 放这里是因为 gp.update 是唯一"进对局后每帧都在跑"的点，面板不开时也有效。
    @try { xrc_audio_speed_tick(); } @catch (NSException *e) {}
    if (s_orig_gp_update) s_orig_gp_update(self, a2, a3, a4, a5);
}

void xrc_gameplay_install_hooks(uint64_t image_base) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        if (!g_xrc.gp_vtable || !g_xrc.gp_update) {   // 锚点未就绪 → 降级（记日志）
            xrc_logd(XRCLC_JUDGE, @"gp hooks skipped: anchor not ready (vtable=%llx update=%llx)",
                    g_xrc.gp_vtable, g_xrc.gp_update);
            return;
        }
        int slot = xrc_swizzle_vtable(g_xrc.gp_vtable,
                                      g_xrc.gp_update - g_xrc.image_base,
                                      (void *)xrc_gameplay_update,
                                      (void **)&s_orig_gp_update);
        if (slot != INT_MIN) xrc_logd(XRCLC_JUDGE, @"gp.update vtable installed slot=%d", slot);
    });
}

// ---------------- 游戏主循环模式升级（面板滚动期间谱面不再冻结）----------------
// 机制：UIKit 在 UIScrollView 拖动期间把主 runloop 切到 UITrackingRunLoopMode，
// 注册在 default 模式的 CADisplayLink 停摆 ⇒ 整个游戏循环（谱面）冻结，而 FMOD
// 音频在独立线程继续播——两个体征合起来即"滑动面板：谱面停、音乐不停"。
// 做法：把 CADisplayLink 的 addToRunLoop:forMode: 一律升级注册到 common modes
//（含 tracking）——滚动期间游戏照常跑，音画一致；注册时打一行日志留痕。
static IMP s_orig_add_to_runloop = NULL;
static void s_cadl_add_common(id self_, SEL _cmd, NSRunLoop *rl, NSString *mode) {
    xrc_logi(XRCLC_BOOT, @"[boot] CADisplayLink addToRunLoop: %@ → common modes", mode);
    ((void (*)(id, SEL, NSRunLoop *, NSString *))s_orig_add_to_runloop)(self_, _cmd, rl,
                                                                        NSRunLoopCommonModes);
}

void xrc_gameplay_displaylink_common_install(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        Class c = NSClassFromString(@"CADisplayLink");
        SEL sel = NSSelectorFromString(@"addToRunLoop:forMode:");
        Method m = c ? class_getInstanceMethod(c, sel) : NULL;
        if (!m) { xrc_logw(XRCLC_BOOT, @"[boot] CADisplayLink hook miss"); return; }
        s_orig_add_to_runloop = method_getImplementation(m);
        method_setImplementation(m, (IMP)s_cadl_add_common);
    });
}


#pragma mark - 循环 / retry 回位（玩法语义说明）

/* ───────────────────────── 数据流总览 ─────────────────────────
 *
 * 循环区间 A/B：仅由面板「起点」/「终点」按钮写入；仅由面板「重置循环」
 *   按钮清除（xrc_loop_reset_all）。**没有任何自动清除路径**：retry 重建
 *   同样会重置曲长（len=143896->0），自动判据必然误伤。
 *
 * 循环开关：面板「循环 开/关」（区间完整才允许开启）。
 *
 * 到 B 点（循环开）：deferred seek 平移回 A。回退一旦被检出（XRCReplay 的
 *   50ms 水位线回落 >300ms），重播引擎在冻结窗内接管（清分→清消费→复活→
 *   重建；语义见 XRCReplay.m 文件头）：音符重现、该段记分清空。
 *   「回跳重播」总门（s_arm_on）关闭时，回跳退化为纯 seek 平移。
 *
 * 手动 Retry（游戏原生重建，安全）：重建后音频回跳（>-10s）被检测 →
 *   **仅当循环开启**时 seek 回 A；未开循环则不干预。
 *
 * 程序化 retry：不可用（重触发会污染 GameModel action 队列致卡死），
 *   本工具不做；路径记录见 XRCProfile.h 的 retry 触发链注释段。
 * ──────────────────────────────────────────────────────────────── */

/*
 * 玩法定义：
 *
 * 【A-B 循环练习】
 *   用户流程：播放到起点按「起点」→ 播放到终点按「终点」→ 开「循环」。
 *   到 B 点 → deferred seek 平移回 A → 回退被重播引擎（XRCReplay）接管：
 *   音符重现、该段记分清空。「回跳重播」开关 = 重播引擎总门；关闭时回跳
 *   退化为纯 seek 平移（音符不重现、计分不回滚，不触碰游戏状态机）。
 *
 * 【手动 Retry（游戏原生重建，安全）】
 *   用户从暂停菜单自行 Retry（游戏原生重建链），重建后音频回跳检测把
 *   进度拉回 A（retry detected -> seek A）——仅循环开启时执行。
 *
 * 【程序化 retry（禁止调用）】
 *   触发调用被游戏静默忽略（Retry 回调首校验 PauseLayer+0x298==1），
 *   重复尝试还会污染 GameModel action 队列致手动 retry 卡在转场界面。
 *   结论：retry 与暂停流程深度耦合，外部驱动需动内部状态，风险不可控。
 *   研究记录见 XRCProfile.h 的 retry 触发链注释段。
 *
 * 【退出重进 vs retry】
 *   换歌/退出重进 = 播放器实例更换或曲长归零（见面板 watcher 判据）→
 *   xrc_loop_reset_all() 清空练习状态。retry = 同一播放器、场景重建 →
 *   状态保留，正好用于续练。
 */

static _Atomic(bool) s_loop_enabled = false;
static _Atomic(uint32_t) s_loop_a = 0;
static _Atomic(uint32_t) s_loop_b = 0;

bool xrc_loop_get_enabled(void) { return atomic_load(&s_loop_enabled); }
void xrc_loop_set_range(uint32_t a_ms, uint32_t b_ms) {
    // 设定区间**不自动启用**（面板流程：设起点→设终点→开循环）。
    // 区间合法性（b >= a+1000）在 tick 与 set_enabled 时检查。
    atomic_store(&s_loop_a, a_ms);
    atomic_store(&s_loop_b, b_ms);
}
void xrc_loop_set_enabled(bool on) {
    uint32_t a = atomic_load(&s_loop_a), b = atomic_load(&s_loop_b);
    if (on && b <= a + 1000) return;   // 区间不完整不允许开启
    atomic_store(&s_loop_enabled, on);
    xrc_logd(XRCLC_JUDGE, @"loop %s (A=%u B=%u)", on ? "ON" : "OFF", a, b);
}
// 换歌/退出重进 = 练习状态归零（只要退出重进就视作换歌，哪怕同一首）。
// 触发链：Tweak.x 0.5s 轮询（player 指针变化）+ 面板 tick watcher（指针/曲长归零）。
// retry 不走这里：同一播放器实例内的场景重建，状态必须保留才能续练。
void xrc_loop_reset_all(void) {
    atomic_store(&s_loop_enabled, false);
    atomic_store(&s_loop_a, 0);
    atomic_store(&s_loop_b, 0);
    xrc_logd(XRCLC_JUDGE, @"loop range reset (manual)");
}
void xrc_loop_get_range(uint32_t *from_ms, uint32_t *to_ms) {
    if (from_ms) *from_ms = atomic_load(&s_loop_a);
    if (to_ms)   *to_ms   = atomic_load(&s_loop_b);
}
void xrc_loop_tick(void *gameplay, uint32_t pos_ms) {
    if (!atomic_load(&s_loop_enabled)) return;
    uint32_t a = atomic_load(&s_loop_a), b = atomic_load(&s_loop_b);
    if (b <= a + 1000) return;
    if (pos_ms >= b) {
        if (xrc_gameplay_request(XRC_OP_LOOP_REWIND, a))
            xrc_logd(XRCLC_JUDGE, @"loop rewind at %u -> %u (seek shift)", pos_ms, a);
    }
}

