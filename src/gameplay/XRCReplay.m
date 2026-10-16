// © 雾月星辰 & MLXC · github@XingChenRS
// XRCReplay.m — 回跳重播引擎。
//
// 结构：
//   基础：安全读写原语 / 指针判据 / 谱面钟读法 / 类名与对象尺寸
//   清洗：段表 / 消费位 / 开闸门 / 清分 / 按桶隐藏 / 事件去重表 / 触摸态
//   复活与重建：collect_live → revive（登记）→ rebuild（渲染工厂重建，主队列 FIFO）
//   编排：reset（清分→…→开闸门→自检）、谱面表看门狗（含自愈写）、弧分段「不藏」窗口
//   引擎：fast_tick（50ms 检出）+ 常驻线程

#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <dispatch/dispatch.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>

#include "XRCReplay.h"
#include "XRCLog.h"
#include "XRCProfile.h"
#include "XRCRuntime.h"
#include "XRCGameplay.h"
#include "XRCPlayer.h"
#include "XRCClock.h"
#include "XRCHook.h"

// ---------------------------------------------------------------- 安全内存读
// vm_read_overwrite：地址未映射时返回 KERN 错误，不会 SIGSEGV。
static bool rd(uint64_t addr, void *buf, size_t n) {
    if (!addr) return false;
    vm_size_t out = 0;
    kern_return_t kr = vm_read_overwrite(mach_task_self(),
                          (vm_address_t)addr, (vm_size_t)n,
                          (vm_address_t)(uintptr_t)buf, &out);
    return kr == KERN_SUCCESS && out == n;
}
static uint64_t rd64(uint64_t addr) { uint64_t v = 0; rd(addr, &v, 8); return v; }
static uint8_t  rd8(uint64_t addr)  { uint8_t  v = 0; rd(addr, &v, 1); return v; }

// ---------------------------------------------------------------- 布局锚点（IDA 实证）
// scene+0x3A0 = note group（计数区在 +0x38）；ng+0xA0/+0xA8 = 活动窗口音符指针数组
// begin/end（8B/项）；ng+0x100/+0x108 = 全谱表（含已判音符）。
#define RPF_VEC_BEGIN  0xA0
#define RPF_VEC_END    0xA8
#define RPF_VEC2_BEGIN 0x100
#define RPF_VEC2_END   0x108
#define RPF_NOTEGRP    0x3A0          // = XRC_GP_NOTEGROUP_OFF（928）
#define RPF_RENDERMGR  880            // 音符视觉层 = *(scene+880)：整个渲染管理器（0x3A8 字节，
                                      // vtable off_1014EDB68；渲染工厂 sub_100B22984 的第一个参数）
#define RPF_TICK_MS      50           // 快路径周期；回跳可能发生在任意时刻，重置必须即时
#define RPF_HEAVY_EVERY  20           // 20 × 50ms = 1s（保留常量备用）

// ---------------------------------------------------------------- 指针判据
// 堆块首地址判据（8B 对齐 + 地址区间）。
static bool s_ishp(uint64_t v) {
    return v >= 0x100000000ULL && v < 0x7000000000ULL && (v & 7) == 0;
}
// ★ 指针合理性检查**不能要求 8 字节对齐**：名字串指针（&7=4）、代码指针（&7=4）、
//   12 字节元素的 vector end（n 为奇数时 &7=4）都会被对齐检查误杀——真机上表现为
//   tap/hold/arctap 类名全读成 "?"、长条段表被判形状非法，按名字分派全落空。
static bool s_isptr(uint64_t v) { return v >= 0x100000000ULL && v < 0x7000000000ULL; }

// ---------------------------------------------------------------- 安全内存写
// 只写自己进程的地址（vm_write 到 mach_task_self），失败返回 false，不抛。
static bool wr16(uint64_t addr, uint16_t v) {
    kern_return_t kr = vm_write(mach_task_self(), (vm_address_t)addr,
                                (vm_offset_t)&v, (mach_msg_type_number_t)sizeof(v));
    return kr == KERN_SUCCESS;
}

static bool wr32(uint64_t addr, uint32_t v) {
    if (!addr) return false;
    kern_return_t kr = vm_write(mach_task_self(), (vm_address_t)addr,
                                (vm_offset_t)&v, (mach_msg_type_number_t)sizeof(v));
    return kr == KERN_SUCCESS;
}

static bool wr8(uint64_t addr, uint8_t v) {
    if (!addr) return false;
    kern_return_t kr = vm_write(mach_task_self(), (vm_address_t)addr,
                                (vm_offset_t)&v, (mach_msg_type_number_t)sizeof(v));
    return kr == KERN_SUCCESS;
}

// 重建用：把新对象接进场景要写 8 字节的指针（唯一写游戏状态之一的路径，
// 只在回跳那一刻、处处带前置校验）。
static bool wr64(uint64_t addr, uint64_t v) {
    if (!addr || !s_ishp(v)) return false;
    kern_return_t kr = vm_write(mach_task_self(), (vm_address_t)addr,
                                (vm_offset_t)&v, (mach_msg_type_number_t)sizeof(v));
    return kr == KERN_SUCCESS;
}

// 自愈用：把 8 字节清零。**只有谱面表看门狗的修复路径会用**（见 rpf_cmap_walk）。
static bool wr64z(uint64_t addr) {
    if (!addr) return false;
    uint64_t z = 0;
    kern_return_t kr = vm_write(mach_task_self(), (vm_address_t)addr,
                                (vm_offset_t)&z, (mach_msg_type_number_t)sizeof(z));
    return kr == KERN_SUCCESS;
}

// ---------------------------------------------------------------- 谱面钟读法
// flag45 ? *(clk+32)-*(clk+40) : *(clk+52)-*(clk+40)。
static uint32_t rpf_now_ms(uint64_t ng) {
    uint64_t clk = 0;
    if (!ng || !rd(ng + 0x30, &clk, 8) || !clk) return 0;
    uint8_t f45 = 0; rd(clk + 45, &f45, 1);
    int32_t a = 0, bse = 0;
    rd(clk + 40, &bse, 4);
    if (f45) { rd(clk + 32, &a, 4); return (uint32_t)(a - bse); }
    rd(clk + 52, &a, 4);
    return (uint32_t)(a - bse);
}

// ---------------------------------------------------------------- 对象尺寸与类名
// malloc_size：问系统这个对象**真实**多大，而不是猜长度（猜长的读会越界）。
static size_t rpf_malloc_size(uint64_t p) {
    static size_t (*s_ms)(const void *) = NULL;
    static int tried = 0;
    if (!tried) { tried = 1; s_ms = (size_t (*)(const void *))dlsym(RTLD_DEFAULT, "malloc_size"); }
    if (!s_ms || !p) return 0;
    return s_ms((const void *)p);
}

// 虚表 → 类名。Itanium ABI：vtable 指针前面一格是 typeinfo，typeinfo+8 指向名字串。
static void rpf_class_name(uint64_t vt, char *out, size_t cap) {
    out[0] = 0;
    if (!s_isptr(vt)) return;
    uint64_t ti = 0, nm = 0;
    if (!rd(vt - 8, &ti, 8) || !s_isptr(ti)) return;
    if (!rd(ti + 8, &nm, 8) || !s_isptr(nm)) return;
    if (!rd(nm, out, cap - 1)) { out[0] = 0; return; }
    out[cap - 1] = 0;
    for (size_t i = 0; i < cap; i++) {
        char c = out[i];
        if (!c) break;
        if (c < 0x20 || c > 0x7e) { out[i] = 0; break; }   /* 非可打印 = 不是名字 */
    }
}

// ---------------------------------------------------------------- 段表清理（hold / arc 共用）
// 只清"段起始时间 >= T"的项。项 +0 是绝对时间(ms)，与播放头比（有符号：前导期 T 可为负）。
static int rpf_clear_segments(uint64_t note, uint32_t T) {
    uint64_t b = 0, e = 0;
    if (!rd(note + 0x78, &b, 8) || !rd(note + 0x80, &e, 8)) return 0;
    if (!s_isptr(b) || !s_isptr(e) || e < b) return 0;
    if (((e - b) % 12) != 0) return 0;          /* 12 字节/项 —— 不是整除就不是段表 */
    uint64_t cnt = (e - b) / 12;
    if (cnt == 0 || cnt > 4096) return 0;
    int n = 0;
    for (uint64_t i = 0; i < cnt; i++) {
        int32_t t0 = 0;
        uint8_t fl = 0;
        if (!rd(b + 12 * i, &t0, 4) || !rd(b + 12 * i + 8, &fl, 1)) break;
        if ((int32_t)t0 - (int32_t)T < 0) continue;        /* 段在 T 之前 ⇒ 保持已处理 */
        if (fl & 1) { if (wr8(b + 12 * i + 8, (uint8_t)(fl & ~1))) n++; }
    }
    return n;
}

// ---------------------------------------------------------------- 一条音符的清理
// 返回清掉的字段数；-1 = 不快（不是已知类 / 字段不存在）。
static int rpf_clear_note(uint64_t note, uint32_t T) {
    uint64_t vt = 0;
    if (!rd(note, &vt, 8) || !s_isptr(vt)) return -1;
    char nm[96];
    rpf_class_name(vt, nm, sizeof(nm));
    if (!nm[0]) return -2;                                 /* 类名读不出 ⇒ 绝不猜 */
    if (!strstr(nm, "Logic")) return -2;                   /* 渲染类等一律不碰 */
    size_t z = rpf_malloc_size(note);
    if (strstr(nm, "Hold") || (strstr(nm, "Arc") && !strstr(nm, "ArcTap"))) {
        if (z < 0x88) return -2;                           /* 这个类没有段表字段 */
        int n = rpf_clear_segments(note, T);
        // 绘制门对每个类都是 +0x0D（渲染遍历判断的虚表 slot6 即 `return *(u8*)(note+13)`）。
        // 段表清了、+0x0D 还留着 1 的话，这一条照样整帧不画。
        uint8_t c0 = 0, c1 = 0;
        rd(note + 0x0C, &c0, 1);
        rd(note + 0x0D, &c1, 1);
        if (c0 & 1) { if (wr8(note + 0x0C, 0)) n++; }
        if (c1 & 1) { if (wr8(note + 0x0D, 0)) n++; }
        // 弧还要带上它挂的**天键**（LogicArcTapNote）：独立对象，不进活动窗口、
        // 不在桶地图、也不在登记表里——只有顺弧自己的子表 arc+0x120..0x128 才够得着。
        // 天键的绘制门同样是 +0x0D，不清它天键永远不画。
        if (!strstr(nm, "ArcTap")) {
            uint64_t ab = 0, ae = 0;
            if (rd(note + 0x120, &ab, 8) && rd(note + 0x128, &ae, 8) &&
                s_isptr(ab) && s_isptr(ae) && ae >= ab && (ae - ab) <= 0x4000) {
                for (uint64_t p = ab; p < ae; p += 8) {
                    uint64_t at = 0, avt = 0;
                    if (!rd(p, &at, 8) || !s_ishp(at)) continue;
                    if (!rd(at, &avt, 8) || !s_isptr(avt)) continue;
                    char an[96];
                    rpf_class_name(avt, an, sizeof(an));
                    if (!strstr(an, "Logic") || strstr(an, "SceneControl")) continue;
                    uint8_t a0 = 0, a1 = 0;
                    rd(at + 0x0C, &a0, 1);
                    rd(at + 0x0D, &a1, 1);
                    if (a0 & 1) { if (wr8(at + 0x0C, 0)) n++; }
                    if (a1 & 1) { if (wr8(at + 0x0D, 0)) n++; }
                }
            }
        }
        return n;
    }
    /* 只有可判定音符才清两个字节：Tap / Flick / ArcTap。
       LogicBar / LogicSceneControl 是场景物件，不是可判定音符 —— 不碰。 */
    if (!strstr(nm, "Tap") && !strstr(nm, "Flick")) return -2;
    if (z < 0x10) return -2;                               /* 写 +0x0C/+0x0D 的前提 */
    int n = 0;
    uint8_t c0 = 0, c1 = 0;
    rd(note + 0x0C, &c0, 1);
    rd(note + 0x0D, &c1, 1);
    if (c0 & 1) { if (wr8(note + 0x0C, 0)) n++; }
    if (c1 & 1) { if (wr8(note + 0x0D, 0)) n++; }
    return n;
}

// ---------------------------------------------------------------- 判据复读（只读）
// 直接调该音符自己的 vtable idx5。
static int rpf_note_consumed(uint64_t note) {
    uint64_t vt = 0, fn = 0;
    if (!rd(note, &vt, 8) || !s_isptr(vt)) return -1;
    if (!rd(vt + 40, &fn, 8) || !s_isptr(fn)) return -1;
    int (*pf)(uint64_t) = (int (*)(uint64_t))fn;
    return pf(note) & 1;
}

// ================================================================ 重播功能主线
extern void xrc_arc_nohide_set(int on);   // XRCHook 导出
extern void xrc_ap_latch_reset(void);     // XRCHook 导出
extern void xrc_freeze_end(void);         // XRCGameplay 导出
extern uint64_t xrc_gameplay_scrub_us(void);   // XRCGameplay 导出（拖动 seek 豁免窗）

// ---- 开关与状态（默认 = 已验证配置） ----
static int s_arm_on;                              /* 回跳重播总门（xrc_replay_set_enabled 控制） */
static int s_no_gate, s_no_pred, s_no_score;      /* 子项断流开关（0 = 执行） */
static int s_rebuild_on = 1;                      /* 渲染重建：弧/长条回跳显示的正解（默认开） */
static int s_do_write = 1;                        /* 落笔（默认开；置 0 = 只读诊断） */

static int s_rst_seq;                             /* 重置序号（日志用） */
static int s_rereg_n;                             /* 上次实际派发的登记条数 */
static uint32_t s_seek_wm;                        /* 播放头水位线（检出"回落"用） */
static uint64_t s_last_scene, s_last_ng;
static int      s_ng_stable;

#define RPF_WALK_SET 1024
static uint64_t s_walk_set[RPF_WALK_SET];
static int      s_walk_n;

// ---- 遍历 ng+0x88..0x90 的时间桶（**照抄 sub_1009204E4 的走法**，不自创）----
//   桶数组项 = std::map*；libc++ map 布局：map+0 = begin 节点，map+8 = end（header 节点）；
//   节点 +0/+8/+16 = 左/右/父；节点 +40/+48 = vector<note*> 的 begin/end。
//   （出处：sub_1009204E4 里 `v10[5]`/`v10[6]` 与 `v9+1` 的哨兵比较。）
// ★ 与引擎唯一的差别：**不提前跳出**。引擎只关心 T+3000 之前（快进用），
//   而我们要覆盖"整张谱在 T 之后的全部音符" —— 回跳点可能远小于之前播放到的地方。
typedef struct {
    int seen, tap, lng, other, cleared, still, soft;
    int nh, nsamp;                       /* 诊断：类名直方图 / 样例计数 */
    char hname[6][40];
    int  hcnt[6];
    int  nbkt, bkt[16];                  /* 每个桶里的对象数（诊断） */
    uint64_t node0;                      /* 第一个非空桶的首节点（诊断：原样 dump） */
    // 判"map 覆盖到哪" —— 走查到的 t 最小值就是 map 的起点。
    // 真机实测：回跳 T=909 时 map 里 t>=T 的第一条是 16198（≈ 播放头 P+1400）
    // ⇒ 已判过的音符**不在 map 里**（被引擎擦掉了），走查自然碰不到它们。
    int tmin, tmax, tmin_n;              /* tmin_n = 取到 tmin 的那条对象 */
    int dist;                            /* 去重后的对象数（条目 vs 对象） */
    int kfirst[8], kfirst_n;             /* 前 8 个节点的 key（诊断：key 的方向与量级） */
} rpf_sweep_t;

// 走查去重表（判"3615 条"里到底有多少个不同的对象）
#define RPF_SEEN_SLOTS 8192
static uint64_t s_seen_key[RPF_SEEN_SLOTS];
static int      s_seen_dist;
static void rpf_seen_reset(void) { memset(s_seen_key, 0, sizeof(s_seen_key)); s_seen_dist = 0; }
static void rpf_seen_add(uint64_t p) {
    uint32_t h = (uint32_t)((p >> 4) ^ (p >> 17) ^ (p >> 33)) & (RPF_SEEN_SLOTS - 1);
    for (int i = 0; i < 64; i++) {
        uint32_t j = (h + i) & (RPF_SEEN_SLOTS - 1);
        if (s_seen_key[j] == p) return;
        if (!s_seen_key[j]) { s_seen_key[j] = p; s_seen_dist++; return; }
    }
}

// 该音符此刻在不在活动窗口（ng+0xA0..0xA8）—— 判断"走查集合"与"引擎在跑的那批"是否同一批
static int rpf_in_window(uint64_t ng, uint64_t note) {
    uint64_t b = 0, e = 0;
    if (!rd(ng + RPF_VEC_BEGIN, &b, 8) || !rd(ng + RPF_VEC_END, &e, 8)) return 0;
    if (!s_ishp(b) || !s_ishp(e) || e < b || (e - b) > 0x100000) return 0;
    for (uint64_t p = b; p < e; p += 8) {
        uint64_t q = 0;
        if (!rd(p, &q, 8)) break;
        if (q == note) return 1;
    }
    return 0;
}

// libc++ __tree_next：右子树最左，或向上直到"从左子树上来"
static int rpf_tree_next(uint64_t sentinel, uint64_t node, uint64_t *out) {
    uint64_t r = 0;
    if (rd(node + 8, &r, 8) && r && r != sentinel) {
        uint64_t n = r, l = 0;
        for (int i = 0; i < 512 && rd(n, &l, 8) && l && l != sentinel; i++) n = l;
        *out = n;
        return 1;
    }
    uint64_t cur = node, p = 0, pl = 0;
    for (int i = 0; i < 512; i++) {
        if (!rd(cur + 16, &p, 8) || !s_ishp(p)) return 0;
        if (rd(p, &pl, 8) && pl == cur) { *out = p; return 1; }   /* p 是后继（尽头 = 哨兵）*/
        cur = p;
    }
    return 0;
}

static void rpf_sweep(uint64_t ng, uint32_t T, int do_write,
                      rpf_sweep_t *s) {
    uint64_t bb = 0, be = 0;
    if (!rd(ng + 0x88, &bb, 8) || !rd(ng + 0x90, &be, 8)) return;
    if (!s_ishp(bb) || !s_ishp(be) || be < bb) return;
    uint64_t nbs = (be - bb) / 8;
    if (nbs == 0 || nbs > 4096) { xrc_logd(XRCLC_JUDGE, @"[rpf] ⟲⟲⟲ 桶数组形状不对（%llu 个）", nbs); return; }
    s->nbkt = (int)(nbs > 16 ? 16 : nbs);
    for (uint64_t bi = 0; bi < nbs; bi++) {
        uint64_t mp = 0, node = 0;
        if (!rd(bb + 8 * bi, &mp, 8) || !s_ishp(mp)) continue;
        if (!rd(mp, &node, 8) || !s_ishp(node)) continue;
        if (!s->node0 && do_write) s->node0 = node;
        uint64_t sentinel = mp + 8;
        int before = s->seen;
        for (int ni = 0; ni < 8192 && node && node != sentinel && s_ishp(node); ni++) {
            uint64_t vb = 0, ve = 0;
            if (do_write && s->kfirst_n < 8) {
                int32_t nk = 0;
                if (rd(node + 32, &nk, 4)) s->kfirst[s->kfirst_n++] = (int)nk;
            }
            if (rd(node + 40, &vb, 8) && rd(node + 48, &ve, 8) &&
                s_ishp(vb) && s_ishp(ve) && ve >= vb && (ve - vb) <= 0x10000) {
                for (uint64_t p = vb; p < ve; p += 8) {
                    uint64_t note = 0;
                    if (!rd(p, &note, 8) || !s_ishp(note)) continue;
                    uint32_t nt = 0;
                    if (!rd(note + 0x18, &nt, 4)) continue;
                    if ((int32_t)nt - (int32_t)T < 0) continue;     /* T 之前 ⇒ 不动 */
                    /* map 覆盖面 + 条目/对象去重 */
                    if (!s->tmin || (int32_t)nt < s->tmin) { s->tmin = (int)nt; s->tmin_n = (int)note; }
                    if ((int32_t)nt > s->tmax) s->tmax = (int)nt;
                    if (do_write) { rpf_seen_add(note); s->dist = s_seen_dist; }
                    uint64_t vt = 0;
                    if (!rd(note, &vt, 8) || !s_ishp(vt)) continue;
                    char nm[96];
                    rpf_class_name(vt, nm, sizeof(nm));
                    s->seen++;
                    if (do_write && s_walk_n < RPF_WALK_SET) s_walk_set[s_walk_n++] = note;
                    /* 类名直方图（诊断：走查到的到底是什么对象） */
                    {
                        const char *key = nm[0] ? nm : "(无类名)";
                        int f = 0;
                        while (f < s->nh && strcmp(s->hname[f], key)) f++;
                        if (f == s->nh && s->nh < 6) {
                            snprintf(s->hname[s->nh], sizeof(s->hname[0]), "%s", key);
                            s->hcnt[s->nh] = 0;
                            s->nh++;
                        }
                        if (f < s->nh) s->hcnt[f]++;
                    }
                    int is_long = nm[0] && strstr(nm, "Logic") &&
                                  (strstr(nm, "Hold") ||
                                   (strstr(nm, "Arc") && !strstr(nm, "ArcTap")));
                    if (is_long) s->lng++; else if (nm[0]) s->tap++; else s->other++;
                    /* 样例（前 8 条）：地址 / 尺寸 / 类名 / 时间 / +A4 / 段表 */
                    if (do_write && s->nsamp < 8) {
                        uint64_t b78 = 0, e80 = 0;
                        int cnt = -1, set = 0;
                        if (rd(note + 0x78, &b78, 8) && rd(note + 0x80, &e80, 8) &&
                            s_isptr(b78) && s_isptr(e80) && e80 >= b78 &&
                            (e80 - b78) <= 0x10000 && ((e80 - b78) % 12) == 0) {
                            cnt = (int)((e80 - b78) / 12);
                            for (int q = 0; q < cnt && q < 4096; q++) {
                                uint8_t fl = 0;
                                if (!rd(b78 + 12 * q + 8, &fl, 1)) break;
                                if (fl & 1) set++;
                            }
                        }
                        uint32_t a4 = 0;
                        rd(note + 0xA4, &a4, 4);
                        uint8_t f99 = 0;
                        uint32_t fd0 = 0;
                        rd(note + 0x99, &f99, 1);
                        rd(note + 0xD0, &fd0, 4);
                        xrc_logd(XRCLC_JUDGE, @"[rpf] ▣ 走查样例 %d: @%llx sz=%zu %s t=%u pred=%d +A4=%u "
                               "段表=[%llx,%llx) 项=%d 置位=%d +99=%u +D0=%u 窗内=%s",
                               s->nsamp, note, rpf_malloc_size(note), nm[0] ? nm : "?",
                               nt, rpf_note_consumed(note), a4, b78, e80, cnt, set,
                               f99, fd0, rpf_in_window(ng, note) ? "Y" : "N");
                        s->nsamp++;
                    }
                    if (do_write && s_do_write && !s_no_pred) {
                        int c = rpf_clear_note(note, T);
                        if (c > 0) s->cleared += c;
                    } else {
                        int cd = rpf_note_consumed(note);
                        if (cd == 1) s->still++;
                    }
                }
            }
            uint64_t nxt = 0;
            if (!rpf_tree_next(sentinel, node, &nxt)) break;
            node = nxt;
        }
        if (bi < 16) s->bkt[bi] = s->seen - before;
    }
}

// ---- 闸门 A：对"槽时间 >= T"的槽置标志 1 ----
static void rpf_open_gates(uint64_t ng, uint32_t T,
                           int *n_slots, int *n_set, int do_write) {
    uint64_t chart = 0, b = 0, e = 0;
    if (!rd(ng + 0x28, &chart, 8) || !s_ishp(chart)) return;
    if (!rd(chart + 0x50, &b, 8) || !rd(chart + 0x58, &e, 8)) return;
    if (!s_ishp(b) || !s_ishp(e) || e < b) return;
    uint64_t cnt = (e - b) / 8;
    if (cnt == 0 || cnt > 4096) { xrc_logd(XRCLC_JUDGE, @"[rpf] ⟲⟲⟲ 槽表形状不对（%llu 个）", cnt); return; }
    for (uint64_t i = 0; i < cnt; i++) {
        uint64_t slot = 0;
        if (!rd(b + 8 * i, &slot, 8) || !s_ishp(slot)) continue;
        uint32_t st = 0;
        uint8_t fl = 0;
        if (!rd(slot + 4, &st, 4) || !rd(slot, &fl, 1)) continue;
        (*n_slots)++;
        if ((int32_t)st - (int32_t)T < 0) continue;     /* 已越过的桶：引擎自己也会清，不动 */
        if (fl != 1) { if (do_write) { if (wr8(slot, 1)) (*n_set)++; } else (*n_set)++; }
    }
}
// ---- 清分：记分器水位线 > 当前位置 ⇒ 回跳 ⇒ 十计数组归零 ----
// 出处：sub_100ACBF98 每帧 `if (*(int*)(sk+184) < (int)a2) *(int*)(sk+184) = a2` —— 只增不减，
// 所以"水位线 > 当前位置"在正常游玩里不可能出现 ⇒ 天然只在回跳那一刻触发。
// 十个数与五条不变量（同一函数里的 exit(0) 自检）：
//     +24 == +20/3、+48 == +32/6、+52 == +36/5、+56 == 2*+40、+60 == 6*+44
//   全部归零 ⇒ 五条在 0 处全部成立 ⇒ 不会踩 exit(0)。
// 分数公式（sub_100B89E28）的分母是谱面总音符数（在 *(sk+96)+184），**不在**这十个数里
// ⇒ 归零不会除零。清分覆盖：显示分 +20、+24、pure +32、hit +36、lost +40、LN +44 及派生。
static int s_sc_writes;
static void rpf_score_reset(uint64_t ng, uint32_t now) {
    uint64_t sk = 0;
    if (!ng || !rd(ng + 0x38, &sk, 8) || !s_ishp(sk)) return;
    int32_t wm = 0;
    if (!rd(sk + 184, &wm, 4)) return;
    if (wm <= (int32_t)now) return;                    /* 正常游玩：水位线恒 <= 当前位置 */

    static const uint32_t kOff[10] = { 20, 24, 32, 36, 40, 44, 48, 52, 56, 60 };
    int32_t before[10];
    int nz = 0;
    for (int i = 0; i < 10; i++) {
        before[i] = 0;
        rd(sk + kOff[i], &before[i], 4);
        if (before[i]) nz++;
    }
    if (!wr32(sk + 184, now)) return;
    if (nz) for (int i = 0; i < 10; i++) wr32(sk + kOff[i], 0);
    // **combo 也清**：清分后 sk+28(当前连击)=0 但 sk+16(最大连击)仍在——
    // 显示上的"combo 没清"就是后者（+16 是给结算/显示用的）。
    uint32_t cb16 = 0, cb28 = 0;
    rd(sk + 16, &cb16, 4);
    rd(sk + 28, &cb28, 4);
    if (cb16) wr32(sk + 16, 0);
    if (cb28) wr32(sk + 28, 0);
    s_sc_writes++;
    xrc_logd(XRCLC_JUDGE, @"[rpf] ⟲⟲⟲ 清分 #%d @%llx 水位 %d→%u 计数组非零 %d/10 "
           "(+20=%d +24=%d +32=%d +36=%d +40=%d +44=%d +48=%d +52=%d +56=%d +60=%d) "
           "combo +16=%u +28=%u → 0",
           s_sc_writes, sk, wm, now, nz,
           before[0], before[1], before[2], before[3], before[4],
           before[5], before[6], before[7], before[8], before[9], cb16, cb28);
}
// ================================================================ 按桶隐藏
// **这就是"逻辑清了但还是不显示"的最后一道门。**
//
// 静态取证：
//   · `RenderNote::tick`（如 RenderTapNote 的 sub_100AE42AC）末尾：
//         if (*(u8*)(LogicNote + 0x55) == 1 && 自己可见) → setVisible(0)
//     —— **渲染节点被直接隐藏**，与位置/透明度无关（所以位置刷新救不了它）。
//   · 写 +0x55 的**全二进制只有一处**：`sub_10091366C(chart, idx, val)`
//         *(u8*)(桶对象 + 2) = val;                       // 桶的"隐藏"标志
//         for (每条 note，若 note+0x50 == idx) {
//             *(u8*)(note + 0x55) = val;                  // ← 整桶音符
//             if (弧) for (每个子弧键) *(u8*)(child + 0x55) = val;
//         }
//   · 它的**唯一调用者**是命令分发器 `sub_100946090` 的 `case 4`：
//         sub_10091366C(*(执行器 + 0x280), 命令.桶号, 命令.+0x6C != 0)
//   · 分发器的**唯一调用者**是自动漏扫 `sub_10091D9A0`：
//         遍历到 **LogicSceneControl** 音符、播放头越过它 ⇒ `sub_100946090(*(ng+704), 该音符)`
//     ⇒ 也就是说：**这是谱面自带的"隐藏这一段"指令**（SceneControl 命令）。
//
// ⇒ 只清"每音符消费字段"不够——还必须碰这个**按桶**的隐藏位：
//   谱面命令隐藏过的桶（黑线 / 弧键 / hold / arc）回跳后依然 `+0x55 == 1` ⇒ 渲染节点被 setVisible(0)
//   ⇒ 完全不显示。只有那些没被命令覆盖到的弧还在（"偶尔的弧末端"）。
//
// 做法：回跳时对"桶时间 >= T"的桶**调用引擎自己的 setter 置 0**（不自造写）。
//   谱面命令会在播放头再次越过时自然重放，所以这里清掉是正确的语义。
typedef void (*rpf_setbucket_t)(uint64_t chart, uint32_t idx, uint32_t val);

static int rpf_clear_buckets(uint64_t ng, uint32_t T) {
    uint64_t chart = 0, tbl = 0, end = 0;
    if (!rd(ng + 0x28, &chart, 8) || !s_ishp(chart)) return 0;
    if (!rd(chart + 0x50, &tbl, 8) || !rd(chart + 0x58, &end, 8)) return 0;
    if (!s_ishp(tbl) || !s_ishp(end) || end < tbl) return 0;
    uint64_t cnt = (end - tbl) / 8;
    if (cnt == 0 || cnt > 4096) return 0;
    // sub_10091366C 内部会遍历 chart+0x20..+0x28 的音符向量并按索引 abort —— 先验形状
    uint64_t nb = 0, ne = 0;
    if (!rd(chart + 0x20, &nb, 8) || !rd(chart + 0x28, &ne, 8) || !s_ishp(nb) || ne < nb) {
        xrc_logd(XRCLC_JUDGE, @"[rpf] ⟲⟲⟲ 跳桶：chart+0x20 不是合法音符数组（%llx/%llx），放弃", nb, ne);
        return 0;
    }
    // 身份旁证：命令分发器用的是 *(执行器+0x280)，这里用的是 *(ng+0x28) —— 应当同一个对象
    uint64_t ex = 0, exq = 0;
    rd(ng + 704, &ex, 8);
    if (s_ishp(ex)) rd(ex + 0x280, &exq, 8);
    xrc_logd(XRCLC_JUDGE, @"[rpf] ⟲⟲⟲ 跳桶预备：chart(ng+0x28)=%llx  执行器+0x280=%llx  一致=%s  桶数=%llu",
           chart, exq, (exq && exq == chart) ? "Y" : "N", cnt);

    rpf_setbucket_t set = (rpf_setbucket_t)(g_xrc.image_base + (0x10091366CULL - 0x100000000ULL));
    int n = 0;
    for (uint64_t i = 0; i < cnt; i++) {
        uint64_t slot = 0;
        uint32_t st = 0;
        uint8_t hid = 0;
        if (!rd(tbl + 8 * i, &slot, 8) || !s_ishp(slot)) continue;
        if (!rd(slot + 4, &st, 4) || !rd(slot + 2, &hid, 1)) continue;
        if ((int32_t)st - (int32_t)T < 0) continue;          /* T 之前的桶保持原样 */
        if (!hid) continue;                                  /* 本来就没隐藏，不动 */
        set(chart, (uint32_t)i, 0);
        n++;
        if (n <= 12) {
            uint8_t nh = 0xff;
            rd(slot + 2, &nh, 1);
            xrc_logd(XRCLC_JUDGE, @"[rpf] ⟲⟲⟲ 跳桶 #%llu：隐藏 %u→%u（槽时间 %d）", i, hid, nh, (int32_t)st);
        }
    }
    return n;
}

// 引擎登记函数原型（rpf_revive_main 直调 0x10091B6CC：按 [t0,te] 跨度把音符塞进每个位置槽）。
typedef uint64_t (*rpf_reg_note_t)(uint64_t ng, uint64_t note);
// ---- 事件派发器的"同时间去重表"必须清（**这就是"没有音效"的根因**） ----
// 打击音不是独立采样：判定写入者 sub_10089D50C 干的三件事是
//     sub_100B69644(*(qword_101673DD8+16), 2, note+0x18 /*音符时间*/, 0, 0);   // ★ 事件派发 = 音效
//     *(u8 *)(note + 13) = 1;        // +0x0D
//     *(u32*)(note + 16) = a3;       // +0x10 = 判定时间
// 而 sub_100B69644 里 ev∈{2,3} 这条分支有一张**同时间去重表**（dispatcher+664..672）：
//     for (i = a1[83]; i != a1[84]; ++i) if ( a3 - *i <= 9 ) return -1;   // ★ 注意不是 abs()
//     sub_100B677A8(...);  sub_100011CEC(v7+83, &time);  if (size >= 0x15) memmove(丢最旧一条);
// **它是 `a3 - *i <= 9` 而不是 `|a3 - *i| <= 9`** ⇒ 只要表里存着一个**比新事件更大的时间**，
// 之后所有更小时间的事件全部 `<= 9` 成立 ⇒ 被静默吞掉。而且吞掉时不写表 ⇒ **旧的大时间永远
// 出不去**（表只在成功派发后才丢最旧一条）⇒ 回跳一次之后**永久失声**——即"没有音效"。
// 做法：把表里的时间逐个改成一个极小值（见下方实现注释；不动 begin/end/cap）。
static int rpf_clear_event_dedup(void) {
    uint64_t app = 0;
    uint64_t gaddr = g_xrc.image_base + (0x101673DD8ULL - 0x100000000ULL);
    if (!rd(gaddr, &app, 8) || !s_isptr(app)) return -1;
    uint64_t d = 0;
    if (!rd(app + 16, &d, 8) || !s_isptr(d)) return -1;
    int n = 0;
    static const uint64_t kEndOff[2] = { 672, 696 };
    static const uint64_t kBegOff[2] = { 664, 688 };
    for (int i = 0; i < 2; i++) {
        uint64_t b = 0, e = 0;
        if (!rd(d + kBegOff[i], &b, 8) || !rd(d + kEndOff[i], &e, 8)) continue;
        if (!s_isptr(b) || !s_isptr(e) || e < b || (e - b) > 0x400) continue;
        int cnt = (int)((e - b) / 4);
        if (cnt > 0 && cnt <= 64) {
            int32_t first = 0, last = 0;
            rd(b, &first, 4);
            rd(e - 4, &last, 4);
            /* ⚠ 不动向量的 begin/end/cap（会改它的逻辑尺寸 ⇒ 崩）——
               只把表里的时间**逐个改成一个极小的值**。去重判定是 `a3 - *i <= 9`，
               改成 -1000000 后任何真实音符时间（>=-10000）减它都 >= 990000 > 9 ⇒ 不拦。 */
            int ok = 0;
            for (int q = 0; q < cnt; q++) if (wr32(b + 4 * q, (uint32_t)0xFFF0BDC0)) ok++;
            xrc_logd(XRCLC_JUDGE, @"[rpf] ⟲⟲⟲ 事件去重表 #%d @%llx 有 %d 条（时间 %d..%d）→ 逐条改写为 -1000000（%d 条）",
                   i, d + kBegOff[i], cnt, first, last, ok);
            n += ok;
        }
    }
    return n;
}

typedef struct { int lns, held, spr; } rpf_touch_t;

static int rpf_clear_touch_state(uint64_t note, rpf_touch_t *st, int verbose) {
    st->lns = st->held = st->spr = 0;
    uint64_t vt = 0;
    if (!rd(note, &vt, 8) || !s_isptr(vt)) return -1;
    char nm[96];
    rpf_class_name(vt, nm, sizeof(nm));
    int is_arc  = strstr(nm, "Arc") && !strstr(nm, "ArcTap");
    int is_hold = strstr(nm, "Hold") != NULL;
    if (!is_arc && !is_hold) return -1;
    int n = 0;
    uint16_t lns = 0;
    uint8_t  held = 0;
    rd(note + 0x64, &lns, 2);
    rd(note + 0xA8, &held, 1);
    if (lns)  { if (wr16(note + 0x64, 0)) { n++; st->lns = lns; } }
    /* **+0xA8 只对长条清**。真机实测两个类的同一个偏移语义不同：
         长条 +A8 = 1    —— 是布尔（出处 = XRCProfile.h 偏移表）。
         弧   +A8 = 205  —— 恒为 0xCD，**不是布尔**，同一偏移在弧上是别的东西。
       拿"长条的被接住位"去清弧，等于动一个未验证字段 ⇒ 弧这边只记不清。 */
    if (held && is_hold) { if (wr8(note + 0xA8, 0)) { n++; st->held = held; } }
    /* 弧 sprite 不写：sub_100187618(note) 返回的是"当前头段对象"，直接按 sprite 偏移写
       是在猜布局——只保留 +0x64/+0xA8 这两个 XRCProfile.h 里有出处的。 */
    /* ---- 引擎"只在音符播完之后才做"的收尾，替它在回跳这一刻做一遍 ----
       出处（全部逐条反汇编确认）：
         note+0x99  弧 slot3 sub_100187B38: `if (arc+0x18 < cur) *(u8*)(arc+0x99)=1`（只置，无 else）
                    长条 slot3 sub_1008E493C: `CMP note+0x18, cur; B.GE ret; +0x99 = 1`（只置）
                    ★ 语义 = "这条音符的时间到了"。**长条亮度判据就是它**：
                      hold tick `LDRB W8,[logic+0x99]; CMP W8,#0; FCSEL S8, 110.0, 220.0`
                      ⇒ +0x99==0 → 110（暗一半）、!=0 → 220。回跳后它粘在 1 ⇒ 亮度取错档。
         arc+0xDC   弧 slot3 收尾路径（形如 arc+0x1C < cur 才置 1，回跳后不掉）
         弧头段(arc+0xE0) +0x11  sub_1001875FC: `if (在段内) head+0x11 = 1`（**只置，无 else**）
                    ⇒ 弧 tick 的"头驱动块"判据里有 `head+0x11 != 1`，粘住会改变走向
         弧**收尾对象**(arc+0xB0) +0x24/+0x2C/+0x30  弧 slot3 收尾路径里才复位（0 / -1 / 0）
                    ⚠ 注意 **是 +0xB0，与头段对象 +0xE0 相差 0x30**；且 +0x24 与 +0x30
                      引擎用的是 1 字节（STRB），只有 +0x2C 是 4 字节（见下方 is_arc 块）。
       ⚠ 不动：+0xA9（唯一写者 sub_10090EC0C = 弧建造器，构造期一次）、+0x65（唯一写者
          sub_10098F384，同构造期）、+0xD0（sub_1001875FC 每帧重算，不是粘滞）。 */
    {
        int k = 0;
        uint8_t f99 = 0;
        rd(note + 0x99, &f99, 1);
        if (f99) { if (wr8(note + 0x99, 0)) { n++; k++; } }
        if (is_arc) {
            uint8_t fdc = 0;
            rd(note + 0xDC, &fdc, 1);
            if (fdc) { if (wr8(note + 0xDC, 0)) { n++; k++; } }
            /* ---- 这里是**两个不同的对象** ----
               ① 头段对象 = *(arc+0xE0)。sub_1001875FC 只在它上面做一件事：
                    0x100187604  LDR  X8,[X0,#0xE0]
                    0x100187610  STRB W9,[X8,#0x11]      ← **只置 1，无 else**
               ② 收尾对象 = *(arc+0xB0) —— **不是 +0xE0，两个指针差 0x30**。sub_100187B38 收尾：
                    0x100187c08  LDR  X8,[X19,#0xB0]
                    0x100187c0c  STRB WZR,[X8,#0x24]     ← **1 字节**
                    0x100187c14  STR  W9,[X8,#0x2C]      ← **4 字节 = -1**
                    0x100187c18  STRB WZR,[X8,#0x30]     ← **1 字节**
               ⚠ 若把这三个偏移全打在 ① 上、且 +0x24/+0x30 用 4 字节 ⇒ **堆溢出**：
                 ① 那个对象很小，wr32(head+0x30, 0) 会啃在相邻 new(0x30) 的 map
                 节点头上，把它的 left 指针低 32 位清零 ⇒ 根变成 0x200000000 ⇒
                 ~LogicChart 崩。 */
            uint64_t head = 0;
            if (rd(note + 0xE0, &head, 8) && s_isptr(head)) {
                uint8_t h11 = 0;
                if (rd(head + 0x11, &h11, 1) && h11) {
                    if (wr8(head + 0x11, 0)) { n++; k++; }
                    if (verbose)
                        xrc_logd(XRCLC_JUDGE, @"[rpf] ◎T ARC %llx 头段(+0xE0) %llx: +11=%u → 0", note, head, h11);
                }
            }
            uint64_t tail = 0;
            if (rd(note + 0xB0, &tail, 8) && s_isptr(tail)) {
                uint8_t t24 = 0, t30 = 0;
                uint32_t t2c = 0;
                rd(tail + 0x24, &t24, 1);
                rd(tail + 0x2C, &t2c, 4);
                rd(tail + 0x30, &t30, 1);
                if (t24 || t30 || t2c != 0xFFFFFFFF) {
                    wr8(tail + 0x24, 0);
                    wr32(tail + 0x2C, 0xFFFFFFFF);
                    wr8(tail + 0x30, 0);
                    n++; k++;
                    if (verbose)
                        xrc_logd(XRCLC_JUDGE, @"[rpf] ◎T ARC %llx 收尾(+0xB0) %llx: +24=%u +2C=%08x +30=%u → 0/-1/0",
                               note, tail, t24, t2c, t30);
                }
            }
        }
        st->spr = k;      /* 复用 spr 字段当"这次清了几处运行期状态" */
    }
    if (verbose && n)
        xrc_logd(XRCLC_JUDGE, @"[rpf] ◎T %s @%llx 清运行期态: +64=%04x→0 +A8=%u→0 共 %d 处（含 +99/头段）",
               is_arc ? "ARC" : "HLD", note, lns, held, n);
    return n;
}

typedef uint64_t (*rpf_get68_t)(uint64_t obj);
typedef void     (*rpf_slot42_t)(uint64_t obj, uint64_t v);

// ---- 弧造型子节点的「原始位置」存档 ----
// 只显回来不够：显回的节点位置仍是挪过头的旧值 ⇒ 看得见但是碎的。
// 把整条链读完，机制是死的：
//   · 弧 tick sub_100AFFC10 的子节点循环（0x100affde4 起）与 sub_100AFFA90 全文，
//     对子节点**只做两件事**：`child->vt[42](child, 0)`（藏），或
//     `sub_100AFEFE4(child, pos)`（把这个片段挪到「头」该在的位置）。
//     **全程序没有任何一处把子节点摆回它当初建出来的那条曲线。**
//   · 两处的触发都要求 `arc+0x18 < now`（弧已开始）—— 0x100affcd0 与 0x100affe58
//     两个 CMP 都是拿 logic+0x18 跟当前时间比。
//   ⇒ 一条**还没开始**的弧，它的子节点一定没被动过（位置 = 建对象时 sub_100AFF158
//     按 arc+0x100 那张 12 字节段表摆出来的曲线布局）。
//   ⇒ 回跳到弧开始之前时：显回来的子节点位置仍是**上一遍挪过头的那批** ⇒ 看得见但是碎的。
// 做法：趁弧还没开始，把每个子节点的原始坐标（child+0x2C0 的 float3）存一份；
//       回跳时先写回原始坐标、再 `vt[42](child,1)`。存与取都用同一个槽、同一个偏移。
#define RPF_CPOS_N 8192
typedef struct { uint64_t child; float x, y, z; } rpf_cpos_t;
static rpf_cpos_t s_cpos[RPF_CPOS_N];
static int s_cpos_restored;   /* 最近一次回跳写回了多少个原始坐标 */

static void rpf_cpos_put(uint64_t child, const float *xyz) {
    uint32_t h = (uint32_t)((child >> 4) & (RPF_CPOS_N - 1));
    for (uint32_t i = 0; i < 64; i++) {
        uint32_t k = (h + i) & (RPF_CPOS_N - 1);
        if (s_cpos[k].child == child) return;     /* 已存过：**绝不覆盖**（存的是"原始"那份） */
        if (s_cpos[k].child == 0) {
            s_cpos[k].child = child;
            s_cpos[k].x = xyz[0]; s_cpos[k].y = xyz[1]; s_cpos[k].z = xyz[2];
            return;
        }
    }
}

static int rpf_cpos_get(uint64_t child, float *xyz) {
    uint32_t h = (uint32_t)((child >> 4) & (RPF_CPOS_N - 1));
    for (uint32_t i = 0; i < 64; i++) {
        uint32_t k = (h + i) & (RPF_CPOS_N - 1);
        if (s_cpos[k].child == child) {
            xyz[0] = s_cpos[k].x; xyz[1] = s_cpos[k].y; xyz[2] = s_cpos[k].z;
            return 1;
        }
        if (s_cpos[k].child == 0) return 0;
    }
    return 0;
}

// 写一个 float（vm_write 只认字节，所以按位搬）
static bool rpf_wf(uint64_t addr, float v) {
    uint32_t u = 0;
    memcpy(&u, &v, 4);
    return wr32(addr, u);
}

// restore=0：只存档（快照趟，**不碰任何可见性**，因为此时子节点本来就该是现在这样）
// restore=1：存档(缺则补) + 把原始坐标写回 + vt[42](child,1) 显回（回跳趟）
static int rpf_reshow_arc_children(uint64_t note, int verbose, int restore) {
    uint64_t rp = 0;
    if (!rd(note + 0x40, &rp, 8) || !s_isptr(rp)) return -1;
    uint64_t node = 0;
    if (!rd(rp + 0x278, &node, 8) || !s_isptr(node)) return -1;
    uint64_t nvt = 0, fn = 0;
    if (!rd(node, &nvt, 8) || !s_isptr(nvt)) return -1;
    if (!rd(nvt + 544, &fn, 8) || !s_isptr(fn)) return -1;      /* vt[68] */
    uint64_t list = ((rpf_get68_t)fn)(node);
    if (!s_isptr(list)) return -1;
    uint64_t b = 0, e = 0;
    if (!rd(list, &b, 8) || !rd(list + 8, &e, 8)) return -1;
    if (!s_isptr(b) || !s_isptr(e) || e < b || (e - b) > 0x4000 || ((e - b) % 8)) return -1;
    int n = 0;
    for (uint64_t p = b; p < e; p += 8) {
        uint64_t child = 0, cvt = 0, show = 0;
        if (!rd(p, &child, 8) || !s_isptr(child)) continue;
        if (!rd(child, &cvt, 8) || !s_isptr(cvt)) continue;
        float cur[3] = { 0, 0, 0 };
        if (!rd(child + 0x2C0, cur, 12)) continue;
        if (!restore) {
            /* 快照趟：弧还没开始 ⇒ 当前位置就是"原始曲线"那份，存下来。
               **不碰任何可见性、不写任何东西。** */
            rpf_cpos_put(child, cur);
            n++;
            continue;
        }
        /* 回跳趟：补存（缺则补，已有绝不覆盖），再把原始坐标写回去 */
        rpf_cpos_put(child, cur);
        float orig[3] = { 0, 0, 0 };
        int restored = 0;
        if (rpf_cpos_get(child, orig) &&
            (cur[0] != orig[0] || cur[1] != orig[1] || cur[2] != orig[2])) {
            if (rpf_wf(child + 0x2C0, orig[0]) && rpf_wf(child + 0x2C4, orig[1]) &&
                rpf_wf(child + 0x2C8, orig[2])) {
                restored = 1;
                s_cpos_restored++;
            }
        }
        if (!rd(cvt + 336, &show, 8) || !s_isptr(show)) continue;   /* slot 42 */
        /* 调用前先拍头部 0x48 字节，调用后再拍一次 —— 差分直接给出 slot42 改的是
           哪个字节；据此可**不调用**而直接读可见性，「碎」到底是"没显回"还是
           "显回了又被引擎藏了"当场可分。 */
        uint8_t pre[0x48], post[0x48];
        int have_pre = (n < 12) && rd(child, pre, sizeof(pre));
        ((rpf_slot42_t)show)(child, 1);
        if (restored && verbose)
            xrc_logd(XRCLC_JUDGE, @"[rpf] ◎S child[%d] @%llx 位置写回 %.1f,%.1f,%.1f（原 %.1f,%.1f,%.1f）",
                   n, child, (double)orig[0], (double)orig[1], (double)orig[2],
                   (double)cur[0], (double)cur[1], (double)cur[2]);
        if (have_pre && rd(child, post, sizeof(post))) {
            char d[220];
            int o = 0;
            for (int i = 0; i < 0x48 && o < (int)sizeof(d) - 16; i++)
                if (pre[i] != post[i])
                    o += snprintf(d + o, sizeof(d) - o, " +%X:%02x→%02x", i, pre[i], post[i]);
            if (o > 0)
                xrc_logd(XRCLC_JUDGE, @"[rpf] ◎R   child[%d] @%llx slot42 改动字节:%s", n, child, d);
        }
        n++;
        /* 把子节点的**位置**与**当前透明度**一并量出来。弧 tick 的子节点循环用的
           就是这两个：
             pos = *(float3*)(child + 0x2C0);    // 判断该藏/该显、以及算透明度
             setOpacity(clamp(((-pos.z - v27) - C) / -1000.0 * 150 + 75, 75, 255) * v28)
           "碎" = 部分子节点位置陈旧或透明度落在低位。这一行能直接分辨是哪一种。 */
        if (verbose && n <= 3) {
            float xyz[3] = { 0, 0, 0 };
            rd(child + 0x2C0, xyz, 12);
            uint64_t cvt2 = 0, gop = 0;
            int op = -1;
            if (rd(child, &cvt2, 8) && s_isptr(cvt2) && rd(cvt2 + 1120, &gop, 8) && s_isptr(gop))
                op = (int)((uint64_t (*)(uint64_t))gop)(child);
            xrc_logd(XRCLC_JUDGE, @"[rpf] ◎R   child[%d] @%llx pos=%.1f,%.1f,%.1f opacity=%d",
                   n - 1, child, (double)xyz[0], (double)xyz[1], (double)xyz[2], op);
        }
    }
    if (verbose && n)
        xrc_logd(XRCLC_JUDGE, @"[rpf] ◎R ARC %llx 造型子节点 %d 个已显回（node=%llx list=%llx）", note, n, node, list);
    return n;
}

// ---- 红黑树自检（场景析构树损坏的定位器）----
// 真机两次崩溃签名**逐字节相同**（KERN_INVALID_ADDRESS at 0xa9417bfd94edf96c，
// possible pointer authentication failure，栈 = sub_100CAA334 场景析构 → sub_100913A40 递归删树）
// ⇒ 不是并发抖动（那会随地址空间抖动），是**确定性的内存写坏**：某个节点的 left/right
//   被写成了非指针数据（来源可能是段表/槽表/去重表/音符字段的某一笔写）。
// 做法：在重置的每一步之后，对 ng+0x88 的 11 棵树做**有界遍历**，检查每个节点的
//   left(+0)/right(+8) 要么为 0、要么是合法的堆指针；一旦发现非法值就**立刻**打出
//   阶段名 + 节点地址 + 那个字段的原值 —— 下一次崩溃前日志里就有"哪一步写坏的"。
static int rpf_tree_check_one(uint64_t mp, const char *stage) {
    uint64_t root = 0;
    if (!rd(mp + 8, &root, 8)) return 0;
    if (!root) return 0;
    if (!s_ishp(root)) {
        xrc_logd(XRCLC_JUDGE, @"[rpf] §TREE %s: map=%llx root=%llx **非法**（节点根就坏了）", stage, mp, root);
        return 1;
    }
    uint64_t stack_[128];
    int sp = 0, seen = 0;
    stack_[sp++] = root;
    while (sp > 0 && seen < 4000) {
        uint64_t n = stack_[--sp];
        if (!s_ishp(n)) {
            xrc_logd(XRCLC_JUDGE, @"[rpf] §TREE %s: 节点 %llx **非法**（map=%llx 栈里取出的）", stage, n, mp);
            return 1;
        }
        seen++;
        uint64_t l = 0, r = 0, v = 0;
        rd(n, &l, 8);
        rd(n + 8, &r, 8);
        if (l && !s_ishp(l)) {
            rd(n - 16, &v, 8);
            xrc_logd(XRCLC_JUDGE, @"[rpf] §TREE %s: 节点 %llx 的 left=%llx **非法**（前 16B 有 %llx）", stage, n, l, v);
            return 1;
        }
        if (r && !s_ishp(r)) {
            xrc_logd(XRCLC_JUDGE, @"[rpf] §TREE %s: 节点 %llx 的 right=%llx **非法**", stage, n, r);
            return 1;
        }
        if (l && sp < 126) stack_[sp++] = l;
        if (r && sp < 126) stack_[sp++] = r;
    }
    return 0;
}

static int rpf_tree_check(uint64_t ng, const char *stage) {
    uint64_t bb = 0, be = 0;
    if (!rd(ng + 0x88, &bb, 8) || !rd(ng + 0x90, &be, 8)) return 0;
    if (!s_ishp(bb) || !s_ishp(be) || be <= bb) return 0;
    uint64_t nbs = (be - bb) / 8;
    if (nbs == 0 || nbs > 64) return 0;
    for (uint64_t i = 0; i < nbs; i++) {
        uint64_t mp = 0;
        if (!rd(bb + 8 * i, &mp, 8) || !s_isptr(mp)) continue;
        if (rpf_tree_check_one(mp, stage)) return 1;
    }
    return 0;
}

// ---- 谱面表看门狗（定义在 rpf_fast_tick 之前，见那里的长注释）----
static int  rpf_cmap_walk(uint64_t chart, const char *stage, int verbose);
static void rpf_cmap_stage(uint64_t ng, const char *stage);

// ---- 重登记的主线程执行体（见 rpf_revive 里的说明）----
#define RPF_PEND_MAX 4096
static uint64_t s_reg_pend[RPF_PEND_MAX];   // 只装「不在桶地图」的（登记用）
static int      s_reg_pend_n;
// 重建渲染对象**单独一张表** —— 必须是过检后的**全量**目标集：
// 与登记表绑定会在"不在场为 0"（真机常态 M=0）时一次都不跑 ⇒ 弧缺段/黑线回归。
static uint64_t s_rb_pend[RPF_PEND_MAX];    // 重建用（过检后的全部目标音符）
static int      s_rb_pend_n;

typedef struct {
    uint64_t scene;
    uint64_t *notes;
    int n;
} rpf_revive_job_t;

static void rpf_revive_main(void *ctx) {
    rpf_revive_job_t *j = (rpf_revive_job_t *)ctx;
    if (!j) return;
    uint64_t ng = 0;
    if (j->scene) rd(j->scene + RPF_NOTEGRP, &ng, 8);
    if (s_ishp(ng)) {
        rpf_reg_note_t pfill = (rpf_reg_note_t)(g_xrc.image_base + (0x10091B6CCULL - 0x100000000ULL));
        uint64_t mb = 0, me = 0;
        /* 这一段是「在主队列上跑引擎自己的登记函数」。崩溃的表是 chart+0x80 的内联
           multimap（见 rpf_cmap_walk 注释），**它和这段代码操作的对象不是同一张表**
           （这里是 ng+0x88 的元素 = new(0x18) 的桶 map）；本段前后各走一遍谱面表以
           界定写入来源：复活前健康、复活后非法 = 本段所写。 */
        uint64_t chart = 0;
        if (rd(ng + 0x28, &chart, 8) && !s_isptr(chart)) chart = 0;
        int bad_before = chart ? rpf_cmap_walk(chart, "复活前", 0) : 0;
        xrc_logd(XRCLC_JUDGE, @"[rpf] ⟲⟲⟲ 复活开始（主队列）：待登记 %d 条 chart=%llx 谱面表=%s",
                  j->n, chart, bad_before ? "已损坏" : "健康");
        if (pfill && rd(ng + 0x88, &mb, 8) && rd(ng + 0x90, &me, 8) &&
            s_ishp(mb) && s_ishp(me) && me > mb) {
            uint64_t ngroups = (me - mb) / 8;
            if (ngroups > 0 && ngroups <= 256) {
                for (int i = 0; i < j->n; i++) {
                    uint32_t g = 0;
                    if (!rd(j->notes[i] + 0x50, &g, 4) || g >= ngroups) continue;
                    pfill(ng, j->notes[i]);
                }
            }
        }
        if (chart) rpf_cmap_walk(chart, "复活后", 1);
        xrc_logd(XRCLC_JUDGE, @"[rpf] ⟲⟲⟲ 复活结束（主队列）");
    }
    free(j->notes);
    free(j);
}

static void rpf_revive_dispatch(uint64_t scene, int n) {
    if (n <= 0) return;
    rpf_revive_job_t *j = (rpf_revive_job_t *)calloc(1, sizeof(*j));
    if (!j) return;
    j->notes = (uint64_t *)malloc(sizeof(uint64_t) * (size_t)n);
    if (!j->notes) { free(j); return; }
    memcpy(j->notes, s_reg_pend, sizeof(uint64_t) * (size_t)n);
    j->scene = scene;
    j->n = n;
    dispatch_async_f(dispatch_get_main_queue(), j, rpf_revive_main);
}

typedef void (*xrc_rebuild_t)(void *mgr, void *vec, void *ctx);

typedef struct {
    uint64_t scene;
    uint64_t *notes;
    int n;
} rpf_rebuild_job_t;

// ---- 渲染注册表 + 连线补齐 ----
// 渲染注册表 = mgr+0x378(begin)..+0x380(end)，8 字节/项（RenderNote*）。
// 出处：场景路 sub_100B21D60 @0x100B220D0（`LDR X26,[X20,#0x378]; LDR X27,[X20,#0x380]` 后逐条走）。
// **连线绘制器 sub_100AE3F5C**（VA 0x100AE3F5C，756 字节）：
//   取 img/white.png 染色（0xAA64A0 / 0x78C8DC 两套）、按「本条 tap 所在槽组成员」逐成员算
//   距离+角度（asin/√、vt[0x520]/vt[0x528] 取两点）→ 设旋转 → 挂 sprite ⟹ **天地双押连线**。
//   全程序唯一调用者：sub_100B21D60 @0x100B2210C —— 顺序 = 工厂(sub_100B22984) → 遍历注册表
//   → dynamic_cast<RenderTapNote> → AE3F5C。只调工厂的话，重建出的 tap 渲染对象**没有连线**
//   ⇒ 回跳后天地双押连线消失（重建失败时连线反而"在"——旧对象带着旧连线）。
#define RPF_RM_REG_BEGIN 0x378
#define RPF_RM_REG_END   0x380ULL
typedef void (*xrc_line_t)(void *render_note);

static void rpf_freeze_end(void);   /* 前向声明（定义在 reset_job 段；重建链末尾收口用） */

static void rpf_rebuild_main(void *ctx) {
    rpf_rebuild_job_t *j = (rpf_rebuild_job_t *)ctx;
    if (!j) return;
    uint64_t mgr = 0;
    if (j->scene) rd(j->scene + RPF_RENDERMGR, &mgr, 8);
    if (s_ishp(mgr) && j->n > 0) {
        static uint64_t s_rb_buf[RPF_PEND_MAX];
        int n = j->n > RPF_PEND_MAX ? RPF_PEND_MAX : j->n;
        for (int i = 0; i < n; i++) s_rb_buf[i] = j->notes[i];
        uint64_t vec[3] = { (uint64_t)s_rb_buf, (uint64_t)(s_rb_buf + n), (uint64_t)(s_rb_buf + n) };
        /* 工厂前拍注册表条目数 —— 工厂把新对象**追加**在尾部（realloc 也保序），
           差值即本批新增，只对这截跑连线补齐（旧的不能碰：再跑一遍会挂第二条线）。 */
        uint64_t rb0 = 0, re0 = 0, rb1 = 0, re1 = 0;
        rd(mgr + RPF_RM_REG_BEGIN, &rb0, 8);
        rd(mgr + RPF_RM_REG_END, &re0, 8);
        long n0 = (s_ishp(rb0) && s_ishp(re0) && re0 >= rb0) ? (long)((re0 - rb0) / 8) : -1;
        xrc_rebuild_t fn = (xrc_rebuild_t)(g_xrc.image_base + (0x100B22984ULL - 0x100000000ULL));
        xrc_logd(XRCLC_JUDGE, @"[rpf] ⟲⟲⟲ 重建渲染对象（主队列）：%d 条 → mgr=%llx", n, mgr);
        fn((void *)mgr, vec, NULL);
        xrc_logd(XRCLC_JUDGE, @"[rpf] ⟲⟲⟲ 重建渲染对象：完成");
        /* 连线补齐（见上注） */
        rd(mgr + RPF_RM_REG_BEGIN, &rb1, 8);
        rd(mgr + RPF_RM_REG_END, &re1, 8);
        if (n0 >= 0 && s_ishp(rb1) && s_ishp(re1) && re1 > rb1) {
            long n1 = (long)((re1 - rb1) / 8);
            if (n1 < n0) n1 = n0;
            xrc_line_t lf = (xrc_line_t)(g_xrc.image_base + (0x100AE3F5CULL - 0x100000000ULL));
            int nline = 0;
            for (long i = n0; i < n1; i++) {
                uint64_t rn = 0, rvt = 0;
                if (!rd(rb1 + 8 * (uint64_t)i, &rn, 8) || !s_ishp(rn)) continue;
                if (!rd(rn, &rvt, 8) || !s_isptr(rvt)) continue;
                char nm[96];
                rpf_class_name(rvt, nm, sizeof(nm));
                if (!strstr(nm, "RenderTap")) continue;      /* 场景路只对 RenderTapNote 跑 */
                lf((void *)rn);
                nline++;
            }
            xrc_logd(XRCLC_JUDGE, @"[rpf] ⟲⟲⟲ 连线补齐（补齐域 %ld..%ld）：%d 条", n0, n1, nline);
        }
    }
    /* 本任务（重建/连线补齐）是重置链最后一棒 ⇒ 冻结窗收口（恢复音频 + 收敛窗）。
       若外层当前没有冻结窗，xrc_freeze_end 是空操作（幂等）。 */
    rpf_freeze_end();
    free(j->notes);
    free(j);
}

static void rpf_rebuild_dispatch(uint64_t scene, int n) {
    if (n <= 0) return;
    rpf_rebuild_job_t *j = (rpf_rebuild_job_t *)calloc(1, sizeof(*j));
    if (!j) return;
    j->notes = (uint64_t *)malloc(sizeof(uint64_t) * (size_t)n);
    if (!j->notes) { free(j); return; }
    memcpy(j->notes, s_rb_pend, sizeof(uint64_t) * (size_t)n);   // 全量目标集
    j->scene = scene;
    j->n = n;
    /* 与 rpf_revive_dispatch 同队列：主队列 FIFO ⇒ 登记先跑、重建后跑 */
    dispatch_async_f(dispatch_get_main_queue(), j, rpf_rebuild_main);
}

// ---- 清洗的取数来源 = 现场扫引擎的活结构 ----
// 依据：三个症状（弧超界 / 弧缺段 / 幽灵 hold）都指向同一件事 —— 某条音符的窗口进出时机或
// 触摸态被改错了。指针快照（最长 1 秒前的 s_reg[]）有两个易错点：
//   · 回跳后场景对象可能已被重建/复用，快照里的地址可能已经不是那条音符；
//   · "vtable 与快照一致"挡不住**同类对象复用**（游戏反复分配同类音符，
//     那块内存很可能又是个 LogicArcNote，vtable 一模一样）⇒ 那一笔就落在别人身上；
//   · 真机数据：4499 个对象里 1944 个连类名都读不出来。
// ⇒ 现在：现场扫 ng+0x88 的桶 → 节点里的音符向量（与 rpf_sweep 同一套走法、同一个
//    rpf_tree_next 后继函数），逐条验活后收集，再动手。登记表保留（差分探针仍用），
//    **清洗与重建不依赖它**。
#define RPF_LIVE_MAX 4096   /* 2048 会被打满（真机日志「现场扫到 2048 条」正是截断）；一首谱 2600+ 条 + 全谱表含已判 ⇒ 放到与 RPF_PEND_MAX 同量级 */

// ---- **去重** + **在场集合** ----
// 现场扫会从多个桶/多个来源扫到同一条音符 —— 因为引擎登记一个音符时，是按它的 [t0,te]
// 跨度把它塞进**每一个**位置槽（sub_10091B6CC 的插入循环 0x10091B7D4..0x10091B82C，
// 真机实测平均 17.4 槽/条）。不去重有两个后果：
//   ① 上限被打满（真机「现场扫到 4096 条」就是这么来的）；
//   ② **复活会把同一条重复登记很多遍**，而每登记一次引擎就再按跨度插一整遍 ——
//      真机：4096 条重复登记 ⇒ 桶地图 +71280 条。每回跳一次涨 7 万 ⇒ 引擎每帧要走完
//      7.6 万条做准入 ⇒ 主线程淹没 = **卡死**（音频在独立线程所以还在响），
//      且同一条弧每帧被处理十几遍 ⇒ **弧超界 / 双押连线消失**。
// 在场集合（pres）= 桶地图里**已经有的**音符。复活只登记**不在场**的 —— 那才是"复活"
// 这个词的语义（恢复被引擎移除过的），也是不重复的唯一正解。
#define RPF_PRES_BITS 13
#define RPF_PRES_SIZE (1u << RPF_PRES_BITS)
static uint64_t s_pres[RPF_PRES_SIZE];
static uint64_t s_dedup[RPF_PRES_SIZE];
static inline uint32_t rpf_hslot(uint64_t p, uint32_t i) {
    return (uint32_t)((((p >> 4) * 0x9E3779B97F4A7C15ull) >> (64 - RPF_PRES_BITS)) + i) & (RPF_PRES_SIZE - 1);
}
static void rpf_hadd(uint64_t *tab, uint64_t p) {
    if (!p) return;
    for (uint32_t i = 0; i < 64; i++) {
        uint32_t k = rpf_hslot(p, i);
        uint64_t v = tab[k];
        if (v == p) return;
        if (v == 0) { tab[k] = p; return; }
    }
}
static int rpf_hhas(const uint64_t *tab, uint64_t p) {
    if (!p) return 0;
    for (uint32_t i = 0; i < 64; i++) {
        uint64_t v = tab[rpf_hslot(p, i)];
        if (v == p) return 1;
        if (v == 0) return 0;
    }
    return 0;
}
static int rpf_collect_live(uint64_t ng, uint32_t T, uint64_t *out, int max) {
    int n = 0;
    memset(s_pres, 0, sizeof(s_pres));
    memset(s_dedup, 0, sizeof(s_dedup));
    /* ---- 来源①：全谱表 ng+0x100..0x108 = **含已判音符** ----
       这张表是幽灵 hold / 弧超界的根因所在：
       第一遍播放时 autoplay 正确标记、引擎正确消费过的音符，**会被从桶地图里移除**；
       而下面的来源②（桶地图）看不到它们 ⇒ 那些"第一遍的标记"（+0xA8 被接住 / +0x99 / 弧的
       消费态 / +0x30 冻结值）原封不动地留着 ⇒ 回跳之后它们"在未来却标着已打过" ⇒
       渲染按 +0x30 算出 alpha=255 且贴在判定线上 = 幽灵；弧则按旧消费态算裁剪 = 超界/缺段。
       真机物证：`☠ 幽灵长条 t=38648 dt=+26707 +99=1 +A8=1` —— 时刻在未来 26 秒，
       "被接住"却已置 1；而 autoplay 的守卫 `now < t0 → return` 决定了它不可能是刚打上去的。 */
    {
        uint64_t fb = 0, fe = 0;
        if (rd(ng + RPF_VEC2_BEGIN, &fb, 8) && rd(ng + RPF_VEC2_END, &fe, 8) &&
            s_ishp(fb) && s_ishp(fe) && fe > fb && (fe - fb) <= 0x100000) {
            uint64_t nf = (fe - fb) / 8;
            for (uint64_t i = 0; i < nf && n < max; i++) {
                uint64_t note = 0;
                if (!rd(fb + 8 * i, &note, 8) || !s_ishp(note)) continue;
                uint32_t t = 0, te = 0;
                if (!rd(note + 0x18, &t, 4) || !rd(note + 0x1C, &te, 4)) continue;
                if ((int32_t)te - (int32_t)T < 0) continue;   /* 整条都在 T 之前 ⇒ 不是目标 */
                if (rpf_hhas(s_dedup, note)) continue;        /* 去重 */
                rpf_hadd(s_dedup, note);
                out[n++] = note;
            }
        }
    }
    /* ---- 来源②：桶地图 ng+0x88（只有"还没被消费"的音符）—— 与 rpf_sweep 同一套走法 ---- */
    uint64_t bb = 0, be = 0;
    if (!rd(ng + 0x88, &bb, 8) || !rd(ng + 0x90, &be, 8)) return n;
    if (!s_ishp(bb) || !s_ishp(be) || be < bb) return n;
    uint64_t nbs = (be - bb) / 8;
    if (nbs == 0 || nbs > 4096) return 0;
    for (uint64_t bi = 0; bi < nbs && n < max; bi++) {
        uint64_t mp = 0, node = 0;
        if (!rd(bb + 8 * bi, &mp, 8) || !s_ishp(mp)) continue;
        if (!rd(mp, &node, 8) || !s_ishp(node)) continue;
        uint64_t sentinel = mp + 8;
        for (int ni = 0; ni < 8192 && node && node != sentinel && s_ishp(node) && n < max; ni++) {
            uint64_t vb = 0, ve = 0;
            if (rd(node + 40, &vb, 8) && rd(node + 48, &ve, 8) &&
                s_ishp(vb) && s_ishp(ve) && ve >= vb && (ve - vb) <= 0x10000) {
                for (uint64_t p = vb; p < ve && n < max; p += 8) {
                    uint64_t note = 0;
                    if (!rd(p, &note, 8) || !s_ishp(note)) continue;
                    uint32_t t = 0, te = 0;
                    if (!rd(note + 0x18, &t, 4) || !rd(note + 0x1C, &te, 4)) continue;
                    rpf_hadd(s_pres, note);                   /* 在地图里 ⇒ 记入在场集合 */
                    if ((int32_t)te - (int32_t)T < 0) continue;   /* 整条都在 T 之前 ⇒ 不是目标 */
                    if (rpf_hhas(s_dedup, note)) continue;        /* 去重 */
                    rpf_hadd(s_dedup, note);
                    out[n++] = note;
                }
            }
            uint64_t nxt = 0;
            if (!rpf_tree_next(sentinel, node, &nxt)) break;
            node = nxt;
        }
    }
    return n;
}

static void rpf_revive(uint64_t ng, uint32_t T, uint32_t P, int do_write,
                       int *n_reg, int *n_clr, int *n_skip) {
    *n_reg = *n_clr = *n_skip = 0;
    s_reg_pend_n = 0;
    s_rb_pend_n = 0;
    uint64_t mb = 0, me = 0;
    if (!rd(ng + 0x88, &mb, 8) || !rd(ng + 0x90, &me, 8)) return;
    if (!s_ishp(mb) || !s_ishp(me) || me < mb) return;
    uint64_t ngroups = (me - mb) / 8;
    if (ngroups == 0 || ngroups > 256) return;

    /* 目标集**现场取**，不用 s_reg[] 快照 */
    static uint64_t s_live[RPF_LIVE_MAX];
    int nlive = rpf_collect_live(ng, T, s_live, RPF_LIVE_MAX);
    int nabs = 0;
    for (int i = 0; i < nlive; i++)
        if (s_live[i] && !rpf_hhas(s_pres, s_live[i])) nabs++;
    xrc_logd(XRCLC_JUDGE, @"[rpf] ⟲⟲⟲ 复活取数：现场扫到 %d 条（已去重），其中**不在桶地图**的 %d 条（T=%u）",
           nlive, nabs, T);

    for (int k = 0; k < nlive; k++) {
        uint64_t note = s_live[k];
        if (!note) continue;
        uint64_t vt = 0;
        if (!rd(note, &vt, 8) || !s_isptr(vt)) { (*n_skip)++; continue; }
        /* 只放行"可判定音符"。LogicSceneControl 排除：sub_10091B6CC 里有一条
           `slot+4 = max(slot+4, 180000)` 的写（动画管理器状态 4 时），我们不该去触发它。 */
        {
            char nm[96];
            rpf_class_name(vt, nm, sizeof(nm));
            if (!strstr(nm, "Logic") || strstr(nm, "SceneControl")) { (*n_skip)++; continue; }
        }
        uint32_t t = 0, te = 0;
        if (!rd(note + 0x18, &t, 4) || !rd(note + 0x1C, &te, 4)) { (*n_skip)++; continue; }
        if ((int32_t)te - (int32_t)T < 0) continue;  /* 整条都在 T 之前 ⇒ 不复活 */
        /* ⚠ 不做"起点 < 回跳前播放头 P"的过滤：真机日志显示回跳**之前**窗口里同样
           有 dt 到 +15s 的弧 —— 那是长弧的正常表现（长弧的头在很远处，尾早就在判定线附近，
           准入判据 min(note+0x30,note+0x34) < 700 因此为真）。过滤会误杀正常长弧。 */
        uint32_t g = 0;
        if (!rd(note + 0x50, &g, 4) || g >= ngroups) { (*n_skip)++; continue; }
        if (do_write) {
            if (rpf_clear_note(note, T) > 0) (*n_clr)++;
            /* ★★★ **树的插入必须搬到主线程**。
               根因：sub_10091B6CC 会往 ng+0x88 的**红黑树**里插节点（find-or-create + 旋转），
               在**探针线程**上调它时，主线程同一时刻正在准入里读/建同一棵树
               （准入也调 sub_100922998，它会建节点）⇒ 并发改树 ⇒ 树结构损坏
               （崩溃链：场景析构 sub_100CAA334 → 递归删树 sub_100913A40，
               KERN_INVALID_ADDRESS + "possible pointer authentication failure"）。
               做法：把插入整批丢到主队列 —— 主队列与游戏 tick 同在主线程、由同一个
               runloop 串行执行（外层 XRCGameplay 的 xrc_gameplay_update 就是主线程 tick），
               所以不会与准入并发。清理那几个字节是单字节写、与引擎的单字节写撞上也无害，
               仍留在原线程做。 */
            /* **只登记桶地图里没有的**（复活的语义 = 恢复被引擎移除过的）。
               在地图里的再登记一次 = 让引擎按 [t0,te] 跨度重复插一整遍（真机 17.4 槽/条），
               每回跳一次灌 7 万条 ⇒ 卡死 + 同一弧每帧被处理十几遍。 */
            if (!rpf_hhas(s_pres, note)) {
                if (s_reg_pend_n < RPF_PEND_MAX) s_reg_pend[s_reg_pend_n++] = note;
            } else {
                (*n_skip)++;
            }
            /* 重建（渲染工厂）吃**过检后的全量** —— 与登记的门控解耦：
               与登记绑定会在"不在场为 0"（真机常态 M=0）时一次都不跑 ⇒ 弧缺段/黑线回归。 */
            /* 全量里要**剔除没有渲染对象的音符**（note+0x40 == 0）：渲染对象是引擎**按入场
               逐个建的**——未来音符本没有对象，全量重建会给它们凭空造出对象，其分段/连线
               处在未初始化态 ⇒ 判定面上多出一大堆杂线（真机截图：多出成扇形的细直线）。
               +0x40 有效的音符 = 本来就有渲染对象（被回跳破坏的那批）⇒ 只重建它们；
               没有对象的留给引擎入场时正常创建。 */
            {
                uint64_t rn = 0;
                if (rd(note + 0x40, &rn, 8) && s_isptr(rn)) {
                    if (s_rb_pend_n < RPF_PEND_MAX) s_rb_pend[s_rb_pend_n++] = note;
                }
            }
        }
    }
    /* 整批丢到主队列执行（与游戏 tick 串行，绝不与准入并发改树） */
    {
        uint64_t scene = xrc_gameplay_instance();
        if (s_reg_pend_n > 0) rpf_revive_dispatch(scene, s_reg_pend_n);
        /* 把**全量**音符交给渲染工厂重建渲染对象（开关默认关，见 rpf_rebuild_main 长注释）。
           顺序：主队列 FIFO ⇒ 登记先、重建后 */
        if (s_do_write && s_rebuild_on && s_rb_pend_n > 0)
            rpf_rebuild_dispatch(scene, s_rb_pend_n);
        *n_reg = s_reg_pend_n;   /* 报告**实际派发**的登记条数 */
    }
}

// ---- 一次完整的回跳重置：三笔写 + 自检（顺序：清分 → 清消费 → 开闸门 → 复读）----
static void rpf_reset(uint64_t ng, uint32_t T, uint32_t P) {
    s_rst_seq++;
    xrc_logd(XRCLC_JUDGE, @"[rpf] ⟲⟲⟲ 回跳重置 #%d：T=%u P=%u（**落笔=%s** 闸门=%s 清消费=%s 清分=%s）",
           s_rst_seq, T, P,
           s_do_write ? "ON" : "OFF(readonly)",
           s_no_gate ? "OFF" : "ON", s_no_pred ? "OFF" : "ON", s_no_score ? "OFF" : "ON");

    if (!s_no_score) rpf_score_reset(ng, T);
    if (s_do_write) { rpf_tree_check(ng, "清分后"); }
    rpf_cmap_stage(ng, "清分后");      /* 谱面表（chart+0x80）在这一刻是否还健康 */

    // 事件派发器的同时间去重表 —— 不清它，回跳后所有打击事件被静默吞掉（失声）
    if (s_do_write) {
        int ce = rpf_clear_event_dedup();
        if (ce < 0) xrc_logd(XRCLC_JUDGE, @"[rpf] ⟲⟲⟲ 事件去重表：找不到派发器（app=%s）", "?");
    }

    s_walk_n = 0;
    rpf_seen_reset();
    rpf_sweep_t s;
    memset(&s, 0, sizeof(s));
    rpf_sweep(ng, T, /*do_write=*/1, &s);
    {
        char hist[420];
        int off = snprintf(hist, sizeof(hist),
                           "[rpf] ▣ 走查：%d 条（tap 族 %d / 长条 %d / 未知 %d）清掉 %d 个字段 ｜ 类名:",
                           s.seen, s.tap, s.lng, s.other, s.cleared);
        for (int i = 0; i < s.nh && off < (int)sizeof(hist) - 60; i++)
            off += snprintf(hist + off, sizeof(hist) - off, " %s×%d", s.hname[i], s.hcnt[i]);
        xrc_logd(XRCLC_JUDGE, @"%s", hist);
        xrc_logd(XRCLC_JUDGE, @"[rpf] ▣ map 覆盖面：条目 %d（去重后 %d 个对象）t∈[%d,%d]（最早一条 @%llx）key 头几个:",
               s.seen, s.dist, s.tmin, s.tmax, (unsigned long long)s.tmin_n);
    }

    if (s_do_write) { rpf_tree_check(ng, "走查后"); }
    rpf_cmap_stage(ng, "走查后");      /* 谱面表分阶段自检 */

    // 复活：现场扫到的音符清消费 + **重新登记回 map**。
    // 这一步必须在走查之后 —— 走查清的是"还在 map 里（即还没播过）"的那批。
    {
        int nr = 0, nc = 0, ns = 0;
        rpf_revive(ng, T, P, s_do_write && !s_no_pred, &nr, &nc, &ns);
        xrc_logd(XRCLC_JUDGE, @"[rpf] ⟲⟲⟲ 复活：实际登记 %d 条 / 重建 %d 条 / 清掉字段 %d 条 / 跳过 %d 条（T=%u）",
               nr, s_rb_pend_n, nc, ns, T);
        s_rereg_n = nr;
    }

    // **长条/弧的触摸态清理**（机制见 rpf_clear_touch_state 上方注释）——
    // 这是"渲染时机和状态不对"的正解。
    if (s_do_write) {
        int nnote = 0, nfield = 0, nvd = 0, nsegv = 0, nseg = 0;
        s_cpos_restored = 0;
        /* 目标集**现场取**（同 rpf_collect_live），不用 s_reg[] 快照：
           "vtable 与快照一致"挡不住**同类对象复用**（复用后 vtable 一模一样）。 */
        static uint64_t s_live2[RPF_LIVE_MAX];
        int nlive2 = rpf_collect_live(ng, T, s_live2, RPF_LIVE_MAX);
        for (int k = 0; k < nlive2; k++) {
            uint64_t note = s_live2[k];
            if (!note) continue;
            uint64_t vt = 0;
            if (!rd(note, &vt, 8) || !s_isptr(vt)) continue;
            uint32_t t = 0, te = 0;
            if (!rd(note + 0x18, &t, 4) || !rd(note + 0x1C, &te, 4)) continue;
            if ((int32_t)te - (int32_t)T < 0) continue;
            rpf_touch_t st;
            int rs = rpf_clear_touch_state(note, &st, nvd < 4);
            if (rs > 0) { nnote++; nfield += rs; if (rs) nvd++; }
            /* 弧的造型子节点——“头过线”只藏不显，回跳到弧开始之前时需要恢复 */
            {
                char nm2[96];
                rpf_class_name(vt, nm2, sizeof(nm2));
                /* **不限制"开始时间 >= T"**：回跳到弧**内部**时（start < T < end），引擎自己的
                   sub_100AFFA90 会因为 arc+0x18 < now 成立而重新跑，把"头之后"的再藏一遍
                   ⇒ 显回是安全且自愈的。 */
                /* 渲染重建已接管"弧分段" ⇒ 默认不做这种**裸虚调用**重显：
                   对登记表里可能已被释放/复用的对象直接 vt[42](child,1) 是崩溃风险。
                   函数保留、由 !s_rebuild_on 门控（重建关时仍走此路径）。 */
                if (!s_rebuild_on && strstr(nm2, "Arc") && !strstr(nm2, "ArcTap")) {
                    int sg = rpf_reshow_arc_children(note, nsegv < 4, 1);
                    if (sg > 0) { nseg += sg; nsegv++; }
                }
            }
        }
        xrc_logd(XRCLC_JUDGE, @"[rpf] ⟲⟲⟲ 触摸态：%d 条长条/弧有残留，清掉 %d 处 ｜ 弧造型子节点显回 %d 个"
               " ｜ 其中坐标写回原始曲线的 %d 个",
               nnote, nfield, nseg, s_cpos_restored);
    }

    if (s_do_write) { rpf_tree_check(ng, "运行期态/重登记后"); }
    rpf_cmap_stage(ng, "运行期态/重登记后");   /* 谱面表分阶段自检 */

    // **谱面自带的"按桶隐藏"指令**（SceneControl 命令）—— 不清它，渲染节点被 setVisible(0)
    if (s_do_write) {
        int nb = rpf_clear_buckets(ng, T);
        xrc_logd(XRCLC_JUDGE, @"[rpf] ⟲⟲⟲ 跳桶：清了 %d 个被隐藏的桶（桶时间 >= T）", nb);
    }

    {
        int slots = 0, set = 0;
        int w = s_do_write && !s_no_gate;
        rpf_open_gates(ng, T, &slots, &set, w);
        xrc_logd(XRCLC_JUDGE, @"[rpf] ⟲⟲⟲ 开闸门：槽 %d 个，%s %d 个（时间 < T 的不动）",
               slots, w ? "set" : "would-set", set);
    }

    // 自检：复读判据（只读）。要求"T 之后判据仍为 1"= 0。
    {
        rpf_sweep_t v;
        memset(&v, 0, sizeof(v));
        rpf_sweep(ng, T, /*do_write=*/0, &v);
        xrc_logd(XRCLC_JUDGE, @"[rpf] ⟲⟲⟲ 自检：T 之后 %d 条音符（tap 族 %d / 长条 %d / 未知类 %d），"
               "判据仍为 1 的 = %d（要求 0）",
               v.seen, v.tap, v.lng, v.other, v.still);
        // 重登记后 map 覆盖起点应落在 T 附近。
        xrc_logd(XRCLC_JUDGE, @"[rpf] ⟲⟲⟲ 自检·map 起点：tmin=%d tmax=%d（T=%u）",
               v.tmin, v.tmax, T);
    }
}

// ================================================================ 谱面表看门狗
// 崩溃链（多次崩溃报告故障地址逐字节相同 = 0xa9417bfd94edf96c，possible pointer
// authentication failure；开着 ASLR 还完全相同 ⇒ **确定性的数据写坏**，不是并发抖动）：
//
//   ~LogicChart = sub_100913724
//     -> sub_100913A40(alloc = chart+0x80, node = *(chart+0x88))
//        = 递归删树：del([n]); del([n+8]); operator delete(n)
//   故障寄存器：x20 = x0 = 0x10bf712c0 = chart + 0x80
//               （chart = 0x10bf71240 = 日志里的 ng+0x28，两者对得上）
//               x1  = x19 = 0xa9417bfd94edf96c —— 那一层的「节点」指针
//   递归帧 0x913a60×4 + 0x913a6c×6 ⇒ 树高约 11 层
//
// 这张表是什么（全部静态定死，附出处）：
//   · LogicChart 在工厂 sub_100C82958 里 new(0x118)，构造函数体 = sub_10090DCA0
//     （xref 核实：_ZTV10LogicChart 只被 sub_100C82958 引用）。
//   · ctor 里：`*(this+0x80) = this+0x88; *(this+0x88) = 0; *(this+0x90) = 0`
//     —— 正是 libc++ __tree 的 {__begin_node_, __end_node_.__left_(根), __size_}
//     ⇒ **chart+0x80 是一张内联 std::multimap，根在 +0x88，条目数在 +0x90**。
//   · 灌表链：sub_10090DCA0 -> sub_10090EC0C（谱面解析器，X19 = chart）
//             -> `ADD X0, X19, #0x80; BL sub_100917D3C`（4 处，按音符类型分派）
//   · sub_100917D3C：node = new(0x30)（0x20 头 __tree_node_base + 0x10 值@+0x20），
//     比较键 = *(u32*)(node+0x20)；下降只有 `CMP W8,W9; B.GE` 两条分支 ——
//     **没有相等分支**（k >= nodekey 就走右）⇒ 它是 __insert_multi，即 multimap。
//   · ⚠ **全程序 sub_100917D3C 的调用者只有 sub_10090EC0C 一处**（xref 核实）
//     ⇒ 这张表**只在构造期灌一次，运行期没有任何插入者/擦除者**。
//
// ⇒ 结论：它的某个节点的 left/right 里出现野值，**只能是别人越界写进来的**
//   （8 字节的数据落在 node+0 / node+8 上）。所以这个看门狗不是去猜是谁，而是把
//   「哪一刻、哪个节点、哪个字段、原值多少」钉死 —— 50ms 粒度，一次真机就能定位。
//   同时每拍记录 **条目数 +0x90**：这张表只该在构造期增长，运行期一旦变化就是铁证。
// 这张表的节点布局（`▣ 首节点 @280f6fc00` 的原始 dump 逐字节对出来的）：
//   +0 left（0 或节点） / +8 right / +0x10 parent / +0x18 __is_black_（只能 0/1）
//   / +0x20 键（i32）
// ⚠ 判据不能用"是不是 s_isptr"——s_isptr 的区间太宽：根曾被写成 0x200000000
//   （= 2<<32）照样通过，遍历会一头扎进**只读代码段**。三项硬判据：8 字节对齐 +
//   __is_black_ ∈ {0,1} + __parent_ 要么 0 要么是合法指针（0x200000000 会在 parent 上被挡下）。
static bool rpf_node_ok(uint64_t n) {
    if (!s_isptr(n)) return false;
    if (n & 7) return false;
    uint8_t blk = 0;
    if (!rd(n + 0x18, &blk, 1)) return false;
    if (blk > 1) return false;
    uint64_t par = 0;
    if (!rd(n + 0x10, &par, 8)) return false;
    if (par && !s_isptr(par)) return false;
    return true;
}

static int rpf_cmap_walk(uint64_t chart, const char *stage, int verbose) {
    uint64_t root = 0;
    if (!rd(chart + 0x88, &root, 8)) return -1;
    if (root == 0) return 0;                       /* 空表：正常（尚未灌 / 已清） */
    int fixed = 0;
    /* **修"槽"而不是修"指针"**：根曾被写成 0x200000000，照那个值去清零会打到一块
       **只读的代码段**上、写入失败 ⇒ 自愈不生效。
       正确做法：每个节点在栈里带上"持有它的那个字段的地址"——根是 chart+0x88，子节点是
       父节点的 +0 / +8。这些槽**全都在堆上、一定可写**，清零一定成功。
       （节点真相：`▣ 首节点 @280f6fc00` 的原始 dump 证实布局 = left@+0 / right@+8 /
         parent@+0x10 / is_black@+0x18 / key32@+0x20，与 sub_100913A40 读 [n]、[n+8] 一致。） */
    struct { uint64_t node, slot; } stk[192];
    int sp = 0, seen = 0, maxd = 0;
    stk[sp].node = root;
    stk[sp].slot = chart + 0x88;
    sp++;
    while (sp > 0 && seen < 9000) {
        uint64_t n = stk[sp - 1].node, slot = stk[sp - 1].slot;
        sp--;
        seen++;
        if (sp > maxd) maxd = sp;
        if (!rpf_node_ok(n)) {
            xrc_logd(XRCLC_JUDGE, @"[rpf] §CMAP %s chart=%llx **节点 %llx 不是合法 map 节点**"
                   "（持有它的槽 %llx，第 %d 步）→ 清零该槽自愈",
                   stage, chart, n, slot, seen);
            if (wr64z(slot)) {
                fixed++;
                xrc_logd(XRCLC_JUDGE, @"[rpf] §CMAP %s → 槽 %llx 已清零（放掉这棵子树，本局不再因它崩）",
                       stage, slot);
            }
            continue;
        }
        uint64_t l = 0, r = 0, p = 0, k = 0;
        {   /* 一次 0x28 字节读拿到 left/right/parent/key32：看门狗每秒都跑，
               把每次遍历的 syscall 从 4N 降到 N（这台机器上 ~1300 个节点）。 */
            uint8_t raw[0x28];
            if (!rd(n, raw, sizeof(raw))) {
                xrc_logd(XRCLC_JUDGE, @"[rpf] §CMAP %s chart=%llx 节点 %llx 读不出来（第 %d 步）",
                       stage, chart, n, seen);
                continue;
            }
            memcpy(&l, raw, 8); memcpy(&r, raw + 8, 8);
            memcpy(&p, raw + 0x10, 8); memcpy(&k, raw + 0x20, 8);
        }
        (void)p; (void)k;
        /* 子节点连「持有它的槽地址」一起入栈 —— 合法性判据统一在弹出时由
           rpf_node_ok 做（对齐 + is_black∈{0,1} + parent 合法）。坏的那个槽要么是
           父节点的 +0（left）要么是 +8（right），一眼可辨。 */
        if (l && sp < 190) { stk[sp].node = l; stk[sp].slot = n;     sp++; }
        if (r && sp < 190) { stk[sp].node = r; stk[sp].slot = n + 8; sp++; }
    }
    if (verbose)
        xrc_logd(XRCLC_JUDGE, @"[rpf] §CMAP %s chart=%llx 表健康：节点=%d 栈深=%d 修复=%d",
               stage, chart, seen, maxd, fixed);
    return fixed ? 2 : 0;
}

static uint64_t s_last_chart;
static int      s_cmap_tick;
static uint64_t s_last_c80, s_last_c88, s_last_c90, s_last_c98;

// 重置各阶段调用（chart 从 ng+0x28 现取）
static void rpf_cmap_stage(uint64_t ng, const char *stage) {
    uint64_t chart = 0;
    if (!ng || !rd(ng + 0x28, &chart, 8) || !s_isptr(chart)) return;
    rpf_cmap_walk(chart, stage, 0);
}

// ---------------------------------------------------------------- 重置在主队列执行（与游戏 tick 串行）
// 症状是**低概率随机**（弧超界 / 不显示 / 幽灵事件），不是规律触发 ⇒ 指向**竞态**：
// 快路径跑在自己的 pthread 上（本文件 rpf_thread），而重置的六笔清洗（清分 / 解除消费 /
// 开闸门 / 触摸态 / 事件去重表 / 重登记）若在那条线程上直接落笔，就与游戏主线程并发
//（复活与重建即因同样原因挪到主队列——「与游戏 tick 串行，绝不与准入并发改树」）。
// ⇒ 快路径**只检出**（三次只读），检到后把重置派发到主队列执行。主队列 FIFO 保证
//   「重置 → 复活 → 重建」的顺序（后两者本来就在 rpf_reset 内部派发）。
typedef struct {
    uint64_t ng;
    uint32_t T, P;
} rpf_reset_job_t;

// 清 autoplay 的「每音符一次」闩（XRCHook 的 xrc_ap_latch_reset）。
// 回跳后播放头会再次经过同一批音符，而闩还记着"已派发"⇒ 那一笔一次性引擎调用
// （弧消费 / 长条标记）永远不会再跑 ⇒ 重放后弧超界 / 双天地双押连线消失。
// 场景切换同样要清（新歌里指针与 t0 可能重合 ⇒ 误闩）。
static void rpf_ap_latch_reset(void) {
    xrc_ap_latch_reset();   /* 直连（extern 声明见本文件顶部） */
}

// 冻结窗收口（xrc_freeze_end 直连）。外层在"回退式 seek"时开冻结窗
// （音频暂停 + 钟钉住），等待重置链跑完；链尾调用本函数 ⇒ 恢复音频 + 进收敛窗。
// 设计全链：内部设计纪要（离线记录）
static void rpf_freeze_end(void) {
    xrc_freeze_end();   /* 直连（extern 声明见本文件顶部） */
}

static void rpf_reset_main(void *ctx) {
    rpf_reset_job_t *j = (rpf_reset_job_t *)ctx;
    if (!j) return;
    rpf_ap_latch_reset();          /* 先清闩，再走清洗/复活/重建 */
    rpf_reset(j->ng, j->T, j->P);
    /* 冻结窗收口。常规路径由**重建任务末尾**收口（它是链上最后一棒）；
       这里只兜「本帧不会有后续任务」的情形（重建未派发 且 复活也未派发）。 */
    {
        int more = 0;
        if (s_do_write && s_rebuild_on && s_rb_pend_n > 0) more = 1;   // 重建将收口
        if (s_reg_pend_n > 0) more = 1;                                // 复活将在重建之前跑
        if (!more) rpf_freeze_end();
    }
    free(j);
}

static void rpf_reset_dispatch(uint64_t ng, uint32_t T, uint32_t P) {
    rpf_reset_job_t *j = (rpf_reset_job_t *)calloc(1, sizeof(*j));
    if (!j) return;
    j->ng = ng; j->T = T; j->P = P;
    dispatch_async_f(dispatch_get_main_queue(), j, rpf_reset_main);
}

// ---------------------------------------------------------------- 弧分段「不藏」开关
// **只在 seek 回跳发生时**把弧的「藏」反过来变成「显」。dylib 侧的桩打在
// setVisible 的实参上，handler 平时写 0（=原行为），置位后写 1（=显回来）。
// 窗口 = 回跳那一刻 → 播放头重新涨回**回跳前的水位 P**；过了 P 之后前方的弧全是"新"的，
// 隐藏行为本来就正确，所以自动关。另加 60s 安全上限（≈1200 拍）兜底。
// 未置位时本模块**一个字节都不发** ⇒ 正常游玩零影响。
static int      s_nh_on    = 0;
static uint32_t s_nh_P     = 0;
static int      s_nh_left  = 0;      /* 剩余拍数（安全上限） */

static void rpf_nohide_begin(uint32_t P) {
    s_nh_P = P;
    s_nh_left = 1200;                    /* 50ms × 1200 = 60s */
    if (!s_nh_on) {
        s_nh_on = 1;
        xrc_arc_nohide_set(1);
        xrc_logd(XRCLC_JUDGE, @"[rpf] ⟲ 弧分段「不藏」开启：窗口到水位 P=%u（涨回来自动关）", P);
    }
}

static void rpf_nohide_tick(uint32_t now) {
    if (!s_nh_on) return;
    if (s_nh_left > 0) s_nh_left--;
    int caught = ((int32_t)s_nh_P - (int32_t)now) < 500;   /* 已涨回（或越过）旧水位 */
    if (caught || s_nh_left <= 0) {
        s_nh_on = 0;
        xrc_arc_nohide_set(0);
        xrc_logd(XRCLC_JUDGE, @"[rpf] ⟲ 弧分段「不藏」关闭（%s）：now=%d P=%u",
               caught ? "已涨回旧水位" : "超时 60s", (int)now, s_nh_P);
    }
}

static void rpf_fast_tick(void) {
    uint64_t scene = xrc_gameplay_instance();
    if (!s_ishp(scene)) scene = 0;
    if (scene != s_last_scene) {
        xrc_logd(XRCLC_JUDGE, @"[rpf] 场景变化 %llx → %llx：归零水位线与稳定计数（本拍不动作）",
               s_last_scene, scene);
        rpf_ap_latch_reset();         /* 新场景必须清闩（指针可能被复用 ⇒ 否则 autoplay 哑掉） */
        s_last_scene = scene;
        s_seek_wm = 0;
        s_last_ng = 0;
        s_ng_stable = 0;
        s_last_chart = 0;
        s_last_c80 = s_last_c88 = s_last_c90 = s_last_c98 = 0;
        return;
    }
    uint64_t ng = 0;
    if (scene) {
        rd(scene + RPF_NOTEGRP, &ng, 8);
        if (!s_ishp(ng)) ng = 0;       /* 场景重建期间这里是野值，当没有 */
    }
    if (ng != s_last_ng) { s_last_ng = ng; s_ng_stable = 0; }
    else if (s_ng_stable < 1000) s_ng_stable++;

    // 谱面表看门狗（机制见 rpf_cmap_walk 上方注释）。
    //   每拍：chart 指针变了立刻报 —— 表被换掉/被释放都是大事件；
    //   每 20 拍（≈1s）：走一遍表；异常时把节点/字段/原值全打出来。
    //   每拍：把「条目数 +0x90」记下来 —— 这张表只该在构造期增长。
    if (ng) {
        uint64_t chart = 0;
        if (rd(ng + 0x28, &chart, 8) && !s_isptr(chart)) chart = 0;
        /* **每 50ms 盯住 chart+0x80..0xA0 这四个字**。
           真机铁证：这张表曾在 0.4 秒内从「383 条目、遍历健康」变成「根 = 0x200000000」。
           而 0x200000000 恰好是原根（节点全在 0x2_80xxxxxx 区，如首节点 0x280f6fc00）
           **低 32 位被清零**的结果 ⇒ 坏它的那一笔是**打在 chart+0x88 上的 4 字节写零**，
           不是野指针。50ms 一拍地记下这四个字的变化，就能把那 0.4s 收窄到 50ms，
           再对着同一刻本模块自己的动作（清分 / 走查 / 复活 / 触摸态）一眼定人。 */
        uint64_t c80 = 0, c88 = 0, c90 = 0, c98 = 0;
        if (chart) {
            rd(chart + 0x80, &c80, 8); rd(chart + 0x88, &c88, 8);
            rd(chart + 0x90, &c90, 8); rd(chart + 0x98, &c98, 8);
        }
        if (chart != s_last_chart || c80 != s_last_c80 || c88 != s_last_c88 ||
            c90 != s_last_c90 || c98 != s_last_c98) {
            xrc_logd(XRCLC_JUDGE, @"[rpf] §CMAP 头四字变化 chart=%llx（ng=%llx）"
                   " | +80=%llx→%llx +88=%llx→%llx +90=%llx→%llx +98=%llx→%llx",
                   chart, ng, s_last_c80, c80, s_last_c88, c88,
                   s_last_c90, c90, s_last_c98, c98);
            if (chart != s_last_chart) {
                s_last_chart = chart;
                if (chart) rpf_cmap_walk(chart, "换表", 1);
            }
            s_last_c80 = c80; s_last_c88 = c88; s_last_c90 = c90; s_last_c98 = c98;
        }
        if (chart) {
            if ((s_cmap_tick % 20) == 0) {
                uint64_t c90 = 0;
                rd(chart + 0x90, &c90, 8);
                if (rpf_cmap_walk(chart, "快拍", 0) == 0 && (s_cmap_tick % 400) == 0)
                    xrc_logd(XRCLC_JUDGE, @"[rpf] §CMAP 快拍 chart=%llx 条目数(+0x90)=%llu", chart, c90);
            }
            s_cmap_tick++;
        }
    }

    if (ng) {
        uint64_t clk = 0;
        if (rd(ng + 0x30, &clk, 8) && s_ishp(clk)) {
            uint32_t now = rpf_now_ms(ng);
            rpf_nohide_tick(now);   /* 回跳窗口的收尾（涨回旧水位/超时即关） */
            // 必须用**有符号比较**：前导期播放头为负，`rpf_now_ms` 返回的 uint32 落在
            //   UINT32_MAX 附近（真机：4294966955 → 4294967005），无符号下 `now + 300`
            //   回绕成 9 ⇒ 每首歌的前导期都会被误判成回跳。有符号下
            //   `-291 + 300 = 9 < -341` 为假；真正的回跳（30000 → 0）`0 + 300 < 30000` 仍为真。
            int32_t dnow = (int32_t)now, dwm = (int32_t)s_seek_wm;
            /* 拖动 seek（实时对齐预览）会话：钟在跟随手指移动 —— **水位线冻结 + 不检出**，
               否则拖动中的钟回落会被当成回跳：重播事务会在拖动中途触发、冻结窗把钟钉住。
               松手后由提交/检出按最终目标走常规路径；豁免窗 = 最近一次拖动落笔后 500ms。 */
            if (xrc_real_now_us() - xrc_gameplay_scrub_us() < 500000ULL) {
                /* 拖动中：不动水位线、不检出 */
            } else if (dnow < -60000 || dnow > 600000) {
                /* 垃圾闸门：退场/过场时引擎字段会读成亿级野值——在垂死的场景上跑带垃圾 P 的
                   重置有污染下一首的风险。只采信 [-60s, 10min] 内的读数；野值不更新
                   水位线、不检出。 */
                /* 野值：忽略 */
            } else if (s_seek_wm && dnow + 300 < dwm) {
                xrc_logd(XRCLC_JUDGE, @"[rpf] ⟲ 检出回跳：%d → %d（回落 %d ms）ng 已稳定 %d 拍",
                       dwm, dnow, dwm - dnow, s_ng_stable);
                s_seek_wm = now;
                /* 回跳窗口内把弧分段的「藏」反过来（dylib 桩），涨回旧水位自动关。
                   与重置同门控：replay_arm 不在时整体不介入。 */
                /* 重建开启时**不反着改可见性** —— 引擎逐帧把"头之后"的分段藏掉是
                   *正常裁剪*（弧该停在判定线），把 W1 改成 1 等于把它留住 ⇒ 弧穿透判定线。 */
                if (s_arm_on && !s_rebuild_on) rpf_nohide_begin((uint32_t)dwm);
                // **引擎状态重置**（三笔写 + 自检）。这是全部动作的唯一入口。
                // 只做"清零 + 开闸门"，不重建任何对象、不释放任何东西、不碰节点树。
                // **主队列执行**（探针线程只检出，不落笔）—— 见 rpf_reset_dispatch 上方注释。
                if (s_arm_on && dnow >= 0 && dnow < 3600000) {
                    xrc_logd(XRCLC_JUDGE, @"[rpf] ⟲ 重置派发到主队列：T=%d P=%d（探针线程只检出）", dnow, dwm);
                    rpf_reset_dispatch(ng, (uint32_t)dnow, (uint32_t)dwm);
                }
                else if (s_arm_on)
                    xrc_logd(XRCLC_JUDGE, @"[rpf] ⟲⟲⟲ 跳过重置：now=%d 不在 [0,3600000)", dnow);
            } else if (dnow > (int32_t)s_seek_wm) {
                s_seek_wm = now;
            }
        }
    }
}

// 显式重播请求（暂停驻停提交用）——与自动检出同一入口，但由调用方给目标 T。
// 语义：P = 当前水位线（回跳前的高水位；无则取 T）；随后把水位线**消化**到 T
// （防自动检出对同一次回跳再触发一遍）。总门关 / 目标越界 / 场景无效 = 无害空操作。
void xrc_replay_request_reset(uint32_t T) {
    if (!s_arm_on) { xrc_logd(XRCLC_JUDGE, @"[rpf] 显式重播请求被忽略（总门关）"); return; }
    if (T >= 3600000) return;
    uint64_t scene = xrc_gameplay_instance();
    uint64_t ng = 0;
    if (!scene || !rd(scene + RPF_NOTEGRP, &ng, 8) || !s_ishp(ng)) return;
    uint32_t P = s_seek_wm ? s_seek_wm : T;
    s_seek_wm = T;
    xrc_logd(XRCLC_JUDGE, @"[rpf] ⟲ 显式重播请求（暂停驻停提交）：T=%u P=%u", T, P);
    rpf_reset_dispatch(ng, T, P);
}

// ---------------------------------------------------------------- 常驻线程与对外接口
// 线程只做"检出"：每 50ms 一次 rpf_fast_tick（三次只读）；检出回跳后把重置派发到主队列
// 执行（重置→复活→重建，主队列 FIFO）。无寿命上限，随进程退出。
static void *rpf_thread(void *arg) {
    (void)arg;
    for (;;) {
        usleep(RPF_TICK_MS * 1000);
        rpf_fast_tick();
    }
    return NULL;   /* 不可达 */
}

void xrc_replay_start(void) {
    static int started = 0;
    if (started) return;   /* 幂等 */
    started = 1;
    pthread_t t;
    if (pthread_create(&t, NULL, rpf_thread, NULL) != 0)
        xrc_logw(XRCLC_JUDGE, @"[rpf] 常驻线程创建失败；回跳重播不可用");
}

void xrc_replay_set_enabled(bool on) { s_arm_on = on ? 1 : 0; }
bool xrc_replay_enabled(void) { return s_arm_on != 0; }

