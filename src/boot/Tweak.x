// © 雾月星辰 & MLXC · github@XingChenRS
// Tweak.x — xrcdemo bootstrap + 悬浮球 UI（悬浮球逻辑见 XRCFloatButton）。
// 游戏逻辑全部在 XRC* 模块；交互全部在 XRCPracticePanel（ArcCreate 同构）。
// 版本与构建标识：统一来源 XRCVersion.h（基线 = Arcaea iOS 7.0.255；跨版本适配见 README §6）。

#import <substrate.h>
#import <time.h>
#include <string.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <sys/time.h>
#import <stdatomic.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>

#import "fishhook.h"
#import "XRCFloatButton.h"
#import "XRCPracticePanel.h"
#import "WHToast/WHToast.h"

#include "XRCLog.h"
#include "XRCVersion.h"
#include "XRCProfile.h"
#include "XRCRuntime.h"
#include "XRCProbe.h"
#include "XRCClock.h"
#include "XRCPlayer.h"
#include "XRCGameplay.h"
#include "XRCJudge.h"
#include "XRCConfig.h"
#include "XRCHook.h"
#include "XRCDump.h"
#include "XRCNet.h"
#include "XRCOMLog.h"
#include "XRCReplay.h"
#include "XRCStore.h"
#include "XRCAudio.h"

extern UIApplication *UIApp;


#pragma mark - 全局 UI 状态（配置快照 + 控件）

static xrc_config_t g_cfg = {0};
XRCFloatButton *button = nil;   // XRCLog.h extern（UI hook 引用）
#if !XRC_DEBUG_BUILD
// 发布构建：常驻可见水印（防滥用威慑 ＋ 泄漏溯源）。运行时绘制文本、不可交互、
// 配置关不掉；与悬浮球同一套「窗口置顶」管理（见下方 UIWindow hook）。
NSArray<UILabel *> *g_mark = nil;
#endif

#pragma mark - 主程序定位（唯一跨模块的 image base 实现）

uint64_t xrc_image_base(void) {
    static uint64_t cached = 0;
    if (cached) return cached;
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        if (strstr(name, ".dylib") != NULL) continue;
        const char *slash = strrchr(name, '/');
        if (slash && strcmp(slash + 1, "Arc-mobile") == 0) {
            cached = (uint64_t)_dyld_get_image_header(i);
            break;
        }
    }
    if (!cached && n > 0)
        cached = (uint64_t)_dyld_get_image_header(0);
    return cached;
}

#pragma mark - 菜单（UI 逻辑，配置读写走 XRCConfig）

// 练习面板桥接：XRCMenuBridge 供 UIWindow hook 引用，转发到 XRCPracticePanel。
@interface XRCMenuBridge : NSObject
+ (instancetype)shared;
- (void)show;
- (void)hide;
- (UIWindow *)keyWindow;
@end

@implementation XRCMenuBridge
+ (instancetype)shared {
    static XRCMenuBridge *s = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [XRCMenuBridge new]; });
    return s;
}
- (void)show { [[XRCPracticePanel shared] show]; }
- (void)hide { [[XRCPracticePanel shared] hide]; }
- (UIWindow *)keyWindow {
    if ([UIApp.delegate respondsToSelector:@selector(window)]) {
        UIWindow *w = [UIApp.delegate performSelector:@selector(window)];
        if (w) return w;
    }
    for (UIWindow *w in UIApp.windows) if (w.isKeyWindow) return w;
    return UIApp.windows.firstObject;
}
@end

#pragma mark - UI overlay

%group ui
%hook NSBundle
+ (NSBundle *)bundleForClass:(Class)aClass {
    if (aClass == [%c(WHToastView) class]) {
        NSBundle *main = [NSBundle mainBundle];
        return main ?: %orig;
    }
    return %orig;
}
%end

%hook UIWindow
- (void)bringSubviewToFront:(UIView *)view {
    %orig;
    if (view == button) return;
    if (button) %orig(button);
#if !XRC_DEBUG_BUILD
    if (g_mark && ![g_mark containsObject:(id)view])
        for (UIView *m in g_mark) %orig(m);
#endif
    // 练习面板自身管理层级（show 时已 bringSubviewToFront）
}
- (void)addSubview:(UIView *)view {
    %orig;
    if (view == button) return;
    if (button) [self bringSubviewToFront:button];
#if !XRC_DEBUG_BUILD
    if (g_mark && ![g_mark containsObject:(id)view])
        for (UIView *m in g_mark) %orig(m);
#endif
}
%end
%end

#pragma mark - floating button bootstrap

static void initButton(void) {
    [WHToast setShowMask:NO];
    button = [XRCFloatButton shared];
    // 单击 = 开/关练习面板
    button.onTap = ^{
        if ([[XRCPracticePanel shared] isVisible])
            [[XRCMenuBridge shared] hide];
        else
            [[XRCMenuBridge shared] show];
    };
    // 长按 = 切换速度预设
    button.onLongPress = ^{
        xrc_config_load(&g_cfg);   // 读取最新配置（面板可能已改预设/开关）
        if (g_cfg.speed_count <= 0) return;
        g_cfg.rate_index = (g_cfg.rate_index + 1) % g_cfg.speed_count;
        xrc_clock_set_rate((double)g_cfg.speeds[g_cfg.rate_index]);
        xrc_config_save(&g_cfg);
        if (g_cfg.toast) {
            [WHToast showMessage:[NSString stringWithFormat:@"%.3fx (tap opens menu)", g_cfg.speeds[g_cfg.rate_index]]
                                       duration:0.5 finishHandler:^{}];
        }
    };
    UIWindow *w = [[XRCMenuBridge shared] keyWindow];
    [button attachToWindow:w];
    if (!g_cfg.button_enabled) [button setHiddenState:YES];
#if !XRC_DEBUG_BUILD
    /* 运行时可见水印（发布构建）。设计取舍：
       · 位置＝屏幕**顶部中央**：顶缘中带远离操作区与判定线（不碍游玩），
         且居中一字排开难以被局部遮挡；
       · 可溯源：正文含署名＋显示版本＋构建戳（sha+时间）——每一份构建可对回其源码时点；
       · 固定性：随窗口置顶（任何新视图加入都会被上方 UIWindow hook 重新提到最前）、
         配置不可关、不可交互、不吃触摸。 */
    if (!g_mark && w) {
        UILabel *l = [[UILabel alloc] init];
        l.text = [NSString stringWithFormat:@"© 雾月星辰&MLXC · github@XingChenRS · v%@ · %s",
                                            XRC_VERSION, XRC_BUILD_STAMP];
        l.font = [UIFont systemFontOfSize:11 weight:UIFontWeightSemibold];
        l.textColor = [UIColor colorWithWhite:1.0 alpha:0.6];
        l.shadowColor = [UIColor colorWithWhite:0.0 alpha:0.75];
        l.shadowOffset = CGSizeMake(1, 1);
        l.userInteractionEnabled = NO;
        l.textAlignment = NSTextAlignmentCenter;
        l.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleTopMargin;
        [w addSubview:l];
        [l sizeToFit];
        CGRect lb = l.frame;
        lb.origin = CGPointMake((w.bounds.size.width - lb.size.width) / 2.0,
                                w.safeAreaInsets.top + 2);
        l.frame = lb;
        g_mark = @[ l ];
        [w bringSubviewToFront:l];
        xrc_logi(XRCLC_BOOT, @"[boot] 发布构建水印已挂载（顶部中央）");
    }
#endif
}

#pragma mark - bootstrap

// xrc_log 实现见 XRCLog.m（级别 × 类别 + 4MB 滚动上限）。

static void xrc_apply_switches(void);   // 定义在 %ctor 前；doBootstrap 先用（避免隐式声明）

static void doBootstrap(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        xrc_logd(XRCLC_BOOT, @"doBootstrap begin");
        uint64_t base = xrc_image_base();
        g_xrc = xrc_runtime_discover();
        @try { initButton(); }       @catch (NSException *e) { xrc_logw(XRCLC_BOOT, @"initButton EX: %@", e); }
        @try { xrc_player_install(base); }      @catch (NSException *e) { xrc_logw(XRCLC_BOOT, @"player EX: %@", e); }
        @try { xrc_gameplay_install_hooks(base); } @catch (NSException *e) { xrc_logw(XRCLC_BOOT, @"gameplay EX: %@", e); }
        @try {
            if (xrc_judge_install(base))
                xrc_judge_log_stats();   // 安装成功 → 打一次基线统计
        } @catch (NSException *e) { xrc_logw(XRCLC_BOOT, @"judge EX: %@", e); }
        @try { xrc_probe_run(); }               @catch (NSException *e) { xrc_logw(XRCLC_BOOT, @"probe EX: %@", e); }
        // BRK 桩：处理器已在 %ctor 装好，这里只注册桩点（见 XRCProfile.h）。
        @try { xrc_brk_setup(base); }           @catch (NSException *e) { xrc_logw(XRCLC_BOOT, @"brk EX: %@", e); }
        xrc_apply_switches();   // 开关统一入口（%ctor 已调过一次；此处幂等刷新）
        // 网络层装配（规则单一出处见 XRCNet.h 文件头）：
        //   发布构建：装入**联网阻断器**——全部 http(s) 重写到保留域（编译期锁死，
        //             下面的配置项调用会被整体忽略）；
        //   开发构建：装入私服重定向（默认关，显式开启「私服」条目才生效）。
        // 私服内容的版权 / 数据处理 / 安全性由使用者自负；
        // 本插件默认的练习能力不强制绑定私服。
        @try {
            xrc_net_install();
            xrc_net_set_base(g_cfg.net_base ? g_cfg.net_base.UTF8String : NULL);
            xrc_net_set_match(g_cfg.net_match ? g_cfg.net_match.UTF8String : NULL);
            xrc_net_set_enabled(g_cfg.net_enabled);
        } @catch (NSException *e) { xrc_logw(XRCLC_BOOT, @"net EX: %@", e); }
        @try {
            static dispatch_once_t tw_once;
            dispatch_once(&tw_once, ^{
                struct rebinding rs[1] = {
                    { "gettimeofday", (void *)xrc_clock_gettimeofday, (void **)&xrc_clock_orig_gettimeofday },
                };                rebind_symbols(rs, 1);
            });
        } @catch (NSException *e) { xrc_logw(XRCLC_BOOT, @"timewarp EX: %@", e); }
        if (g_cfg.speed_count > 0)
            xrc_clock_set_rate((double)g_cfg.speeds[g_cfg.rate_index]);
        xrc_logd(XRCLC_BOOT, @"config path: %@", xrc_config_path());
        // 必须挂 NSRunLoopCommonModes：scheduledTimerWithTimeInterval: 只进 default mode，
        // 而 cocos2d 的游戏循环不服务 default mode —— 对局中轮询会整个停摆
        //（player 变化检测与位置兜底失效），挂 common modes 才能全程跑。
        NSTimer *xrc_tick = [NSTimer timerWithTimeInterval:0.5 repeats:YES block:^(NSTimer *t) {
#if XRC_DEBUG_BUILD
            // applog 采集（开发构建）：日志档位 = 详细 且类别含 om 时落盘。
            if ((xrc_log_cats() & XRCLC_OM) && xrc_log_level() >= XRCLL_DEBUG) {
            // applog 明文捕获落盘（加密前）。缓冲放静态区，避免块捕获大数组。
            static uint32_t last_cap_seq = 0;
            static uint8_t  capbuf[XRC_BRK_CAP_MAX];
            uint32_t cap_seq = xrc_brk_capture_seq();
            if (cap_seq != last_cap_seq) {
                last_cap_seq = cap_seq;
                size_t n = xrc_brk_capture_take(capbuf, sizeof(capbuf));
                if (n) {
                    NSString *dir = [NSSearchPathForDirectoriesInDomains(
                                        NSDocumentDirectory, NSUserDomainMask, YES).firstObject
                                     stringByAppendingPathComponent:@"xrcdemo-net"];
                    [[NSFileManager defaultManager] createDirectoryAtPath:dir
                                             withIntermediateDirectories:YES attributes:nil error:nil];
                    NSString *path = [dir stringByAppendingPathComponent:
                                      [NSString stringWithFormat:@"applog-%u.bin", cap_seq]];
                    NSData *blob = [NSData dataWithBytes:capbuf length:n];
                    BOOL wrote = [blob writeToFile:path atomically:YES];
                    // 前 64 字节 hex + ascii 预览，便于日志里直接看结构
                    NSMutableString *hex = [NSMutableString string];
                    NSMutableString *asc = [NSMutableString string];
                    for (size_t i = 0; i < n && i < 64; i++) {
                        [hex appendFormat:@"%02x", capbuf[i]];
                        [asc appendFormat:@"%c", (capbuf[i] >= 32 && capbuf[i] < 127) ? capbuf[i] : '.'];
                    }
                    xrc_logd(XRCLC_OM, @"[brk] applog plaintext %zu bytes wrote=%d -> %@", n, wrote, path);
                    xrc_logd(XRCLC_OM, @"[brk]   hex: %@", hex);
                    xrc_logd(XRCLC_OM, @"[brk]   asc: %@", asc);
                } else {
                    xrc_logd(XRCLC_OM, @"[brk] applog hit but no plaintext captured (buf empty/invalid)");
                }
            }
            }
            if ((xrc_log_cats() & XRCLC_OM) && xrc_log_level() >= XRCLL_DEBUG) {
            // log_blob 密文捕获落盘（载荷加密出口，第二个桩点）。
            // 与明文分开缓冲：两次命中相隔极近，共用会被互相覆盖。
            static uint32_t last_blob_seq = 0;
            static uint8_t  blobbuf[XRC_BRK_CAP_MAX];
            uint32_t blob_seq = xrc_brk_blob_seq();
            if (blob_seq != last_blob_seq) {
                last_blob_seq = blob_seq;
                size_t n = xrc_brk_blob_take(blobbuf, sizeof(blobbuf));
                if (n) {
                    NSString *dir = [NSSearchPathForDirectoriesInDomains(
                                        NSDocumentDirectory, NSUserDomainMask, YES).firstObject
                                     stringByAppendingPathComponent:@"xrcdemo-net"];
                    [[NSFileManager defaultManager] createDirectoryAtPath:dir
                                             withIntermediateDirectories:YES attributes:nil error:nil];
                    NSString *path = [dir stringByAppendingPathComponent:
                                      [NSString stringWithFormat:@"logblob-%u.bin", blob_seq]];
                    NSData *blob = [NSData dataWithBytes:blobbuf length:n];
                    BOOL wrote = [blob writeToFile:path atomically:YES];
                    NSMutableString *hex = [NSMutableString string];
                    for (size_t i = 0; i < n && i < 64; i++)
                        [hex appendFormat:@"%02x", blobbuf[i]];
                    xrc_logd(XRCLC_OM, @"[brk] log_blob ciphertext %zu bytes wrote=%d -> %@", n, wrote, path);
                    xrc_logd(XRCLC_OM, @"[brk]   hex: %@", hex);
                } else {
                    xrc_logd(XRCLC_OM, @"[brk] log_blob hit but nothing captured");
                }
            }
            }
#endif
            void *p = xrc_player_get();
            if (xrc_player_detect_change(p)) {
                xrc_logd(XRCLC_JUDGE, @"new song: player=%p", p);
                // 换歌不清循环；清除只走面板「重置循环段落」按钮
            }
            if (p) {
                xrc_player_try_capture_length(p);
                xrc_player_poll_position(p);   // 位置兜底（getpos hook 不频繁触发）
            }
        }];
        [[NSRunLoop mainRunLoop] addTimer:xrc_tick forMode:NSRunLoopCommonModes];
        xrc_replay_start();   // 回跳重播引擎：常驻检出线程（落笔在主队列；总门由面板控制）
        xrc_logi(XRCLC_BOOT, @"存储：%@ ｜ cb 自由化 %s",
                 xrc_store_cb_status(), g_cfg.cb_bypass ? "on" : "off");
        xrc_logd(XRCLC_BOOT, @"%@（开关 %s）", xrc_audio_speed_status(),
                 g_cfg.speed_audio ? "on" : "off");
        // 未注册桩位自愈：主程序与当前桩表不一致时被运行时还原过 → 提醒重新注入
        @try {
            int rh = xrc_brk_selfheal_count();
            if (rh > 0)
                xrc_logw(XRCLC_BRK, @"命中未注册桩位 %d 次（最后 pc-base=%#llx）"
                         "—— 主程序与当前 dylib 桩表不一致，建议用 inject.py 重新注入主程序",
                         rh, (unsigned long long)xrc_brk_selfheal_last_off());
        } @catch (NSException *e) {}
        xrc_logd(XRCLC_BOOT, @"doBootstrap done");
    });
}

// 前后台**配对开关**：willEnterForeground 可能在不配对的情况下到达（系统弹层/
// 恢复路径）——未配对的它若直接扣冻结计数，会把别人（如面板驻停）的冻结扣掉。
static int s_bg_hold = 0;
static void onAppDidEnterBackground(CFNotificationCenterRef center, void *observer,
                                    CFStringRef name, const void *object,
                                    CFDictionaryRef userInfo) {
    if (s_bg_hold) return;                 /* 已持有：重复后台通知不重复计 */
    s_bg_hold = 1;
    xrc_clock_freeze_inc();
    xrc_logd(XRCLC_BOOT, @"app -> background, warp frozen (count=%d)", xrc_clock_freeze_count());
}

static void onAppWillEnterForeground(CFNotificationCenterRef center, void *observer,
                                     CFStringRef name, const void *object,
                                     CFDictionaryRef userInfo) {
    if (!s_bg_hold) {                      /* 未配对的前台通知：不碰冻结计数 */
        xrc_logd(XRCLC_BOOT, @"app -> foreground（未配对，忽略；count=%d）", xrc_clock_freeze_count());
        return;
    }
    s_bg_hold = 0;
    xrc_clock_freeze_dec();
    xrc_logd(XRCLC_BOOT, @"app -> foreground, warp unfrozen (count=%d)", xrc_clock_freeze_count());
}

static void onAppLaunched(CFNotificationCenterRef center, void *observer,
                          CFStringRef name, const void *object,
                          CFDictionaryRef userInfo) {
    xrc_logd(XRCLC_BOOT, @"onAppLaunched notification fired");
    doBootstrap();
}

// 开关统一入口：**必须早于最早的桩命中** —— cb 校验在 didFinishLaunching 之前就会在
// 后台线程跑，因此 %ctor 即设好（doBootstrap 太晚）。%ctor 与 doBootstrap 都调用
//（幂等，均为原子写）。
static void xrc_apply_switches(void) {
    @try {
        // 「全部解锁」是总闸：开 ⇒ 拥有链/FV/DO/链门（含包状态机）/下载谓词一并放行（与细项 OR，
        // 细项仍可单独用）；关 ⇒ 全部逐字节恢复原行为（桩处理器在开关=0 时重放原指令，不做反向锁定）。
        // ⚠ 拥有链三站在 release 包默认未注入（inject.py 归 redundant）——此 OR 于 dev/显式启用时生效。
        xrc_brk_set_unlock_own(g_cfg.unlock_own || g_cfg.unlock_all);
        xrc_brk_set_unlock_fv(g_cfg.unlock_fv || g_cfg.unlock_all);
        xrc_brk_set_unlock_do(g_cfg.unlock_do || g_cfg.unlock_all);
        xrc_brk_set_gate_open(g_cfg.gate_open || g_cfg.unlock_all);
        xrc_brk_set_unlock_all(g_cfg.unlock_all);
        xrc_brk_set_dl_ready(g_cfg.unlock_all);   // 下载谓词并入总闸（"本地有谱面就能玩"的一部分）
    } @catch (NSException *e) { xrc_logw(XRCLC_BOOT, @"unlock flags EX: %@", e); }
    @try { xrc_brk_set_cb_bypass(g_cfg.cb_bypass); }
    @catch (NSException *e) { xrc_logw(XRCLC_BOOT, @"cb flag EX: %@", e); }
    @try { xrc_judge_set_autoplay(g_cfg.autoplay); }
    @catch (NSException *e) { xrc_logw(XRCLC_BOOT, @"autoplay flag EX: %@", e); }
    // 音乐变速：BGM 跟随速度 + FMOD 内置移调 DSP 保音高；关 = 只 warp 谱面时钟
    @try { xrc_audio_speed_set_enabled(g_cfg.speed_audio); }
    @catch (NSException *e) { xrc_logw(XRCLC_BOOT, @"speed audio flag EX: %@", e); }
    // 日志档位：配置优先；缺省 INFO + 全部类别。
    @try {
        xrc_log_set_level(g_cfg.log_level);
        xrc_log_set_cats(g_cfg.log_cats ? (uint32_t)g_cfg.log_cats : XRCLC_ALL);
    } @catch (NSException *e) { xrc_logw(XRCLC_BOOT, @"log cfg EX: %@", e); }
    // 回跳重播（XRCReplay）与观测桩轻量：幂等应用（%ctor 与面板保存共用本入口）
    @try { xrc_replay_set_enabled(g_cfg.replay_arm); }
    @catch (NSException *e) { xrc_logw(XRCLC_BOOT, @"replay flag EX: %@", e); }
    @try { xrc_arc_stubs_lite_set(g_cfg.stubs_lite); }
    @catch (NSException *e) { xrc_logw(XRCLC_BOOT, @"stubs lite EX: %@", e); }
}

%ctor {
    NSString *gameVer = [NSBundle mainBundle].infoDictionary[@"CFBundleShortVersionString"] ?: @"?";
    xrc_logi(XRCLC_BOOT, @"==== xrcdemo %@ build %s · %s · 基线 %@ ====",
             XRC_VERSION, XRC_BUILD_STAMP,
             XRC_DEBUG_BUILD ? "debug" : "release", gameVer);
    // 游戏循环模式升级：面板滚动（滚动视图跟踪模式）期间谱面不再冻结
    @try { xrc_gameplay_displaylink_common_install(); } @catch (NSException *e) { xrc_logw(XRCLC_BOOT, @"displaylink common EX: %@", e); }
    @try { %init(ui); }   @catch (NSException *e) { xrc_logw(XRCLC_BOOT, @"%%init(ui) EX: %@", e); }
    @try { xrc_config_load(&g_cfg); }  @catch (NSException *e) { xrc_logw(XRCLC_BOOT, @"config EX: %@", e); }
    @try {
        xrc_judge_set_windows(g_cfg.judge_max_ms, g_cfg.judge_pure_ms,
                              g_cfg.judge_far_ms, g_cfg.judge_lost_ms);
    } @catch (NSException *e) { xrc_logw(XRCLC_BOOT, @"judge setup EX: %@", e); }
    // BRK 桩：处理器安装 + **立即注册** —— cb 校验在 didFinishLaunching 之前就有后台
    // 线程命中；注册晚于命中 = 空表分发 → 崩。doBootstrap 里的 setup 为幂等刷新
    //（同 site 重复注册只换 handler）。
    @try { xrc_brk_setup_early(); } @catch (NSException *e) { xrc_logw(XRCLC_BOOT, @"brk early EX: %@", e); }
    xrc_apply_switches();   // 早设：cb 校验可能在本行之后数秒内就跑
    // 存储外置（XRCStore）：把 cb 内容根搬进 Documents（容器内软链，免 root / 免越狱）。
    // 必须在游戏首次读 cb 之前 —— %ctor 是唯一稳妥的位置（doBootstrap 太晚）。
    @try {
        if (g_cfg.external_cb) {
            int r = xrc_store_install();
            xrc_logi(XRCLC_BOOT, @"cb 外置：%s ｜ %@",
                     r == 0 ? "本次完成迁移" : (r == 1 ? "已就位" : "失败(见上)"),
                     xrc_store_cb_status());
        } else {
            xrc_logi(XRCLC_BOOT, @"cb 外置：开关关闭，未做迁移 ｜ %@", xrc_store_cb_status());
        }
    } @catch (NSException *e) { xrc_logw(XRCLC_BOOT, @"store EX: %@", e); }
    CFNotificationCenterAddObserver(CFNotificationCenterGetLocalCenter(), NULL,
        onAppLaunched,
        (CFStringRef)UIApplicationDidFinishLaunchingNotification,
        NULL, CFNotificationSuspensionBehaviorCoalesce);
    CFNotificationCenterAddObserver(CFNotificationCenterGetLocalCenter(), NULL,
        onAppDidEnterBackground,
        (CFStringRef)UIApplicationDidEnterBackgroundNotification,
        NULL, CFNotificationSuspensionBehaviorCoalesce);
    CFNotificationCenterAddObserver(CFNotificationCenterGetLocalCenter(), NULL,
        onAppWillEnterForeground,
        (CFStringRef)UIApplicationWillEnterForegroundNotification,
        NULL, CFNotificationSuspensionBehaviorCoalesce);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        xrc_logw(XRCLC_BOOT, @"3s fallback bootstrap（didFinishLaunching 未按时到达）");
        doBootstrap();
    });
}
