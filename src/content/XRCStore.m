// © 雾月星辰 & MLXC · github@XingChenRS
// XRCStore.m — 外置实现。设计取舍见 XRCStore.h 顶部。
//
// 全程 POSIX（lstat/readlink/rename/symlink/rmdir），只有建目录与列目录用 NSFileManager：
// 软链判定必须用 lstat（stat 会跟链，把"已外置"误判成"是目录"）。

#import "XRCStore.h"
#include "XRCLog.h"

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static NSString *s_cb_in_support(void) {
    return [[NSHomeDirectory() stringByAppendingPathComponent:@"Library/Application Support"]
            stringByAppendingPathComponent:@"cb"];
}

static NSString *s_cb_in_docs(void) {
    return [[NSHomeDirectory() stringByAppendingPathComponent:@"Documents"]
            stringByAppendingPathComponent:@"cb"];
}

// 0 = 存在（*mode 有效）；-1 = 不存在或出错
static int s_lstat(const char *p, mode_t *mode) {
    struct stat st;
    if (!p || lstat(p, &st) != 0) return -1;
    if (mode) *mode = st.st_mode;
    return 0;
}

static NSString *s_symlink_target(const char *p) {
    char buf[PATH_MAX];
    ssize_t n = readlink(p, buf, sizeof(buf) - 1);
    if (n <= 0) return nil;
    buf[n] = '\0';
    return [NSString stringWithUTF8String:buf];
}

// 浅层合并：把 src 里 dst 缺的条目搬过去，dst 已有的（同名）保留不动。
// cb 目录只有 meta.cb / active / tmp / rm 几个条目，浅层足够。
static void s_merge_into(NSString *src, NSString *dst) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray<NSString *> *names = [fm contentsOfDirectoryAtPath:src error:nil];
    int moved = 0, kept = 0;
    for (NSString *name in names) {
        NSString *from = [src stringByAppendingPathComponent:name];
        NSString *to   = [dst stringByAppendingPathComponent:name];
        if ([fm fileExistsAtPath:to]) { kept++; continue; }
        if (rename(from.fileSystemRepresentation, to.fileSystemRepresentation) == 0) {
            moved++;
        } else {
            kept++;
            xrc_logw(XRCLC_CB, @"[store] 合并：%@ 搬入失败 (%s)", name, strerror(errno));
        }
    }
    xrc_logi(XRCLC_CB, @"[store] 合并：搬入 %d 项，保留 Documents 侧同名 %d 项", moved, kept);
}

int xrc_store_install(void) {
    @autoreleasepool {
        NSString *src = s_cb_in_support();
        NSString *dst = s_cb_in_docs();
        const char *csrc = src.fileSystemRepresentation;
        const char *cdst = dst.fileSystemRepresentation;
        mode_t m = 0;

        // ① 已是软链：确认指向
        if (s_lstat(csrc, &m) == 0 && S_ISLNK(m)) {
            NSString *t = s_symlink_target(csrc);
            if ([t isEqualToString:dst]) {
                xrc_logi(XRCLC_CB, @"[store] cb 已外置 → %@", dst);
                return 1;
            }
            // 侧载覆盖可能更换数据容器 UUID：旧容器的绝对软链必然失效，须原子重建
            //（否则游戏写 meta.cb 时 fopen 失败）。只接管"我们自己建的"链
            //（指向某容器 Documents/cb）；用户自建的外来链仍不碰。
            BOOL ours = [t containsString:@"/Containers/Data/Application/"] &&
                        [t hasSuffix:@"/Documents/cb"];
            if (ours) {
                if (s_lstat(cdst, &m) != 0) {
                    NSError *err = nil;
                    if (![[NSFileManager defaultManager] createDirectoryAtPath:dst
                                                   withIntermediateDirectories:YES
                                                                    attributes:nil
                                                                         error:&err]) {
                        xrc_loge(XRCLC_CB, @"[store] 迁移后建 %@ 失败: %@", dst, err);
                        return -1;
                    }
                } else if (!S_ISDIR(m)) {
                    xrc_loge(XRCLC_CB, @"[store] 迁移后的 %@ 不是目录", dst);
                    return -1;
                }
                NSString *tmp = [src stringByAppendingFormat:@".xrc-relink-%@", [NSUUID UUID].UUIDString];
                const char *ctmp = tmp.fileSystemRepresentation;
                if (symlink(cdst, ctmp) != 0) {
                    xrc_loge(XRCLC_CB, @"[store] 新 cb 软链创建失败: %s", strerror(errno));
                    return -1;
                }
                if (rename(ctmp, csrc) != 0) {
                    int saved = errno;
                    unlink(ctmp);
                    xrc_loge(XRCLC_CB, @"[store] cb 软链更新失败: %s", strerror(saved));
                    return -1;
                }
                xrc_logi(XRCLC_CB, @"[store] 容器迁移后 cb 软链已修复：%@ → %@", t, dst);
                return 0;
            }
            xrc_logw(XRCLC_CB, @"[store] cb 是软链但指向 %@（期望 %@），不动它", t, dst);
            return 1;
        }

        BOOL srcIsDir = (s_lstat(csrc, &m) == 0 && S_ISDIR(m));
        BOOL srcOther = (s_lstat(csrc, &m) == 0 && !S_ISDIR(m));
        BOOL dstIsDir = (s_lstat(cdst, &m) == 0 && S_ISDIR(m));

        if (srcOther) {   // 意外形态（普通文件等）：不碰，交给人处理
            xrc_logw(XRCLC_CB, @"[store] %@ 存在非目录对象，跳过外置", src);
            return -1;
        }

        if (srcIsDir && !dstIsDir) {
            // 同卷 rename：瞬时、零拷贝、原子（cb 动辄数百 MB，绝不能走拷贝）
            if (rename(csrc, cdst) != 0) {
                xrc_loge(XRCLC_CB, @"[store] cb 搬迁失败: %s", strerror(errno));
                return -1;
            }
            xrc_logi(XRCLC_CB, @"[store] cb 已搬到 Documents（rename，无拷贝）");
        } else if (srcIsDir && dstIsDir) {
            xrc_logw(XRCLC_CB, @"[store] 两处都有 cb —— 浅层合并（Documents 侧同名优先）");
            s_merge_into(src, dst);
            if (rmdir(csrc) != 0) {
                // 残留（合并时两侧都有的那份）挪到旁边，保证软链能建起来、内容不丢
                NSString *aside = [NSString stringWithFormat:@"%@.stale-%lld", src, (long long)time(NULL)];
                if (rename(csrc, aside.fileSystemRepresentation) == 0)
                    xrc_logw(XRCLC_CB, @"[store] 残留内容移到 %@", aside);
                else
                    xrc_logw(XRCLC_CB, @"[store] 残留内容清理失败 (%s)，继续建链", strerror(errno));
            }
        } else {
            // 全新安装：建 Documents/cb 占位，之后游戏的 cb 下载直接落在这里
            NSError *err = nil;
            if (![[NSFileManager defaultManager] createDirectoryAtPath:dst
                                           withIntermediateDirectories:YES
                                                            attributes:nil
                                                                 error:&err]) {
                xrc_loge(XRCLC_CB, @"[store] 建 %@ 失败: %@", dst, err);
                return -1;
            }
            xrc_logi(XRCLC_CB, @"[store] 无既有 cb，已建 Documents/cb 占位");
        }

        if (symlink(cdst, csrc) != 0) {
            // 全新安装时 Library/Application Support 可能还不存在（游戏自己还没建），
            // 补一次父目录再试；仍失败则完全放弃（cb 留在原处，功能不受影响）。
            if (errno == ENOENT &&
                [[NSFileManager defaultManager] createDirectoryAtPath:
                      [src stringByDeletingLastPathComponent]
                                                withIntermediateDirectories:YES
                                                                 attributes:nil
                                                                      error:nil] &&
                symlink(cdst, csrc) == 0) {
                xrc_logi(XRCLC_CB, @"[store] cb 外置完成（补建父目录）：%@ → %@", src, dst);
                return 0;
            }
            xrc_loge(XRCLC_CB, @"[store] 软链失败: %s（cb 仍在原处，功能不受影响）", strerror(errno));
            return -1;
        }
        xrc_logi(XRCLC_CB, @"[store] cb 外置完成：%@ → %@", src, dst);
        return 0;
    }
}

BOOL xrc_store_cb_external(void) {
    const char *csrc = s_cb_in_support().fileSystemRepresentation;
    mode_t m = 0;
    if (s_lstat(csrc, &m) != 0 || !S_ISLNK(m)) return NO;
    return [s_symlink_target(csrc) isEqualToString:s_cb_in_docs()];
}

NSString *xrc_store_cb_status(void) {
    NSString *src = s_cb_in_support();
    const char *csrc = src.fileSystemRepresentation;
    mode_t m = 0;
    if (s_lstat(csrc, &m) != 0)
        return @"cb 未创建（首次内容下载后生成）";
    if (S_ISLNK(m)) {
        NSString *t = s_symlink_target(csrc);
        if ([t isEqualToString:s_cb_in_docs()]) return @"cb 已外置 → Documents/cb";
        return [NSString stringWithFormat:@"cb 软链指向异常 → %@", t ?: @"(读不到)"];
    }
    return @"cb 在容器内：Library/Application Support/cb";
}
