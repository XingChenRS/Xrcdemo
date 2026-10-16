# © 雾月星辰 & MLXC · github@XingChenRS
"""
Inject libxrcdemo.dylib + libellekit.dylib into Arc-mobile.app.

Two independent stages:

1. dylib injection (default): copy dylibs, insert LC_LOAD_DYLIB / LC_RPATH
   into the existing load-command padding.
2. judge stub (--stub): patch the judge entry (sub_10091E684) -> trampoline in
   __TEXT tail zero-padding -> slot in __DATA tail zero-padding. No Mach-O header
   surgery; both regions lie inside the existing segment filesizes. Re-sign
   afterwards (the user signs the result).

Stub facts (Arcaea iOS 7.0.255):
  entry      vm 0x10091E684  (fileoff 0x91E684)   ← 判定核（注意与特效显示链 sub_1009D9ED8 区分）
  trampoline vm 0x10146800C  (fileoff 0x146800C, __TEXT tail zero-run 0x146800a..0x146c000)
  slot       vm 0x10164AB28  (fileoff 0x164AB28, __DATA tail zero-run 0x164ab25..0x164c000)
  distance entry->tramp = 177MB > B range -> ADRP+ADD+BR absolute (12 bytes,
  replays first 3 insns of the entry prologue).
"""
import os
import sys as _sys
try:                      # GBK 控制台兜底（Windows）
    _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
import shutil
import struct
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(ROOT, "ios", "Payload", "Arc-mobile.app")
MAIN = os.path.join(APP, "Arc-mobile")
FW_DIR = os.path.join(APP, "Frameworks")
DYLIB_NAMES = ["libxrcdemo.dylib", "libellekit.dylib"]
INJECT_NAME = "@rpath/libxrcdemo.dylib"

LC_LOAD_DYLIB = 0x8000000C
LC_RPATH = 0x8000001C

# ---- judge stub constants (7.0.255) ----
# 判定核心 = sub_10091E684（整数 CMP 级联；与 6.13 sub_100870FD0 入口及 CMP
# 站点字节级同构——跨版本可直接按字节指纹重定位，见 README §6）。
# 判别：sub_1009D9ED8 是特效显示链，与判定核易混。
STUB_ENTRY_VA   = 0x10091E684
STUB_ENTRY_FILE = 0x91E684
STUB_TRAMP_VA   = 0x10146800C
STUB_TRAMP_FILE = 0x146800C
STUB_SLOT_VA    = 0x10164AB28
STUB_SLOT_FILE  = 0x164AB28
STUB_INFO_VA    = 0x10164AB40   # slot 之后 24B 处
STUB_INFO_FILE  = 0x164AB40
# expected first 3 insns at entry (file byte order; IDA dwords
# a9bc5ff8=a90157f6=a9024ff4 as STP X24,X23 / STP X22,X21 / STP X20,X19):
STUB_ENTRY_EXPECT = bytes.fromhex("f85fbca9f65701a9f44f02a9")

XRC_MAGIC = 0x58424331  # 'XRC1'
XRC_INFO_VERSION = 2  # blob 布局版本：slot 24B + 判定链 ABI

# ---- BRK 桩 ----
# 把目标指令原地改成 `BRK #0`（D4200000，4B 长度不变），dylib 用 SIGTRAP 处理器
# 接住并把 PC 指向重放跳板。跳板 = 原始指令 + B 回 site+4，共 8B。
# 与判定桩的 40B 跳板（fileoff 0x146800C..0x1468034）不重叠。
BRK_INSN = struct.pack("<I", 0xD4200000)
# (名称, site VA, replay VA, 原字节 hex 或 None) —— replay 必须落在 __TEXT 空白页且互不重叠。
# replay 区分配：judge 跳板 0x146800C..0x1468034；BRK 重放自 0x1468040 起，8B/桩。
# expect 非 None 时做"原字节断言"（防版本漂移；已打桩的二进制跳过断言）。
BRK_HOOKS = [
    ("applog_send", 0x100623AEC, 0x101468040, None),   # sub_100623AEC 入口（OnlineManager 槽 72）
    # log_blob 组装处（密文出口）：待发送的 std::string 在 sp+0x290。
    # 站点指令 0x1006399E4（add x0,sp,#var_428）为 SP 相对寻址——重放安全；
    # PC 相对指令（ADR/ADRL/B/CBZ 等）不能在重放跳板执行（会在别处算错目标）。
    ("applog_blob", 0x1006399E4, 0x101468050, None),
    # ---- 拥有/解锁链（功能账 §1.1）----
    # 歌曲归属由 cb 的 songlist/packlist/unlocks 三张清单 + 服务器 /user/me 授予共同决定；
    # 本组覆盖"服务器未授予、但本地已有内容"的场景（--features unlock_own 启用）。
    # 层1 取第 2 条指令：LDR X9,[X0,#0x268] 为寄存器相对寻址（重放安全）；
    # 首条 CBZ X1 是 PC 相对条件分支，不可进重放跳板。
    ("unlock_l1",  0x100BE46AC, 0x101468058, "093441f9"),  # 层1 sub_100BE46A8 +4（拥有表线性扫描）
    ("unlock_l2",  0x100BE46EC, 0x101468060, "ff0302d1"),  # 层2 sub_100BE46EC 入口（SUB SP,#0x80）
    ("unlock_l3",  0x100BE4D38, 0x101468068, "fd7bbfa9"),  # 层3 sub_100BE4D38 入口（STP X29,X30,[SP,#-0x10]!）
    # ---- cb 验证链（功能账 §3）----
    ("cb_ready",    0x100F43274, 0x101468078, "00a04039"),  # 就绪位 getter（LDRB W0,[X0,#0x28];RET）
    # cb 自由化：让校验结论恒为通过，并保持成功路径完整：
    #   ① 逐文件 sha256 比较的 B.NE → 恒不跳（视为相等）
    #   ② 三清单 HMAC 比较的 B.NE → 恒不跳（成功块照常写 valid=1 并回填版本串）
    #   ③ 清树函数入口 → 直接返回（cb/meta*.cb 与 cb/active 整树不因校验失败被删）
    #   ⚠ ① ② 是 PC 相对条件分支，**不能进重放跳板**（会在别处算错目标）；handler 内按 NZCV
    #     自行复现分支，故 replay=0（no-replay）。
    ("cb_filehash", 0x100F44F9C, None, "21110054"),  # B.NE loc_100F451C0（逐文件 32B sha256 比较）
    ("cb_listhash", 0x100F450B0, None, "21090054"),  # B.NE loc_100F451D4（三表 HMAC 比较）
    ("cb_wipe",     0x100F43C08, 0x101468120, "ffc301d1"),  # 清树入口（SUB SP,#0x70）
    ("cb_dispatch", 0x10013C5E8, 0x101468088, "ff0304d1"),  # 更新错码分发入口（SUB SP,#0x100）
    # ---- cb 版本/更新链（无 meta.cb 情形；2026-10-12 补；语义/证据链见 XRCProfile.h 同名块）----
    # ① 内容更新强制门 sub_1001963D8（OnlineManager::tryHandleContentBundleOldError）：
    #    服务端 code 11（内容包过旧）→「A new content update is required...returning to title」
    #    + 换场回标题；68 个调用者 = HTTP 端点响应处理器家族（0x1007FA490-0x100819C78）。
    #    开关开 → x0=0 直返（镜像其"已在标题/转场场景"的合法早退：不弹窗不换场）；关 → 重放原序言。
    ("cb_gate",     0x1001963D8, 0x101468128, "ffc303d1"),  # 更新强制门入口（SUB SP,#0xF0）
    # ② 内容包更新指令处理器 sub_100815498（+0xA0 处引响应字段 orderedResults）：
    #    入口直返 = 忽略服务器更新指令（设备内容即真值）；函数身份 [高]、内部动作 [中]（见
    #    XRCProfile.h），桩只做入口直返。出处 research/notes/xrc-plugin-site-semantics-2026-09-19.md
    #    §3.1。离线不可达（无响应）。
    ("cb_fetch",    0x100815498, 0x101468130, "ffc306d1"),  # 内容包响应处理器入口（SUB SP,#0x1B0）
    # ---- 自动演奏（外部参考实现对齐；功能账 §5.2）----
    # 站点语义/handler 见 XRCProfile.h + XRCHook.m；开关 xrc_judge_set_autoplay（默认关）。
    # 关时各站重放原指令，行为与未注入一致；开启后长条走原版 Pure tick、窗口点强判、
    # 三输入入口吞触摸。配对标记 "autoplay-eve v1"（dylib 侧必须存在，见配对校验）。
    ("ap_ln_state",      0x10091DBC8, 0x1014680B0, "08904139"),  # LDRB W8,[X0,#0x64]（长条触摸态读取点）
    ("ap_ln_tick",       0x10091DC48, 0x1014680B8, "680340f9"),  # LDR X8,[X27]（长条判定派发前 vtable 装载）
    ("ap_note_win",      0x10091DD70, 0x1014680C0, "5f00086b"),  # CMP W2,W8（窗口 = note+0x1C+0xC8）
    ("ap_arctap_win",    0x10091DF34, 0x1014680C8, "5f00086b"),  # CMP W2,W8（窗口 = note+0x1C+0x64，弧子音符）
    ("ap_swallow_judge", 0x10091EBC8, 0x1014680D0, "ffc305d1"),  # SUB SP,#0x170（逐触消费 sub_10091EBC8 入口）
    ("ap_swallow_batch", 0x10091F688, 0x1014680D8, "ff8302d1"),  # SUB SP,#0xA0（输入批处理 sub_10091F688 入口）
    ("ap_swallow_touch", 0x100921DC4, 0x1014680E0, "ff0302d1"),  # SUB SP,#0x80（触摸批 sub_100921DC4 入口）
    ("ap_arc_visual",    0x10091CC84, 0x1014680E8, "1f200079"),  # STRH WZR,[X0,#0x10]（场景 tick 弧清态点）
    # 诊断计数：引擎两个 tick 助手的返回点（MOV X26,X0；重放安全），
    # 量化"引擎自己发了多少 tick 判定"（对账物量/分数 vs 原谱）。
    ("ap_tickcnt1",      0x10091DCBC, 0x1014680F0, "fa0300aa"),  # MOV X26,X0（helper1=sub_10091E878 返回后，Pure tick 数）
    ("ap_tickcnt2",      0x10091DDBC, 0x1014680F8, "fa0300aa"),  # MOV X26,X0（helper2=sub_10091E958 返回后，Lost tick 数）
    # ---- 曲目锁态覆盖（取证 research/notes/xrc-packlock-rootcause-2026-09-19.md）----
    # 锁状态函数 sub_100919E5C 的两个专属子分支（各自唯一调用方=锁态函数自身）：
    #   FV 五曲 fast path / DO(konzetsu) 分支。入口直返 0（⚠ 极性 2026-10-16 修正：
    #   五字节序 **1=锁、0=可玩**；旧值 0x0101010101 实为"全锁死"）；
    #   开关 unlockFv / unlockDo 关时重放原指令走原路径。两处入口指令均 SP 相对、重放安全。
    ("lock_fv",          0x100991508, 0x101468100, "f44fbea9"),  # STP X20,X19,[SP,#-0x20]!（FV 五曲 fast path 入口）
    ("lock_do",          0x100AAE50C, 0x101468108, "ff4303d1"),  # SUB SP,#0xD0（DO/konzetsu 分支入口）
    # 终章链门（FV 五曲"锁标 + 开局门"的共同上游：锁态 sub_100991508 与可玩性谓词
    #   sub_100919874 都调它）→ 入口直返 1 = **放行**（注意语义：0 是"锁"）；
    #   开关 gateOpen，关时重放。
    ("fv_gate",          0x10099156C, 0x101468110, "ff0303d1"),  # SUB SP,#0xC0（终章链门入口）
    # 链进度覆盖（7.0「链」系统的查表点；取证 xrc-chain-regression-6.13-vs-7.0-2026-09-19.md）：
    #   sub_10098FB1C 把硬编码曲名（InitFunc_194 表）拼 "<名>|<难度>" 查节点对象；对象按 songlist 的
    #   id 注册 → 改名/挪包即 NULL → 不判空 → 读 [NULL+0x28] 崩。入口直返 100（无对象进度值）。
    #   **不设开关、恒生效**（守崩桩）；dylib 侧配对标记 "chain-guard v1"。
    ("chain_prog",       0x10098FB1C, 0x101468118, "ffc302d1"),  # SUB SP,#0xB0（链进度 sub_10098FB1C 入口）
    # ---- 全条件放行（unlock_all / dl_ready；2026-10-12；站点/证据链见 XRCProfile.h 同名块）----
    # 目标：本地存在合法谱面（难度已声明 song+0x250[idx]）时，任何"条件"不得阻止可见/可玩。
    #   ① lock_all   = 锁态总源 sub_100919E5C（44 调用点：cell/曲绘/横幅/世界/包页）→ 0（0=可玩；⚠ 极性 2026-10-16 修正）
    #   ② play_gate  = 可玩性总源 sub_100919874（70 调用点：start 钮/开局链）→ 1（守卫：难度须已声明）
    #   ③ cond_unlock_a/b = 难度条件求值 sub_100BDC5A8/sub_100BDC8D4（解锁条件对象家族）→ 1
    #   ④ dl_play    = 下载"需动作"谓词 sub_100850308（2 调用点：start 钮图标/开局弹窗分流）→ 0
    #      ⚠ 不动 sub_100844774（下载机制本体，2026-09-28 教训）；缺文件仍由开局链温和失败+重扫。
    #   ⑤ jacket_lock = sub_10084EE7C 内 0x84EF48 `TBNZ X0,#0x20`（arghena 专属锁绘分支；
    #      与 unlockDo/unlockAll 的 b4=1 联动）。**no-replay**（PC 相对条件分支，handler 按位复现）。
    #   配对标记 "unlock-policy v3"（dylib 侧须存在，缺则拒配——见 main() 的配对校验）。
    ("lock_all",         0x100919E5C, 0x101468138, "ffc302d1"),  # SUB SP,#0xB0（锁态总源入口）
    ("play_gate",        0x100919874, 0x101468140, "ff8301d1"),  # SUB SP,#0x60（可玩性总源入口）
    ("dl_play",          0x100850308, 0x101468148, "f657bda9"),  # STP X22,X21,[SP,#-0x30]!（需动作谓词入口）
    ("cond_unlock_a",    0x100BDC5A8, 0x101468150, "ff4302d1"),  # SUB SP,#0x90（难度条件求值 A）
    ("cond_unlock_b",    0x100BDC8D4, 0x101468158, "ff8301d1"),  # SUB SP,#0x60（难度条件求值 B）
    # ⑥ pack_open  = 包状态机 sub_100CD0108（13 调用点：FV「先过 Black Fate」点击拦截/封面/
    #      歌列表跳过）→ 3（已拥有；1=不可进）。开关 gateOpen（面板已 ||unlockAll）。入口 SUB SP,#0x50。
    ("pack_open",        0x100CD0108, 0x101468160, "ff4301d1"),  # SUB SP,#0x50（包状态机 sub_100CD0108 入口）
    # ⑦ shutter_done = 进歌在线检查完成位（scene+0x348）唯一清零点（0x100976F68，
    #      `strb wzr,[x19,#0x348]`）→ 跳过清 0（完成位恒 1；7s 逐帧等待与
    #      Network Error 弹窗不可达，等效自动 Continue Offline）。开关 gateOpen；
    #      站点为非 PC 相对普通存储（可重放）；slot 0x101468168 已核全零。
    ("shutter_done",     0x100976F68, 0x101468168, "7f220d39"),  # strb wzr,[x19,#0x348]（唯一清 0）
    # 锁绘分支族（四处，no-replay：PC 相对条件分支，handler 按位复现；开关 = unlockAll || unlockDo）。
    # 触发器 = 锁态 bit32（b4）；置位 → sub_10084F0E8 锁绘选择器（konzetsu/finale/grievouslady/
    # tempestissimo/undyingmacula → jacket_locked_*，其余 → img/1080/jacket_locked_generic.jpg）。
    # 开关开时恒走普通曲绘侧。站点/目标均取自原生二进制反汇编（XRCProfile.h 同名块有全链证据）。
    ("jacket_lock",      0x10084EF48, None,        "a00800b7"),  # TBNZ X0,#0x20（84EE7C 内 arghena 门；目标 0x84F05C）
    ("jacket_cell",      0x1008EAFB4, None,        "480100b7"),  # TBNZ X8,#0x20（选曲 cell；目标 0x8EAFDC）
    ("jacket_info",      0x10094A57C, None,        "000100b7"),  # TBNZ X0,#0x20（曲目信息面板；目标 0x94A59C）
    ("jacket_panel",     0x100B3F274, None,        "980100b6"),  # TBZ  X24,#0x20（详情面板；目标 0xB3F2A4=跳过锁绘）
    # ---- 弧/绘制观测桩（只观测不改行为；handler 见 XRCHook.m"弧/绘制 观测桩"）----
    # 三处都是函数入口，首指令均为 SUB SP,SP,#N（非 PC 相对 ⇒ 可重放）。
    # ⚠ 这三条打在**入口 +4**：入口的 `SUB SP,SP,#N` 照常执行 ⇒ SP 自然正确；
    #   被换成 BRK 的是一条 `STP Dn,Dm,[SP,#..]`（保存 callee 浮点，无副作用）。
    #   `B` 够不到 0x101468xxx（271MB）⇒ replay=0，handler 只把 PC 设到 site+4。
    ("rpf_draw",    0x100B23668, 0, "eb2b056d"),  # 绘制趟 入口+4（STP D11,D10）X0=track X1=音符表
    ("rpf_arctick", 0x100AFFC14, 0, "ed33016d"),  # 弧 tick 入口+4（STP D13,D12）X0=弧渲染对象
    ("rpf_arcpass", 0x100AFFA94, 0, "eb2b026d"),  # 头过线 入口+4（STP D11,D10）X0=弧渲染对象
    # ---- 弧分段「藏」的两处（仅在回跳窗口内把「藏」反成「显」）----
    # 症状：弧带下端被整齐切掉 = **弧的开头**不显示，起手点不可见。
    # 反汇编：两处唯一的藏动作都是 `MOV W1,#0` + `setVisible(child, 0)`（slot 42，vtable+0x150）：
    #   A 0x100AFFB60  in sub_100AFFA90（头过线）：判据 isVisible && (pos.z+head)*sgn >= sgn*10
    #   B 0x100AFFE80  in sub_100AFFC10（弧 tick）：跳到共享尾声 0x100B00048 处才 BLR
    # 打桩打在 **MOV W1,#0** 这条上：handler 平时一个字都不改（=与未打桩逐字节同行为），
    # 仅在「回跳后尚未涨回旧水位」的窗口里把 W1 改成 1 ⇒ 引擎自己把分段显回来。
    # 正常游玩不受影响（只在 seek 回发生时生效）。
    ("arc_hide_a", 0x100AFFB60, 0, "01008052"),   # MOV W1,#0（头过线里的藏）
    ("arc_hide_b", 0x100AFFE80, 0, "01008052"),   # MOV W1,#0（弧 tick 里的藏）
]

# ---- 还原站点：不在 BRK_HOOKS、但既有二进制可能带其桩的站点 ----
# 还原逻辑遍历 BRK_HOOKS + 本表：本表站点再注入时若原地仍是 BRK 则还原原字节。
# 必须单列：遗漏即**还原不掉**，而 dylib 无该站点的处理器 ⇒ 命中 BRK 时 SIGTRAP **直接闪退**。
# 原字节取自原始二进制（samples/.../stage1/Arc-mobile，md5 49fbbba8…）。新增还原项时照此补。
RESTORE_SITES = [
    ("cb_verify", 0x100F43FFC, "fc6fbaa9"),   # STP X28,X27,[SP,#-0x60]!（cb 校验入口序言）
]

# ---- 功能集（**构建期开关**）----
# 注入器按 profile 决定打哪些桩；dylib 启动自检"本构建有哪些站点"（xrc_feature_present），
# 面板只显示本构建含有的项；清单落进 xrc_patch_manifest.json 可审计。
#   --profile release（默认）| dev（全量）| 或 --features a,b 显式指定
#   status: required=守崩必备 / stable=稳定 / redundant=由其它机制覆盖（默认不进 release）
#           / debug=调试采集（默认不进 release）
FEATURES = [
    ("unlock_own",     ["unlock_l1", "unlock_l2", "unlock_l3"],                    True,  "stable",
     "拥有链三层：归属由 cb 三清单 + 服务器授予决定；恒真=视为已有内容。2026-10-16 起 release 纳入："
     "点 START 归属复查（sub_100C14898→sub_100C0FEB4 离线门→登录弹窗）与曲包状态机（CD0108 两处消费 BE46A8）同源"),
    ("unlock_lock",    ["lock_fv", "lock_do", "fv_gate", "pack_open", "shutter_done"], True, "stable",
     "曲目锁态覆盖（FV/DO 五难度全解）+ 终章链门/包状态机/进歌在线检查放行（gateOpen 同闸）"),
    ("chain_guard",    ["chain_prog"],                                             True,  "required",
     "7.0 链查表守崩桩（恒生效；防改名/挪包 NULL 崩）"),
    ("unlock_all",     ["lock_all", "play_gate", "cond_unlock_a", "cond_unlock_b",
                        "jacket_lock", "jacket_cell", "jacket_info", "jacket_panel"],
                                                                                   True,  "stable",
     "全条件放行：锁态/可玩性/难度条件判定源头恒真（开关 unlockAll；锁绘族与 unlockDo 联动）"),
    ("dl_ready",       ["dl_play"],                                                True,  "stable",
     "本地内容放行：下载'需动作'谓词恒 0（开关 dlReady 默认关；文件真实存在性仍由开局链亲验）"),
    ("cb_free",        ["cb_ready", "cb_filehash", "cb_listhash", "cb_wipe", "cb_dispatch",
                        "cb_gate", "cb_fetch"],                                    True, "stable",
     "cb 自由化：校验结论恒通过且保持成功路径回填；清树调用直返；就绪恒真；更新错码分发/更新强制门/远端更新指令直返（无 meta.cb 亦可进入）"),
    ("autoplay",       ["ap_ln_state", "ap_ln_tick", "ap_note_win", "ap_arctap_win",
                        "ap_swallow_judge", "ap_swallow_batch", "ap_swallow_touch",
                        "ap_arc_visual", "ap_tickcnt1", "ap_tickcnt2"],           True,  "stable",
     "自动演奏（面板开关，默认关）+ 判定计数诊断"),
    # 观测桩只用于逆向观测：命中一次过一次内核 SIGTRAP，且 handler 在游戏线程上遍历整张
    # 音符表 ⇒ 帧时间随弧数浮动。默认不进 release（需要时 --features rpf_arcprobe）。
    ("rpf_arcprobe",   ["rpf_draw", "rpf_arctick", "rpf_arcpass"],                False, "debug",
     "弧/绘制观测桩（只观测不改行为；高频负载，默认不进 release）"),
    # 回跳窗口内把弧分段的「藏」反成「显」；窗口外与未打桩逐字节同行为。
    # 注意：它与渲染重建的显示路径叠加会让弧越过判定线——默认不进 release。
    ("arc_nohide",     ["arc_hide_a", "arc_hide_b"],                               False, "debug",
     "回跳期把弧分段的「藏」反成「显」（默认不进 release）"),
    ("applog_capture", ["applog_send", "applog_blob"],                             False, "debug",
     "applog 明文/密文采集（调试；默认不落盘，仅 brk 分支构建含）"),
]


def features_selected(argv):
    """按 --profile/--features 选出本次要注入的功能名集合 → (set, 描述串)。"""
    names = [f[0] for f in FEATURES]
    if "--features" in argv:
        i = argv.index("--features")
        if i + 1 >= len(argv):
            raise SystemExit("usage: --features a,b,c")
        want = [x.strip() for x in argv[i + 1].split(",") if x.strip()]
        bad = [x for x in want if x not in names]
        if bad:
            raise SystemExit(f"unknown feature(s): {bad}; known: {names}")
        return set(want), "features=" + ",".join(want)
    prof = argv[argv.index("--profile") + 1] if "--profile" in argv else "release"
    if prof == "dev":
        return set(names), "profile=dev(全量)"
    if prof != "release":
        raise SystemExit(f"unknown profile: {prof} (release|dev)")
    return {n for n, _s, rel, _st, _note in FEATURES if rel}, "profile=release"


def sites_for(feat_names):
    """功能名集合 → 要注入的 BRK 站点名集合；未归入任何功能的站点始终注入。"""
    keep = set()
    for n, sites, _rel, _st, _note in FEATURES:
        if n in feat_names:
            keep.update(sites)
    listed = {x for _n, ss, _r, _st, _no in FEATURES for x in ss}
    keep.update(n for n, _s, _r, _e in BRK_HOOKS if n not in listed)
    return keep


# ---- 门禁静态补丁：就地写、无跳板（默认空表；仅 --gate 时应用）----
# (名称, VA, 原字节 hex, 补丁字节 hex) —— 幂等：已是补丁字节跳过；expect 不符即报错。
GATE_PATCHES = []
# 静态偏移（VA - image base 0x100000000）
GP_VTABLE_OFF   = 0x151D8C0   # GameScene vtable
GP_UPDATE_OFF   = 0xCA7160    # 槽 103 每帧函数
MTP_VTABLE_OFF  = 0x14B75B0   # MTP vtable
MTP_GETPOS_OFF  = 0x8E24F0    # 槽 7


def encode_adrp_add_br(pc_addr: int, dst: int, reg: int = 16) -> bytes:
    """ADRP reg, dst_page; ADD reg, reg, #pgoff; BR reg (12 bytes)."""
    pc_page = pc_addr & ~0xFFF
    dst_page = dst & ~0xFFF
    imm = (dst_page - pc_page) >> 12
    imm &= 0x1FFFFF  # 21-bit 符号扩展
    adrp = 0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | reg
    add = 0x91000000 | ((dst & 0xFFF) << 10) | (reg << 5) | reg
    br = 0xD61F0000 | (reg << 5)
    return struct.pack("<III", adrp, add, br)


def encode_b(pc_addr: int, dst: int) -> int:
    off = (dst - pc_addr) >> 2
    assert -0x2000000 <= off < 0x2000000, "B out of range"
    return 0x14000000 | (off & 0x3FFFFFF)


def build_trampoline() -> bytes:
    """Full-takeover trampoline v2。

    判定核 sub_10091E684 的第 6 参 X6 由调用方透传进落账函数 sub_100ACB880
    （judge 自身从不写 X6），handler 重排参数后必须原样转发。跳板在 BR 前插一条
    `MOV X3, X6`，把 a6 作为 handler 的第 4 参传入——无需动 SP、无需保存区，
    跳板只做分发与一次寄存器搬移。

    handler 签名（与 xrc_abi.h 一致）：
        uint64_t handler(ng /*x0*/, note /*x1*/, ts /*x2*/, a6 /*x3=X6*/)
    handler 用普通 C 函数（BR 不改 LR，其 RET 直接回到判定核的调用方）。

    布局（40B，< 64B 上限）：
      0  ADRP X9, slot_page
      4  ADD  X9, X9, #pgoff
      8  LDR  X9, [X9]        (slot+0 = handler)
      12 CBZ  X9, native
      16 MOV  X3, X6
      20 BR   X9
      24 native: replay 3 insns (12B) + B entry+12
    """
    out = bytearray()
    pc_page = STUB_TRAMP_VA & ~0xFFF
    slot_page = STUB_SLOT_VA & ~0xFFF
    imm = (slot_page - pc_page) >> 12
    adrp = 0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | 9
    add = 0x91000000 | ((STUB_SLOT_VA & 0xFFF) << 10) | (9 << 5) | 9
    out += struct.pack("<II", adrp, add)             # ADRP/ADD X9, slot
    out += struct.pack("<I", 0xF9400129)             # LDR X9, [X9]
    native_va = STUB_TRAMP_VA + 24
    off = (native_va - (STUB_TRAMP_VA + 12)) >> 2
    out += struct.pack("<I", 0xB4000000 | ((off & 0x7FFFF) << 5) | 9)  # CBZ X9, native
    out += struct.pack("<I", 0xAA0603E3)             # MOV X3, X6
    out += struct.pack("<I", 0xD61F0120)             # BR X9
    out += STUB_ENTRY_EXPECT                         # native: 重放前 3 条
    out += struct.pack("<I", encode_b(native_va + 12, STUB_ENTRY_VA + 12))
    return bytes(out)

def build_info_blob() -> bytes:
    """xrc_info 结构：magic + version + 6 个静态偏移 + reserved[8]。
    dyld 不 rebase 零填充区（不在 rebase 列表），dylib 手动重定位。"""
    fields = [
        XRC_MAGIC, 2,   # blob 布局版本：slot 24B + 判定链 ABI

        STUB_ENTRY_VA - 0x100000000,   # judge_entry_off
        STUB_SLOT_VA - 0x100000000,    # judge_slot_off
        GP_VTABLE_OFF,
        GP_UPDATE_OFF,
        MTP_VTABLE_OFF,
        MTP_GETPOS_OFF,
    ] + [0] * 8
    return struct.pack("<II6Q8Q", *fields)


def patch_judge_stub(data: bytearray) -> list[str]:
    logs = []
    base = fat_arm64_slice_offset(bytes(data))
    entry_file = base + STUB_ENTRY_FILE
    cur = bytes(data[entry_file:entry_file + 12])
    if cur != STUB_ENTRY_EXPECT:
        raise RuntimeError(
            f"stub entry bytes mismatch at {entry_file:#x}: {cur.hex()} "
            f"(expected {STUB_ENTRY_EXPECT.hex()}) — wrong binary version?"
        )
    tramp = build_trampoline()
    tramp_file = base + STUB_TRAMP_FILE
    if len(tramp) > 0x40:
        raise RuntimeError("trampoline too large")
    # verify zero region
    if bytes(data[tramp_file:tramp_file + len(tramp)]) != b"\0" * len(tramp):
        raise RuntimeError(f"trampoline region not zero @ {tramp_file:#x}")
    data[tramp_file:tramp_file + len(tramp)] = tramp
    logs.append(f"trampoline ({len(tramp)}B) @ fileoff {tramp_file:#x} (vm {STUB_TRAMP_VA:#x})")

    # slot: 24B {handler=0, orig=STUB_ENTRY_VA, reserved=0}
    slot_file = base + STUB_SLOT_FILE
    if bytes(data[slot_file:slot_file + 24]) != b"\0" * 24:
        raise RuntimeError(f"slot region not zero @ {slot_file:#x}")
    data[slot_file:slot_file + 24] = struct.pack("<QQQ", 0, STUB_ENTRY_VA, 0)
    logs.append(f"slot (24B) @ fileoff {slot_file:#x} (vm {STUB_SLOT_VA:#x})")

    # info blob: 桩点回报信息（运行时锚点清单，dylib 手动重定位）
    info = build_info_blob()
    info_file = base + STUB_INFO_FILE
    if bytes(data[info_file:info_file + len(info)]) != b"\0" * len(info):
        raise RuntimeError(f"info region not zero @ {info_file:#x}")
    data[info_file:info_file + len(info)] = info
    logs.append(f"info blob ({len(info)}B) @ fileoff {info_file:#x} (vm {STUB_INFO_VA:#x})")

    # entry patch: ADRP/ADD/BR X16 -> trampoline
    patch = encode_adrp_add_br(STUB_ENTRY_VA, STUB_TRAMP_VA)
    data[entry_file:entry_file + 12] = patch
    logs.append(f"entry patched ({12}B) @ vm {STUB_ENTRY_VA:#x} -> tramp")
    return logs


def pc_relative_kind(w: int) -> str | None:
    """返回 PC 相关指令的名称（不能在别处重放），否则 None。"""
    if (w >> 26) in (0b000101, 0b100101):
        return "B/BL"
    if (w & 0x9F000000) in (0x10000000, 0x90000000):
        return "ADR/ADRP"
    if (w & 0x7E000000) == 0x34000000:
        return "CBZ/CBNZ"
    if (w & 0x7E000000) == 0x36000000:
        return "TBZ/TBNZ"
    if (w & 0x3B000000) == 0x18000000:
        return "LDR-literal"
    return None


def patch_brk_hooks(data: bytearray, only_sites=None) -> list[str]:
    """把（本次功能集选中的）BRK_HOOKS 站点改成 `BRK #0`，并在 replay 处建重放跳板。

    跳板 = 原始 4 字节 + `B site+4`。原始指令若 PC 相关则拒绝（在别处重放会算错）。
    only_sites=None → 全部；给集合则未选中的站点**原样保留**（dylib 侧自检会报"本构建无此项"）。
    """
    logs = []
    base = fat_arm64_slice_offset(bytes(data))

    # ① 还原站点：只要原地还是 BRK 就还原（与本次功能集无关）——见 RESTORE_SITES 注释。
    for rname, rva, rhex in RESTORE_SITES:
        roff = base + (rva - 0x100000000)
        if bytes(data[roff:roff + 4]) == BRK_INSN:
            data[roff:roff + 4] = bytes.fromhex(rhex)
            logs.append(f"brk[{rname}]: 还原 {rhex} @ {rva:#x}")

    for name, site_va, replay_va, expect in BRK_HOOKS:
        if only_sites is not None and name not in only_sites:
            # 功能未选中：若原地仍是 BRK，还原为原始字节（否则命中即为无处理器的 SIGTRAP）。
            site_file0 = base + (site_va - 0x100000000)
            cur = bytes(data[site_file0:site_file0 + 4])
            # 原字节来源：① expect ② 没写 expect 的站点（如 applog_*）从重放跳板回读
            orig_hex = expect
            if orig_hex is None and replay_va:
                rf = base + (replay_va - 0x100000000)
                orig_hex = bytes(data[rf:rf + 4]).hex()
            if cur == BRK_INSN and orig_hex is not None:
                data[site_file0:site_file0 + 4] = bytes.fromhex(orig_hex)
                logs.append(f"brk[{name}]: reverted to original {orig_hex} (feature off)")
            else:
                logs.append(f"brk[{name}]: skipped (feature off for this build)")
            continue
        site_file = base + (site_va - 0x100000000)
        orig = bytes(data[site_file:site_file + 4])
        if len(orig) != 4:
            raise RuntimeError(f"brk[{name}]: site {site_va:#x} out of range")
        if orig == BRK_INSN:
            logs.append(f"brk[{name}]: already patched @ {site_va:#x}")
            continue
        if expect is not None and orig.hex() != expect:
            raise RuntimeError(
                f"brk[{name}]: site {site_va:#x} bytes {orig.hex()} != expected "
                f"{expect} — wrong binary version?"
            )
        if replay_va == 0:
            # no-replay 且 **handler 自行模拟原指令**（入口桩专用）：语义 = handler 里手工
            # 复现首指令的效果（如 SUB SP,SP,#N）再把 PC 设到 site+4。仍然拒绝 PC 相关指令。
            w0 = struct.unpack("<I", orig)[0]
            kind0 = pc_relative_kind(w0)
            if kind0:
                raise RuntimeError(
                    f"brk[{name}]: site {site_va:#x} insn {orig.hex()} is {kind0} "
                    f"— handler-emulated stub 也不能是 PC 相关指令"
                )
            data[site_file:site_file + 4] = BRK_INSN
            logs.append(
                f"brk[{name}]: {site_va:#x} -> BRK#0 (orig {orig.hex()}, handler-emulated)"
            )
            continue
        if replay_va is None:
            # no-replay 桩：处理器自设 PC，无需跳板。仅接受**条件分支**——
            # CBZ/CBNZ(0x34/0x35/0xB4/0xB5)、TBZ/TBNZ(0x36/0x37/0xB6/0xB7)、
            # B.cond(0x54：PC 相对，同样不能进跳板，由 handler 按 NZCV 复现)。
            top = orig[3]
            if top not in (0x34, 0x35, 0xB4, 0xB5, 0x36, 0x37, 0xB6, 0xB7, 0x54):
                raise RuntimeError(
                    f"brk[{name}]: no-replay site {site_va:#x} insn {orig.hex()} "
                    f"is not a conditional branch"
                )
            data[site_file:site_file + 4] = BRK_INSN
            logs.append(
                f"brk[{name}]: {site_va:#x} -> BRK#0 (orig {orig.hex()}, no-replay)"
            )
            continue
        replay_file = base + (replay_va - 0x100000000)
        w = struct.unpack("<I", orig)[0]
        kind = pc_relative_kind(w)
        if kind:
            raise RuntimeError(
                f"brk[{name}]: site insn {orig.hex()} is {kind} — not replay-safe"
            )
        tramp = orig + struct.pack("<I", encode_b(replay_va + 4, site_va + 4))
        if bytes(data[replay_file:replay_file + len(tramp)]) != b"\0" * len(tramp):
            raise RuntimeError(f"brk[{name}]: replay region not zero @ {replay_file:#x}")
        data[replay_file:replay_file + len(tramp)] = tramp
        data[site_file:site_file + 4] = BRK_INSN
        logs.append(
            f"brk[{name}]: {site_va:#x} -> BRK#0 (orig {orig.hex()}), "
            f"replay @ {replay_va:#x}"
        )

    # ② 审计：文件里不允许存在任何"计划外"的 BRK。原始二进制本身零 BRK（已核），
    #    所以任何多出来的都只可能是残留 —— 而 dylib 收到无处理器的 SIGTRAP 会**直接闪退**，
    #    宁可在这里 fail loud，也不放一份会崩的二进制出去。
    allowed = {va for n, va, _r, _e in BRK_HOOKS if only_sites is None or n in only_sites}
    allowed |= {va for _n, va, _h in RESTORE_SITES}
    raw = bytes(data)
    stray, pos = [], raw.find(BRK_INSN)
    while pos != -1:
        if (pos - base) % 4 == 0:                    # 只认 4 字节对齐的指令槽
            va = 0x100000000 + (pos - base)
            if va not in allowed:
                stray.append(va)
        pos = raw.find(BRK_INSN, pos + 1)
    if stray:
        raise RuntimeError(
            "brk 审计失败：发现计划外 BRK @ "
            + ", ".join(f"{v:#x}" for v in stray[:8])
            + (" …" if len(stray) > 8 else "")
            + " —— 计划外 BRK 命中时 dylib 没有处理器，会 SIGTRAP 闪退。"
            " 确认来源后把原字节补进 RESTORE_SITES 再重跑。"
        )
    logs.append(f"brk 审计：计划内 {len(allowed)} 站，无计划外 BRK")
    return logs


def patch_gates(data: bytearray) -> list[str]:
    """门禁静态补丁（**默认不调用**，仅 --gate 时）：就地写，无跳板。

    幂等：已是补丁字节则跳过；与 expect 不符时报错（防版本漂移）。
    """
    logs = []
    base = fat_arm64_slice_offset(bytes(data))
    for name, va, expect, patch in GATE_PATCHES:
        off = base + (va - 0x100000000)
        want = bytes.fromhex(patch)
        cur = bytes(data[off:off + len(want)])
        if len(cur) != len(want):
            raise RuntimeError(f"gate[{name}]: VA {va:#x} out of range")
        if cur == want:
            logs.append(f"gate[{name}]: already patched @ {va:#x}")
            continue
        if cur.hex() != expect:
            raise RuntimeError(
                f"gate[{name}]: {va:#x} bytes {cur.hex()} != expected {expect}"
                f" — wrong binary version?"
            )
        data[off:off + len(want)] = want
        logs.append(f"gate[{name}]: {va:#x} {cur.hex()} -> {patch}")
    return logs


def patch_ats() -> list[str]:
    """给 app 的 Info.plist 开 ATS 豁免，否则明文 HTTP 连自有服务端会被拦。

    ⚠️ 关键规则：iOS 10+ 上，只要 NSAppTransportSecurity
    里存在 NSAllowsLocalNetworking / NSAllowsArbitraryLoadsInWebContent /
    NSAllowsArbitraryLoadsForMedia 中**任意一个**，系统就会**忽略**
    NSAllowsArbitraryLoads。而 NSAllowsLocalNetworking 只覆盖 .local 与无后缀
    主机名，**不覆盖数字 IP**——两者同时存在会导致 http://<内网IP> 仍被拦。

    因此这里只写 NSAllowsArbitraryLoads=true，并主动移除其它 Allows* 键。
    NSLocalNetworkUsageDescription 另加（iOS 14+ 本地网络权限说明；TrollStore
    安装的 app 因 platform-application entitlement 通常被豁免，不弹窗属正常）。
    """
    import plistlib
    logs = []
    plist_path = os.path.join(APP, "Info.plist")
    if not os.path.isfile(plist_path):
        raise RuntimeError(f"Info.plist not found: {plist_path}")
    with open(plist_path, "rb") as f:
        pl = plistlib.load(f)
    ats = dict(pl.get("NSAppTransportSecurity", {}))
    changed = False
    # 去掉会让 NSAllowsArbitraryLoads 失效的键
    for k in ("NSAllowsLocalNetworking",
              "NSAllowsArbitraryLoadsInWebContent",
              "NSAllowsArbitraryLoadsForMedia"):
        if k in ats:
            ats.pop(k)
            changed = True
            logs.append(f"ATS: removed {k} (it would disable NSAllowsArbitraryLoads)")
    if ats.get("NSAllowsArbitraryLoads") is not True:
        ats["NSAllowsArbitraryLoads"] = True
        changed = True
        logs.append("ATS: NSAllowsArbitraryLoads = true")
    pl["NSAppTransportSecurity"] = ats
    if not pl.get("NSLocalNetworkUsageDescription"):
        pl["NSLocalNetworkUsageDescription"] = "Connect to the local Arcaea test server"
        changed = True
        logs.append("added NSLocalNetworkUsageDescription")
    if changed:
        with open(plist_path, "wb") as f:
            plistlib.dump(pl, f)
    else:
        logs.append("ATS: already exempt")
    return logs


def patch_filesharing() -> list[str]:
    """开文件共享：让 Documents 在「文件」App / 电脑（Finder、iTunes、爱思等）上可见。

    这是**免越狱自用**的关键一环：没有这两个键，app 的 Documents 除了 app 自己
    谁也看不见、改不了 —— cb 外置（XRCStore 把 cb 根软链到 Documents）也就用不起来。
        UIFileSharingEnabled              — 把 Documents 暴露给「文件」App / 文件共享
        LSSupportsOpeningDocumentsInPlace — 允许原地打开（就地编辑），iOS 11+
    两者都只是 plist 键，随重签一起生效；对游戏本身行为无影响。
    """
    import plistlib
    logs = []
    plist_path = os.path.join(APP, "Info.plist")
    if not os.path.isfile(plist_path):
        raise RuntimeError(f"Info.plist not found: {plist_path}")
    with open(plist_path, "rb") as f:
        pl = plistlib.load(f)
    changed = False
    for k in ("UIFileSharingEnabled", "LSSupportsOpeningDocumentsInPlace"):
        if pl.get(k) is not True:
            pl[k] = True
            changed = True
            logs.append(f"file sharing: {k} = true")
    if changed:
        with open(plist_path, "wb") as f:
            plistlib.dump(pl, f)
    else:
        logs.append("file sharing: already enabled")
    return logs


def fat_arm64_slice_offset(raw: bytes) -> int:
    if raw[:4] != b"\xca\xfe\xba\xbe":
        return 0
    nfat = struct.unpack(">I", raw[4:8])[0]
    off = 8
    for _ in range(nfat):
        cputype, _, so, _, _ = struct.unpack(">IIIII", raw[off:off + 20])
        off += 20
        if cputype in (0x0100000c, 0x00000012):
            return so
    return 0


def slice_range(raw: bytes) -> tuple[int, int]:
    base = fat_arm64_slice_offset(raw)
    if base:
        nfat = struct.unpack(">I", raw[4:8])[0]
        off = 8
        for _ in range(nfat):
            cputype, _, so, sz, _ = struct.unpack(">IIIII", raw[off:off + 20])
            off += 20
            if cputype in (0x0100000c, 0x00000012):
                return so, so + sz
    return 0, len(raw)


def parse_load_commands(raw: bytes, base: int):
    ncmds, sizeofcmds = struct.unpack_from("<II", raw, base + 16)
    pos = base + 32
    cmds = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", raw, pos)
        cmds.append((cmd, cmdsize, pos))
        pos += cmdsize
    return ncmds, sizeofcmds, cmds


def has_load_dylib(raw: bytes, base: int, name: str) -> bool:
    _, _, cmds = parse_load_commands(raw, base)
    for cmd, cmdsize, pos in cmds:
        if (cmd & 0xFFFFFF) != 0x0C:
            continue
        path_off = struct.unpack_from("<I", raw, pos + 8)[0]
        path = raw[pos + path_off:pos + cmdsize].split(b"\0")[0].decode()
        if path == name:
            return True
    return False


def has_rpath(raw: bytes, base: int, path: str) -> bool:
    _, _, cmds = parse_load_commands(raw, base)
    for cmd, cmdsize, pos in cmds:
        if (cmd & 0xFFFFFF) != 0x1C:
            continue
        path_off = struct.unpack_from("<I", raw, pos + 8)[0]
        rp = raw[pos + path_off:pos + cmdsize].split(b"\0")[0].decode()
        if rp == path:
            return True
    return False


def build_load_dylib_cmd(path: str) -> bytes:
    path_b = path.encode("ascii") + b"\0"
    cmdsize = (24 + len(path_b) + 7) & ~7
    cmd = bytearray(cmdsize)
    struct.pack_into("<II", cmd, 0, LC_LOAD_DYLIB, cmdsize)
    struct.pack_into("<IIII", cmd, 8, 24, 2, 0x10000, 0x10000)
    cmd[24:24 + len(path_b)] = path_b
    return bytes(cmd)


def build_rpath_cmd(path: str) -> bytes:
    path_b = path.encode("ascii") + b"\0"
    cmdsize = (12 + len(path_b) + 7) & ~7
    cmd = bytearray(cmdsize)
    struct.pack_into("<II", cmd, 0, LC_RPATH, cmdsize)
    struct.pack_into("<I", cmd, 8, 12)
    cmd[12:12 + len(path_b)] = path_b
    return bytes(cmd)


def padding_after_lc(raw: bytes, base: int, sizeofcmds: int) -> int:
    end = base + 32 + sizeofcmds
    i = end
    sl_end = slice_range(raw)[1]
    limit = min(sl_end, len(raw))
    while i < limit and raw[i] == 0:
        i += 1
    return i - end


def insert_load_commands_inplace(data: bytearray, base: int) -> list[str]:
    logs = []
    ncmds, sizeofcmds, _ = parse_load_commands(data, base)

    to_add = []
    if not has_load_dylib(data, base, INJECT_NAME):
        to_add.append(build_load_dylib_cmd(INJECT_NAME))
    if not has_rpath(data, base, "@executable_path/Frameworks"):
        to_add.append(build_rpath_cmd("@executable_path/Frameworks"))

    if not to_add:
        logs.append("already has LC_LOAD_DYLIB + LC_RPATH")
        return logs

    need = sum(len(c) for c in to_add)
    pad = padding_after_lc(data, base, sizeofcmds)
    if need > pad:
        raise RuntimeError(
            f"load command padding too small: need {need} bytes, have {pad}"
        )

    insert_at = base + 32 + sizeofcmds
    for cmd in to_add:
        data[insert_at:insert_at + len(cmd)] = cmd
        insert_at += len(cmd)
        sizeofcmds += len(cmd)
        ncmds += 1

    struct.pack_into("<II", data, base + 16, ncmds, sizeofcmds)
    logs.append(f"inserted {len(to_add)} load command(s) (+{need} bytes in padding)")
    return logs


def find_dylibs() -> list[str]:
    candidates = [ROOT, os.path.join(ROOT, "ci-artifacts", "libxrcdemo-sideload")]
    found = []
    for name in DYLIB_NAMES:
        path = None
        for d in candidates:
            p = os.path.join(d, name)
            if os.path.isfile(p):
                path = p
                break
        if not path:
            raise FileNotFoundError(f"dylib missing: {name} (ROOT or ci-artifacts/)")
        found.append(path)
    return found


def check_binary(path: str) -> int:
    """--check：报告任意 Arc-mobile 的桩/注入状态（签名前后都可自查）。"""
    raw = bytearray(open(path, "rb").read())
    base = fat_arm64_slice_offset(raw)
    entry = bytes(raw[base + STUB_ENTRY_FILE:base + STUB_ENTRY_FILE + 12])
    tramp = struct.unpack_from("<10I", raw, base + STUB_TRAMP_FILE)
    has_dylib = has_load_dylib(raw, base, INJECT_NAME)
    has_stub = entry[:4] != STUB_ENTRY_EXPECT[:4]
    stub_v2 = tramp[4] == 0xAA0603E3
    slot = struct.unpack_from("<QQQ", raw, base + STUB_SLOT_FILE) if has_stub else None
    ok = True
    print(f"file       : {path}")
    print(f"entry      : {'PATCHED (ADRP/ADD/BR)' if has_stub else 'original (STP ...)'}")
    print(f"trampoline : {'v2 (MOV X3,X6 present)' if stub_v2 else 'v1 or absent'}")
    print(f"slot       : {slot if slot else '-'}")
    for name, site_va, replay_va, _expect in BRK_HOOKS:
        sf = base + (site_va - 0x100000000)
        insn = struct.unpack_from("<I", raw, sf)[0]
        if replay_va:
            rf = base + (replay_va - 0x100000000)
            tramp_b = raw[rf:rf + 8]
            print(f"brk[{name}]: site {insn:#010x} "
                  f"{'PATCHED' if insn == 0xD4200000 else 'original'}; "
                  f"replay {tramp_b.hex() if any(tramp_b) else 'empty'}")
        else:
            print(f"brk[{name}]: site {insn:#010x} "
                  f"{'PATCHED' if insn == 0xD4200000 else 'original'}; no-replay")
    print(f"dylib LC   : {'@rpath/libxrcdemo.dylib present' if has_dylib else 'MISSING'}")
    gate_ok = 0
    for name, va, expect, patch in GATE_PATCHES:
        gf = base + (va - 0x100000000)
        want = bytes.fromhex(patch)
        cur = bytes(raw[gf:gf + len(want)])
        if cur == want:
            gate_ok += 1
            state = "PATCHED"
        elif cur.hex() == expect:
            state = "original"
        else:
            state = f"UNKNOWN({cur.hex()})"
        print(f"gate[{name}]: {va:#x} {state}")
    print(f"gates      : {gate_ok}/{len(GATE_PATCHES)} patched")
    if has_stub and not has_dylib:
        print("=> INVALID: stub without dylib (features would be dead)")
        ok = False
    if has_stub and not stub_v2:
        print("=> v1 trampoline (missing MOV X3,X6) — 判定链接管需要 v2；请重新打桩")
        ok = False
    if has_stub and stub_v2 and has_dylib:
        print("=> OK: stub v2 + dylib — judge feature should report live on device")
    if not has_stub:
        print("=> NOT PATCHED: this main carries no stub (judge feature unavailable)")
    return 0 if ok else 2


def main():
    # 独立入口：只给指定 app bundle 打 ATS 豁免（用于已经注入过二进制、只需补 plist 的场合）
    #   python inject.py --ats <Arc-mobile.app 路径>
    if "--ats" in sys.argv:
        i = sys.argv.index("--ats")
        if i + 1 >= len(sys.argv):
            print("usage: inject.py --ats <path/to/Arc-mobile.app>")
            sys.exit(1)
        global APP
        APP = sys.argv[i + 1]
        if not os.path.isdir(APP):
            print(f"[!] not a directory: {APP}")
            sys.exit(1)
        try:
            for line in patch_ats():
                print(f"[+] {line}")
            for line in patch_filesharing():
                print(f"[+] {line}")
        except Exception as e:
            print(f"[!] {e}")
            sys.exit(1)
        print("[i] re-sign the app before installing")
        sys.exit(0)

    if "--check" in sys.argv:
        i = sys.argv.index("--check")
        if i + 1 >= len(sys.argv):
            print("usage: inject.py --check <Arc-mobile path>")
            sys.exit(1)
        sys.exit(check_binary(sys.argv[i + 1]))
    do_stub = "--stub" in sys.argv
    do_brk = "--brk" in sys.argv
    g_selected_features, g_features_desc = features_selected(sys.argv)
    print(f"[i] build feature set: {g_features_desc} ({len(g_selected_features)} 个功能)")
    for _n, _sites, _rel, _st, _note in FEATURES:
        mark = "+" if _n in g_selected_features else "-"
        try:
            print(f"    [{mark}] {_n:16s} {_st:10s} {_note}")
        except Exception:
            print(f"    [{mark}] {_n}")
    if not os.path.isfile(MAIN):
        print(f"[!] main not found: {MAIN}")
        sys.exit(1)

    try:
        dylibs = find_dylibs()
    except FileNotFoundError as e:
        print(f"[!] {e}")
        sys.exit(1)

    # 配对校验（两条）：
    #   ① autoplay 桩（ap_*）需要 dylib 侧处理器（"autoplay-eve v1"）；
    #   ② 链进度桩（chain_prog）需要 "chain-guard v1"。
    # dylib 与桩表不配套会落默认处理器 → 崩，故缺标记即拒配。
    if any(n.startswith("ap_") for n, _s, _r, _e in BRK_HOOKS):
        marker = b"autoplay-eve v1"
        if not any(marker in open(d, "rb").read() for d in dylibs):
            print("[!] dylibs lack 'autoplay-eve v1' support —")
            print("    ap_* BRK sites would fall through to the fallback table on first hit")
            print("    and chain to Swift/Crashlytics trap handlers. Refusing to mix.")
            sys.exit(3)

    # 同款配对校验：链进度桩（chain_prog，7.0「链」系统查表点）需要 dylib 侧处理器。
    if any(n == "chain_prog" for n, _s, _r, _e in BRK_HOOKS):
        marker = b"chain-guard v1"
        if not any(marker in open(d, "rb").read() for d in dylibs):
            print("[!] dylibs lack 'chain-guard v1' support —")
            print("    chain_prog BRK would replay the original lookup → NULL deref crash")
            print("    for renamed ids / moved packs. Refusing to mix.")
            sys.exit(3)

    # 同款配对校验：全条件放行族（unlock_all/dl_ready 诸站 + pack_open + shutter_done）需要 dylib 侧处理器。
    # jacket_* 是 no-replay 条件分支桩：旧 dylib 无处理器时会落兜底/默认陷阱 → 必须拒配。
    if any(n in ("lock_all", "play_gate", "dl_play", "cond_unlock_a", "cond_unlock_b",
                 "jacket_lock", "jacket_cell", "jacket_info", "jacket_panel", "pack_open",
                 "shutter_done")
           for n, _s, _r, _e in BRK_HOOKS):
        marker = b"unlock-policy v3"
        if not any(marker in open(d, "rb").read() for d in dylibs):
            print("[!] dylibs lack 'unlock-policy v3' support —")
            print("    unlock-policy BRK sites (incl. no-replay jacket_lock / pack_open / shutter_done)")
            print("    would fall through to the default trap handlers. Refusing to mix.")
            sys.exit(3)

    os.makedirs(FW_DIR, exist_ok=True)
    for d in dylibs:
        dst = os.path.join(FW_DIR, os.path.basename(d))
        shutil.copy2(d, dst)
        print(f"[+] copied -> {dst}")

    # ATS 豁免：私服走明文 HTTP，必须放开（否则请求被静默拦截）
    try:
        for line in patch_ats():
            print(f"[+] {line}")
    except Exception as e:
        print(f"[!] ATS patch failed: {e}")
        sys.exit(1)

    # 文件共享：Documents 在「文件」App / 电脑上可见（cb 外置能被外部管理的前提）
    try:
        for line in patch_filesharing():
            print(f"[+] {line}")
    except Exception as e:
        print(f"[!] file-sharing patch failed: {e}")
        sys.exit(1)

    with open(MAIN, "rb") as f:
        data = bytearray(f.read())

    base = fat_arm64_slice_offset(data)
    try:
        logs = insert_load_commands_inplace(data, base)
        for line in logs:
            print(f"[+] {line}")
    except RuntimeError as e:
        print(f"[!] {e}")
        sys.exit(1)

    if do_stub:
        try:
            logs = patch_judge_stub(data)
            for line in logs:
                print(f"[+] {line}")
        except RuntimeError as e:
            print(f"[!] stub: {e}")
            sys.exit(1)
        print("[i] stub patched — re-sign the app before installing")

    if do_brk:
        try:
            logs = patch_brk_hooks(data, sites_for(g_selected_features))
            for line in logs:
                print(f"[+] {line}")
        except RuntimeError as e:
            print(f"[!] brk: {e}")
            sys.exit(1)
        print("[i] brk hook patched — re-sign the app before installing")

    # 门禁静态补丁：默认不应用，须显式 --gate 打开（表为空时为无操作）。
    do_gates = "--gate" in sys.argv
    if do_gates:
        try:
            logs = patch_gates(data)
            for line in logs:
                print(f"[+] {line}")
        except RuntimeError as e:
            print(f"[!] gates: {e}")
            sys.exit(1)

    with open(MAIN, "wb") as f:
        f.write(data)

    size = os.path.getsize(MAIN)
    with open(MAIN, "rb") as f:
        raw = f.read()
    _, sl_end = slice_range(raw)
    print(f"[+] wrote {MAIN}")
    print(f"[i] size={size} (slice_end={sl_end})")
    if size < sl_end - 1000:
        print("[!] WARNING: file smaller than slice - possible corruption")
        sys.exit(1)

    # ---- 补丁清单：本二进制的实际补丁状态落盘，与 dylib 侧启动自检
    # （xrc_brk_static_report）互为对照，可审计。
    import json as _json
    import datetime as _dt
    manifest = {
        "generated": _dt.datetime.now().isoformat(timespec="seconds"),
        "main": os.path.relpath(MAIN, ROOT).replace("\\", "/"),
        "applied": {
            "dylib_injection": True,
            "ats_exemption": True,
            "judge_stub_v2": bool(do_stub),
            "brk_hooks": bool(do_brk),
            "gate_patches": bool(do_gates),
        },
        "features_desc": g_features_desc if do_brk else None,
        "features": [{"name": n, "status": st, "note": note,
                      "sites": sites, "enabled": (n in g_selected_features)}
                     for n, sites, _r, st, note in FEATURES] if do_brk else [],
        "brk_sites": [n for n, _s, _r, _e in BRK_HOOKS
                      if do_brk and (sites_for(g_selected_features) is None
                                     or n in sites_for(g_selected_features))],
        "gate_patches": [
            {"name": n, "va": hex(va), "patch": pt}
            for n, va, _e, pt in (GATE_PATCHES if do_gates else [])
        ],
        "dylibs": [os.path.basename(d) for d in dylibs],
    }

    # ---- 状态清单：**重扫当前二进制实际字节**，而非本次命令行旗标 ----
    import hashlib as _hashlib
    with open(MAIN, "rb") as f:
        cur = bytearray(f.read())
    cbase = fat_arm64_slice_offset(cur)
    cur_entry = bytes(cur[cbase + STUB_ENTRY_FILE:cbase + STUB_ENTRY_FILE + 12])
    cur_tramp = struct.unpack_from("<10I", cur, cbase + STUB_TRAMP_FILE)
    brk_inplace, brk_absent, brk_other = [], [], []
    for site_name, site_va, _replay_va, expect in BRK_HOOKS:
        sf = cbase + (site_va - 0x100000000)
        insn = struct.unpack_from("<I", cur, sf)[0] if sf + 4 <= len(cur) else 0
        if insn == 0xD4200000:
            brk_inplace.append(site_name)
        elif expect is not None and insn == int.from_bytes(bytes.fromhex(expect), "little"):
            brk_absent.append(site_name)
        else:
            brk_other.append(site_name)
    restore_ok, restore_left = [], []
    for site_name, site_va, _rhex in RESTORE_SITES:
        sf = cbase + (site_va - 0x100000000)
        insn = struct.unpack_from("<I", cur, sf)[0] if sf + 4 <= len(cur) else 0
        (restore_left if insn == 0xD4200000 else restore_ok).append(site_name)
    dylib_info = []
    for p in dylibs:
        b = open(p, "rb").read()
        dylib_info.append({
            "name": os.path.basename(p),
            "size": len(b),
            "sha256": _hashlib.sha256(b).hexdigest(),
        })
    if cur_entry[:4] != STUB_ENTRY_EXPECT[:4]:
        stub_state = "v2" if cur_tramp[4] == 0xAA0603E3 else "v1"
    else:
        stub_state = "none"
    manifest["state"] = {
        "rescanned": _dt.datetime.now().isoformat(timespec="seconds"),
        "judge_stub": stub_state,
        "load_dylib": has_load_dylib(cur, cbase, INJECT_NAME),
        "brk_sites": {"inplace": brk_inplace, "absent": brk_absent, "unexpected": brk_other},
        "restore_sites": {"restored": restore_ok, "still_patched": restore_left},
        "dylibs": dylib_info,
    }

    mpath = os.path.join(ROOT, "xrc_patch_manifest.json")
    with open(mpath, "w", encoding="utf-8") as mf:
        _json.dump(manifest, mf, ensure_ascii=False, indent=2)
    print(f"[i] patch manifest -> {mpath}")
    print(f"[i] applied: stub={do_stub} brk={do_brk} gates={do_gates} "
          f"brk_sites={len(manifest['brk_sites'])} features={manifest.get('features_desc')}")
    _st = manifest["state"]
    print(f"[i] state(rescan): stub={_st['judge_stub']} dylib={_st['load_dylib']} "
          f"brk inplace={len(_st['brk_sites']['inplace'])}/{len(BRK_HOOKS)} "
          f"restore pending={len(_st['restore_sites']['still_patched'])}")

    # 组合守卫：打桩的二进制必须同时载入 dylib，否则
    # 跳板会把判定核转发给 slot（handler=0 → 直通）——游戏能玩但功能全无；
    # 反向（载入 dylib 但没打桩）则由 dylib 侧降级（judge 区禁用）。
    with open(MAIN, "rb") as f:
        final = bytearray(f.read())
    fbase = fat_arm64_slice_offset(final)
    has_dylib = has_load_dylib(final, fbase, INJECT_NAME)
    # 打桩判据 = 入口首 4 字节已不是原始 STP（被 12 字节 ADRP/ADD/BR 覆盖）
    has_stub = bytes(final[fbase + STUB_ENTRY_FILE:fbase + STUB_ENTRY_FILE + 4]) != STUB_ENTRY_EXPECT[:4]
    print(f"[i] combination check: dylib={has_dylib} stub={has_stub}")
    if has_stub and not has_dylib:
        print("[!] INVALID COMBINATION: stub patched but LC_LOAD_DYLIB missing —")
        print("    the judge trampoline would dispatch to a NULL handler (features dead).")
        print("    Re-run without --stub for a clean injection, or keep both.")
        sys.exit(2)


if __name__ == "__main__":
    main()
