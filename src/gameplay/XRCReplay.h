// © 雾月星辰 & MLXC · github@XingChenRS
// XRCReplay.h — 回跳重播引擎。
//
// 功能语义：回跳到已游玩并判定过的谱面段落时，支持重新游玩该段，同时清空分数记录。
//
// 重置链的步骤顺序、阈值与守卫均为实测结论——改动前先核对行内注释。
#pragma once

#include <stdint.h>
#include <stdbool.h>

// 启动常驻线程（由 Tweak.x 在关卡安装完成后调用；线程只检出，落笔在主队列）。
void xrc_replay_start(void);

// 回跳重播总门（默认关；面板开关驱动）。
void xrc_replay_set_enabled(bool on);
bool xrc_replay_enabled(void);

// 显式重播请求（暂停驻停提交用）：由调用方给目标 T（ms）。
// 与自动检出同一入口；P 取当前水位线（回跳前高水位），随后水位线消化到 T
// ——防自动检出对同一次回跳再触发一遍。总门关闭/目标越界/场景无效时为无害空操作。
void xrc_replay_request_reset(uint32_t T);

// 按谱面重建 enwidencamera / enwidenlanes（ng+84..+116）。
// 拖动、前跳、后跳、回跳都要走：否则 6k 段跳回 4k 仍是高相机或 6 轨。
void xrc_scn_restore(void *ng, uint32_t T);
