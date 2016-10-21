#pragma once

#include <string>
#include <iostream>
#include <windows.h>

using namespace std;

//不弹框的system，返回执行结果
extern BOOL system_hide(string CommandLine, string &exe_result);

//获取当前主机第一张网卡的MAC地址
extern void get_3part_mac(string &mac);

//通过WMI获取主机信息
extern BOOL ManageWMIInfo(string &result, string table, wstring wcol);

//识别Virtual PC异常
extern DWORD __forceinline IslnsideVPC_exceptionFilter(LPEXCEPTION_POINTERS ep);