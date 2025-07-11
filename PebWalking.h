#pragma once

void* GetModuleBase(const wchar_t* name);
void* GetProcedureAddress(void* base, const char* name);
