#include "pch.h"
#include "minhook/MinHook.h"
#include <vector>
#pragma comment(lib,"minhook/minhook.lib")

uintptr_t FindPattern(const char* signature, bool bRelative = false, uint32_t offset = 0)
{
	uintptr_t base_address = reinterpret_cast<uintptr_t>(GetModuleHandle(NULL));
	static auto patternToByte = [](const char* pattern)
	{
		auto bytes = std::vector<int>{};
		const auto start = const_cast<char*>(pattern);
		const auto end = const_cast<char*>(pattern) + strlen(pattern);

		for (auto current = start; current < end; ++current)
		{
			if (*current == '?')
			{
				++current;
				if (*current == '?') ++current;
				bytes.push_back(-1);
			}
			else { bytes.push_back(strtoul(current, &current, 16)); }
		}
		return bytes;
	};

	const auto dosHeader = (PIMAGE_DOS_HEADER)base_address;
	const auto ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t*)base_address + dosHeader->e_lfanew);

	const auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
	auto patternBytes = patternToByte(signature);
	const auto scanBytes = reinterpret_cast<std::uint8_t*>(base_address);

	const auto s = patternBytes.size();
	const auto d = patternBytes.data();

	for (auto i = 0ul; i < sizeOfImage - s; ++i)
	{
		bool found = true;
		for (auto j = 0ul; j < s; ++j)
		{
			if (scanBytes[i + j] != d[j] && d[j] != -1)
			{
				found = false;
				break;
			}
		}
		if (found)
		{
			uintptr_t address = reinterpret_cast<uintptr_t>(&scanBytes[i]);
			if (bRelative)
			{
				address = ((address + offset + 4) + *(int32_t*)(address + offset));
				return address;
			}
			return address;
		}
	}
	return NULL;
}


bool ISILS_Detour() {
	return false;
}

void Init() {
	MessageBoxA(0, "LS Patcher\nMade by GD", "LS Patcher", MB_OK);
	//(TODO) get the address by the string "Reason for Showing/Hiding LoadingScreen is unknown!"
	uintptr_t Add = FindPattern("48 89 4C 24 ? 55 53 56 57 41 ? 41 ? 48 8B EC 48 83 EC 38 4C 8B F1");
	if (!Add) {
		Add = FindPattern("48 89 5C 24 ? 48 89 4C 24 ? 55 56 57 41 54 41 56 48 8B EC 48 83 EC 30 48 8B F1");
		if (!Add) {
			FindPattern("48 89 5C 24 ? 55 57 41 54 41 55 41 56 48 8B EC 48 83 EC 30 4C 8B E1");
		}
	}
   	MH_Initialize();
    	MH_CreateHook((LPVOID)Add, ISILS_Detour, nullptr);
	MH_EnableHook((LPVOID)Add);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        Init();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
