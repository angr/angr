#include <stdbool.h>

#if defined(__linux__) || defined(__FreeBSD__) || defined(__APPLE__) || defined(__OpenBSD__)
#include <dlfcn.h>
#elif defined(_WIN32)
#include <windows.h>
#else
#error "Unsupported platform - need dlopen equivalent"
#endif

#define ANGR_UNICORN_API
#include <unicorn/unicorn.h>

bool simunicorn_setup_imports(char *uc_path) {

#if defined(__linux__) || defined(__FreeBSD__) || defined(__APPLE__) || defined(__OpenBSD__)
	void *handle = dlopen(uc_path, RTLD_NOW | RTLD_GLOBAL);
	if (!handle) {
		return false;
	}
#define XX(x) *((void**)&x) = (void*)dlsym(handle, #x); if (!x) { return false; }
#include "uc_macro.h"

#elif defined(_WIN32)
	HMODULE handle = LoadLibraryA(uc_path);
	if (!handle) {
		return false;
	}
#define XX(x) *((void**)&x) = (void*)GetProcAddress(handle, #x); if (!x) { return false; }
#include "uc_macro.h"

#endif

	return true;
}
