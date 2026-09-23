#include "memUtils.hpp"
#include "Logging.hpp"

#include "x32/jni/include/Utils.hpp"
#include "x32/jni/libs/Substrate/SubstrateHook.hpp"

size_t g_libAddress = NULL;

size_t getLibraryAddress(const char *libName) {
  return get_libBase(libName);
}

size_t getActualOffset(size_t offset) {
  return getRealOffset(offset);
}

size_t getOriginalOffset(size_t actualOffset) {
  return getOriOffset(actualOffset);
}

void PVZ2HookFunction(size_t offset, void *replace, void **result, const char *funcName) {
  MSHookFunction((void *)getActualOffset(offset), replace, result);
  LOGI("Hooked %s", funcName);
}

void *copyVFTable(size_t vftableAddr, int numVFuncs) {
  size_t size = numVFuncs * sizeof(size_t);
  void *vftableCopy = malloc(size);
  memcpy(vftableCopy, (const void *)vftableAddr, size);
  return vftableCopy;
}

void patchVFTable(void *vftable, void *funcAddr, int index) {
  void **slot = &((reinterpret_cast<void **>(vftable))[index]);
  // vtable 可能在 .data.rel.ro（只读）——先解锁所在页（对 malloc 副本无副作用）
  // 页大小动态获取：兼容 16KB 页设备（Pixel 8 系列等）
  size_t pageSize = (size_t)sysconf(_SC_PAGESIZE);
  size_t page = (size_t)slot & ~(pageSize - 1);
  if (mprotect((void *)page, pageSize * 2, PROT_READ | PROT_WRITE) != 0) {
    LOGW("patchVFTable: mprotect failed at %p", (void *)slot);
    return;  // 解锁失败 → 不写（写只读内存必崩）
  }
  *slot = funcAddr;
}

// 指令 patch（权威做法参照 And64InlineHook __make_rwx）：
// 页对齐 + 完整覆盖目标 → RWX 解锁 → 写入 → flush 指令缓存 → 恢复 r-x（短窗口，
// Android 10+ 对代码段加 W 许可有严格限制，恢复可避免持续 RWX 被拒/被内核重置）
void patchInsn32(size_t offset, uint32_t value) {
  uint32_t *p = (uint32_t *)getActualOffset(offset);
  size_t pageSize = (size_t)sysconf(_SC_PAGESIZE);
  uintptr_t start = (uintptr_t)p & ~(pageSize - 1);
  uintptr_t end = ((uintptr_t)p + sizeof(uint32_t) + pageSize - 1) & ~(pageSize - 1);
  if (mprotect((void *)start, end - start, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
    LOGW("patchInsn32: mprotect(RWX) failed at %p", (void *)p);
    return;
  }
  *p = value;
  __builtin___clear_cache((char *)p, (char *)p + sizeof(uint32_t));
  if (mprotect((void *)start, end - start, PROT_READ | PROT_EXEC) != 0) {
    LOGW("patchInsn32: restore r-x failed at %p", (void *)p);
  }
}

void copyVFTable(void *dest, size_t vftableAddr, int numVFuncsToCopy) {
  size_t size = numVFuncsToCopy * sizeof(size_t);
  memcpy(dest, (const void *)vftableAddr, size);
}

void *createChildVFTable(int vFuncsCount, size_t parentVftable, int nuMVFuncsToCopy) {
  if (nuMVFuncsToCopy > vFuncsCount)
    nuMVFuncsToCopy = vFuncsCount;  // 防 memcpy 越界
  size_t size = vFuncsCount * sizeof(size_t);
  void *childVftable = malloc(size);
  copyVFTable(childVftable, parentVftable, nuMVFuncsToCopy);

  return childVftable;
}

void setVFTable(void *obj, void *newVftablePtr) {
  *reinterpret_cast<void **>(obj) = newVftablePtr;
}

void *GetVirtualFunc(void *obj, int index) {
  void **vtable = *reinterpret_cast<void ***>(obj);
  return vtable[index];
}