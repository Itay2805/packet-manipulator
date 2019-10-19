#include <jni.h>
#include <string.h>

JNIEXPORT jobject JNICALL
Java_me_itay_packetmanipulator_pcapproxy_JNI_NewDirectByteBuffer(JNIEnv *env, jclass clazz, jlong value, jlong size) {
    return (*env)->NewDirectByteBuffer(env, (void*)value, size);
}

JNIEXPORT jboolean JNICALL
Java_me_itay_packetmanipulator_pcapproxy_JNI_is64bit(JNIEnv *env, jclass clazz) {
    return sizeof(void*) == 8 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL
Java_me_itay_packetmanipulator_pcapproxy_JNI_NewStringUTF(JNIEnv *env, jclass clazz, jlong ptr) {
    return (*env)->NewStringUTF(env, (const char *) ptr);
}