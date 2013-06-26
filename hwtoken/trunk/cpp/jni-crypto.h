/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class org_webpki_sks_testclib_AESProvider */

#ifndef _Included_org_webpki_sks_testclib_AESProvider
#define _Included_org_webpki_sks_testclib_AESProvider
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     org_webpki_sks_testclib_AESProvider
 * Method:    createAESProvider
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_webpki_sks_testclib_AESProvider_createAESProvider
  (JNIEnv *, jobject);

/*
 * Class:     org_webpki_sks_testclib_AESProvider
 * Method:    deleteAESProvider
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_webpki_sks_testclib_AESProvider_deleteAESProvider
  (JNIEnv *, jobject, jlong);

/*
 * Class:     org_webpki_sks_testclib_AESProvider
 * Method:    setKey
 * Signature: (J[BZ)V
 */
JNIEXPORT void JNICALL Java_org_webpki_sks_testclib_AESProvider_setKey
  (JNIEnv *, jobject, jlong, jbyteArray, jboolean);

/*
 * Class:     org_webpki_sks_testclib_AESProvider
 * Method:    encrypt
 * Signature: (J[B[BZ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_webpki_sks_testclib_AESProvider_encrypt
  (JNIEnv *, jobject, jlong, jbyteArray, jbyteArray, jboolean);

#ifdef __cplusplus
}
#endif
#endif
/* Header for class org_webpki_sks_testclib_SHA256Provider */

#ifndef _Included_org_webpki_sks_testclib_SHA256Provider
#define _Included_org_webpki_sks_testclib_SHA256Provider
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     org_webpki_sks_testclib_SHA256Provider
 * Method:    createSHA256Provider
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_webpki_sks_testclib_SHA256Provider_createSHA256Provider
  (JNIEnv *, jobject);

/*
 * Class:     org_webpki_sks_testclib_SHA256Provider
 * Method:    deleteSHA256Provider
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_webpki_sks_testclib_SHA256Provider_deleteSHA256Provider
  (JNIEnv *, jobject, jlong);

/*
 * Class:     org_webpki_sks_testclib_SHA256Provider
 * Method:    update
 * Signature: (J[B)V
 */
JNIEXPORT void JNICALL Java_org_webpki_sks_testclib_SHA256Provider_update
  (JNIEnv *, jobject, jlong, jbyteArray);

/*
 * Class:     org_webpki_sks_testclib_SHA256Provider
 * Method:    doFinal
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_webpki_sks_testclib_SHA256Provider_doFinal
  (JNIEnv *, jobject, jlong);

#ifdef __cplusplus
}
#endif
#endif
/* Header for class org_webpki_sks_testclib_SHA1Provider */

#ifndef _Included_org_webpki_sks_testclib_SHA1Provider
#define _Included_org_webpki_sks_testclib_SHA1Provider
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     org_webpki_sks_testclib_SHA1Provider
 * Method:    createSHA1Provider
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_org_webpki_sks_testclib_SHA1Provider_createSHA1Provider
  (JNIEnv *, jobject);

/*
 * Class:     org_webpki_sks_testclib_SHA1Provider
 * Method:    deleteSHA1Provider
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_org_webpki_sks_testclib_SHA1Provider_deleteSHA1Provider
  (JNIEnv *, jobject, jlong);

/*
 * Class:     org_webpki_sks_testclib_SHA1Provider
 * Method:    update
 * Signature: (J[B)V
 */
JNIEXPORT void JNICALL Java_org_webpki_sks_testclib_SHA1Provider_update
  (JNIEnv *, jobject, jlong, jbyteArray);

/*
 * Class:     org_webpki_sks_testclib_SHA1Provider
 * Method:    doFinal
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_webpki_sks_testclib_SHA1Provider_doFinal
  (JNIEnv *, jobject, jlong);

#ifdef __cplusplus
}
#endif
#endif