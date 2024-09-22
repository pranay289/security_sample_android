package com.example.securitybreachsample.jailbreak

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException


class AppDeviceSecurityCheck private constructor() : JailBreak {
    private val googleManufacturer = "Google"
    private val googleBrand = "google"

    private val sdkGphonePrefix = "google/sdk_gphone_"
    private val sdkGphoneReleaseSuffix = ":user/release-keys"
    private val sdkGphoneProductPrefix = "sdk_gphone_"
    private val sdkGphoneModelPrefix = "sdk_gphone_"

    private val sdkGphone64Prefix = "google/sdk_gphone64_"
    private val sdkGphone64ReleaseSuffix = ":userdebug/dev-keys"
    private val sdkGphone64ReleaseSuffix2 = ":user/release-keys"
    private val sdkGphone64ProductPrefix = "sdk_gphone64_"
    private val sdkGphone64ModelPrefix = "sdk_gphone64_"

    private val kiwiModel = "HPE device"
    private val kiwiFingerprintPrefix = "google/kiwi_"
    private val kiwiBoard = "kiwi"
    private val kiwiProductPrefix = "kiwi_"

    private val genericFingerprint = "generic"
    private val unknownFingerprint = "unknown"

    private val googleSdkModel = "google_sdk"
    private val emulatorModel = "Emulator"
    private val androidSdkX86Model = "Android SDK built for x86"

    private val qcReferenceBoard = "QC_Reference_Phone"
    private val xiaomiManufacturer = "Xiaomi"
    private val genymotionManufacturer = "Genymotion"

    private val buildHostPrefix = "Build"

    private val kernelQemuProperty = "ro.kernel.qemu"
    private val kernelQemuValue = "1"
    private val SIGNATURE = "D5235DDDC04D46D7F5AFF2B967424490F1EB596F"

    override fun bytesToHex(bytes: ByteArray): String {
        val hexArray = charArrayOf(
            '0', '1', '2', '3', '4', '5', '6', '7', '8',
            '9', 'A', 'B', 'C', 'D', 'E', 'F'
        )
        val hexChars = CharArray(bytes.size * 2)
        for (j in bytes.indices) {
            val v = bytes[j].toInt() and 0xFF
            hexChars[j * 2] = hexArray[v shr 4]
            hexChars[j * 2 + 1] = hexArray[v and 0x0F]
        }
        return String(hexChars)
    }

    override fun isAppSignatureValid(context: Context): Boolean {
        var packageInfo: PackageInfo? = null
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                packageInfo = context.packageManager.getPackageInfo(
                    context.packageName, PackageManager.GET_SIGNING_CERTIFICATES
                )
                val data = packageInfo.signingInfo.signingCertificateHistory
                for (signature in data) {
                    // SHA1 the signature
                    val sha1: String = getSHA1(signature.toByteArray())

                    // check is matches hardcoded value
                    return SIGNATURE == sha1
                }
            } else {
                @Suppress("DEPRECATION")
                packageInfo = context.packageManager.getPackageInfo(
                    context.packageName, PackageManager.GET_SIGNATURES
                )
                //note sample just checks the first signature
                for (signature in packageInfo.signatures) {
                    // SHA1 the signature
                    val sha1: String = getSHA1(signature.toByteArray())

                    // check is matches hardcoded value
                    return SIGNATURE == sha1
                }
            }

        } catch (e: PackageManager.NameNotFoundException) {
            Log.e("Errorr", e.message, e)
        } catch (e: NoSuchAlgorithmException) {
            Log.e("Errorr", e.message, e)
        } catch (e: NoSuchProviderException) {
            Log.e("Errorr", e.message, e)
        }
        return false
    }

    override fun isInstalledFromPlayStore(context: Context, playStoreAppId: String?): Boolean {
        val infoData: String?
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            infoData =
                context.packageManager.getInstallSourceInfo(context.packageName).installingPackageName

        } else {
            @Suppress("DEPRECATION")
            infoData = context.packageManager.getInstallerPackageName(context.packageName)
        }
        return infoData != null && (infoData == (playStoreAppId
            ?: "com.android.vending"))
    }

    companion object {
        val instance = AppDeviceSecurityCheck()
    }


    override fun isUsingEmulator(): Boolean {
        return (Build.MANUFACTURER == googleManufacturer && Build.BRAND == googleBrand &&
                ((Build.FINGERPRINT.startsWith(sdkGphonePrefix) &&
                        Build.FINGERPRINT.endsWith(sdkGphoneReleaseSuffix) &&
                        Build.PRODUCT.startsWith(sdkGphoneProductPrefix) &&
                        Build.MODEL.startsWith(sdkGphoneModelPrefix)) ||
                        (Build.FINGERPRINT.startsWith(sdkGphone64Prefix) &&
                                (Build.FINGERPRINT.endsWith(sdkGphone64ReleaseSuffix) ||
                                        (Build.FINGERPRINT.endsWith(sdkGphone64ReleaseSuffix2) &&
                                                Build.PRODUCT.startsWith(sdkGphone64ProductPrefix) &&
                                                Build.MODEL.startsWith(sdkGphone64ModelPrefix)))) ||
                        (Build.MODEL == kiwiModel &&
                                Build.FINGERPRINT.startsWith(kiwiFingerprintPrefix) &&
                                Build.FINGERPRINT.endsWith(sdkGphoneReleaseSuffix) &&
                                Build.BOARD == kiwiBoard &&
                                Build.PRODUCT.startsWith(kiwiProductPrefix))) ||
                Build.FINGERPRINT.startsWith(genericFingerprint) ||
                Build.FINGERPRINT.startsWith(unknownFingerprint) ||
                Build.MODEL.contains(googleSdkModel) ||
                Build.MODEL.contains(emulatorModel) ||
                Build.MODEL.contains(androidSdkX86Model) ||
                (Build.BOARD == qcReferenceBoard &&
                        !Build.MANUFACTURER.equals(xiaomiManufacturer, ignoreCase = true)) ||
                Build.MANUFACTURER.contains(genymotionManufacturer) ||
                Build.HOST.startsWith(buildHostPrefix) ||
                (Build.BRAND.startsWith(genericFingerprint) &&
                        Build.DEVICE.startsWith(genericFingerprint)) ||
                Build.PRODUCT == googleSdkModel ||
                System.getProperty(kernelQemuProperty) == kernelQemuValue
                )
    }

    private fun getSHA1(sig: ByteArray?): String {
        try {


            val digest = MessageDigest.getInstance("SHA1")
            if (sig != null) {
                digest.update(sig)
            }
            val hashText = digest.digest()
            return bytesToHex(hashText)
        } catch (e: Exception) {
            throw e
        }
    }
//    override fun isRooted(): Boolean {
//        val places = listOf(
//            "/sbin/",
//            "/system/bin/",
//            "/system/xbin/",
//            "/data/local/xbin/",
//            "/data/local/bin/",
//            "/system/sd/xbin/",
//            "/system/bin/failsafe/",
//            "/data/local/"
//        )
//        places.forEach { path ->
//            val file = File(path + "su")
//            if (file.exists()) {
//                println("Found: ${file.path}")
//            } else {
//                println("Not found: ${file.path}")
//            }
//                println("Found: ${file.path}")
//
//        }
//
//        return places.any { File(it + "su").exists() }
//    }


}