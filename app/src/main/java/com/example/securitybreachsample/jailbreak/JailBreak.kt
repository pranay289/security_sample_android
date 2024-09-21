package com.example.securitybreachsample.jailbreak

import android.content.Context
import java.security.NoSuchAlgorithmException

interface JailBreak {

    //    private val SIGNATURE = "Your apk signature"
//    private val PLAY_STORE_APP_ID = "com.android.vending"
//    val TAG: String = TamperUtils::class.java.getSimpleName()
    @Throws(NoSuchAlgorithmException::class)
    fun bytesToHex(bytes: ByteArray): String

    /**
     * To check app signature
     */
    fun isAppSignatureValid(context: Context): Boolean

    fun isInstalledFromPlayStore(context: Context,playStoreAppId:String?=null): Boolean
//      fun isDebuggable(context:Context):Boolean

    fun isUsingEmulator(): Boolean
//    fun isRooted(): Boolean
//      fun isRooted():Boolean
}
