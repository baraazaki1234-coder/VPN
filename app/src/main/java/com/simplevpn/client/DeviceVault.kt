package com.simplevpn.client

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Encrypts local VPN material with an AES-GCM key held by Android Keystore.
 * Plaintext private keys are never written to app files.
 */
class DeviceVault(context: Context) {
    private val appContext = context.applicationContext
    private val directory = File(appContext.filesDir, "secure-vault").apply { mkdirs() }

    fun writeString(name: String, value: String) = writeBytes(name, value.toByteArray(Charsets.UTF_8))

    fun readString(name: String): String? =
        readBytes(name)?.toString(Charsets.UTF_8)

    fun writeBytes(name: String, plaintext: ByteArray) {
        require(name.matches(Regex("[a-zA-Z0-9._-]{1,80}")))
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val encrypted = cipher.doFinal(plaintext)
        val output = cipher.iv + encrypted
        File(directory, name).writeBytes(output)
    }

    fun readBytes(name: String): ByteArray? {
        require(name.matches(Regex("[a-zA-Z0-9._-]{1,80}")))
        val file = File(directory, name)
        if (!file.isFile) return null
        val input = file.readBytes()
        require(input.size > 12 + 16) { "Encrypted vault entry is incomplete" }
        val iv = input.copyOfRange(0, 12)
        val encrypted = input.copyOfRange(12, input.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(128, iv))
        return cipher.doFinal(encrypted)
    }

    private fun getOrCreateKey(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        return generator.generateKey()
    }

    companion object {
        private const val KEY_ALIAS = "simplevpn.local.vault.aes"
    }
}
