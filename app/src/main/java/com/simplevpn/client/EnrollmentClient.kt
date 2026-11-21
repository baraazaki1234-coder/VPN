package com.simplevpn.client

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL

data class EnrollmentResult(
    val deviceId: String,
    val address: String,
    val endpoint: String,
    val serverPublicKey: String,
    val dns: String,
    val allowedIps: String,
    val persistentKeepalive: Int
)

object EnrollmentClient {
    fun enroll(
        baseUrl: String,
        invitation: String,
        deviceName: String,
        publicKey: String
    ): EnrollmentResult {
        val base = baseUrl.trim().trimEnd('/')
        val uri = URI(base)
        require(uri.scheme.equals("https", ignoreCase = true) && !uri.host.isNullOrBlank()) {
            "The control-plane address must be a valid HTTPS URL"
        }
        require(uri.rawUserInfo == null && uri.rawQuery == null && uri.rawFragment == null) {
            "The control-plane URL must not contain credentials, query parameters, or fragments"
        }
        val url = URL("$base/v1/enroll")
        val body = JSONObject()
            .put("invitation", invitation)
            .put("device_name", deviceName)
            .put("public_key", publicKey)
            .toString()
            .toByteArray(Charsets.UTF_8)

        val connection = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = 15_000
            readTimeout = 20_000
            doOutput = true
            setRequestProperty("Content-Type", "application/json; charset=utf-8")
            setRequestProperty("Accept", "application/json")
            setFixedLengthStreamingMode(body.size)
        }
        try {
            connection.outputStream.use { it.write(body) }
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val responseText = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
            val response = try { JSONObject(responseText) } catch (_: Exception) {
                throw IllegalStateException("Control plane returned an unreadable response (HTTP $status)")
            }
            if (status !in 200..299) {
                throw IllegalStateException(response.optString("detail").ifBlank { "Enrollment failed (HTTP $status)" })
            }
            return EnrollmentResult(
                deviceId = response.getString("device_id"),
                address = response.getString("assigned_address"),
                endpoint = response.getString("server_endpoint"),
                serverPublicKey = response.getString("server_public_key"),
                dns = response.getString("dns"),
                allowedIps = response.optString("allowed_ips", "0.0.0.0/0, ::/0"),
                persistentKeepalive = response.optInt("persistent_keepalive", 25)
            )
        } finally {
            connection.disconnect()
        }
    }
}
