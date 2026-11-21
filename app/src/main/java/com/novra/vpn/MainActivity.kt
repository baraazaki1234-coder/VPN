package com.novra.vpn

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import java.io.ByteArrayInputStream
import java.io.File
import java.util.Locale
import java.util.concurrent.Executors

class MainActivity : Activity() {
    private val worker = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())
    private val statsRefresh = object : Runnable {
        override fun run() {
            if (statusText.text != "متصل") return
            worker.execute {
                try {
                    val stats = backend.getStatistics(tunnel)
                    runOnUiThread {
                        statsText.text = "استقبال: ${formatBytes(stats.totalRx())}  •  إرسال: ${formatBytes(stats.totalTx())}"
                    }
                } catch (_: Exception) {
                    // Keep the last visible counters; a later refresh can recover.
                }
            }
            mainHandler.postDelayed(this, 3000)
        }
    }
    private lateinit var backend: GoBackend
    private lateinit var statusText: TextView
    private lateinit var detailText: TextView
    private lateinit var configName: TextView
    private lateinit var statsText: TextView
    private lateinit var importButton: Button
    private lateinit var connectButton: Button
    private lateinit var disconnectButton: Button

    private var activeConfig: Config? = null
    private val tunnel = NovraTunnel()

    companion object {
        private const val REQUEST_VPN_PERMISSION = 4102
        private const val CONFIG_FILE = "novra-tunnel.conf"
        private const val TUNNEL_NAME = "novra"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusText = findViewById(R.id.statusText)
        detailText = findViewById(R.id.detailText)
        configName = findViewById(R.id.configName)
        statsText = findViewById(R.id.statsText)
        importButton = findViewById(R.id.importButton)
        connectButton = findViewById(R.id.connectButton)
        disconnectButton = findViewById(R.id.disconnectButton)

        try {
            backend = GoBackend(applicationContext)
        } catch (error: Throwable) {
            showError("تعذر تهيئة محرك WireGuard: ${error.message ?: "خطأ غير معروف"}")
            importButton.isEnabled = false
            return
        }

        importButton.setOnClickListener {
            val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "*/*"
            }
            startActivityForResult(intent, 4101)
        }
        connectButton.setOnClickListener { requestVpnPermission() }
        disconnectButton.setOnClickListener { disconnect() }

        loadSavedConfig()
    }

    @Deprecated("Using the platform document picker for broad Android compatibility")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 4101 && resultCode == RESULT_OK) {
            val uri = data?.data ?: return
            worker.execute {
                try {
                    val bytes = contentResolver.openInputStream(uri)?.use { it.readBytes() }
                        ?: throw IllegalStateException("تعذر قراءة الملف")
                    val parsed = Config.parse(ByteArrayInputStream(bytes))
                    File(filesDir, CONFIG_FILE).writeBytes(bytes)
                    activeConfig = parsed
                    runOnUiThread {
                        configName.text = "تم تحميل إعداد WireGuard"
                        detailText.text = "الإعداد صالح من ناحية التنسيق وجاهز لمحاولة الاتصال."
                        connectButton.isEnabled = true
                        toast("تم استيراد ملف الإعداد")
                    }
                } catch (error: Exception) {
                    runOnUiThread { showError("ملف الإعداد غير صالح: ${error.message ?: "راجع الملف"}") }
                }
            }
        } else if (requestCode == REQUEST_VPN_PERMISSION) {
            if (resultCode == RESULT_OK) connect() else showError("لازم توافق على طلب Android لتشغيل اتصال VPN.")
        }
    }

    private fun loadSavedConfig() {
        val file = File(filesDir, CONFIG_FILE)
        if (!file.exists()) return
        worker.execute {
            try {
                val parsed = file.inputStream().use { Config.parse(it) }
                activeConfig = parsed
                runOnUiThread {
                    configName.text = "إعداد محفوظ على الجهاز"
                    detailText.text = "تم تحميل آخر إعداد محفوظ."
                    connectButton.isEnabled = true
                }
            } catch (_: Exception) {
                file.delete()
                runOnUiThread { showError("الإعداد المحفوظ لم يعد صالحًا؛ استورد ملفًا جديدًا.") }
            }
        }
    }

    private fun requestVpnPermission() {
        if (activeConfig == null) {
            showError("استورد ملف WireGuard أولًا.")
            return
        }
        val permissionIntent = VpnService.prepare(this)
        if (permissionIntent != null) {
            startActivityForResult(permissionIntent, REQUEST_VPN_PERMISSION)
        } else {
            connect()
        }
    }

    private fun connect() {
        val config = activeConfig ?: return
        setBusy(true, "جارٍ إنشاء النفق…")
        worker.execute {
            try {
                backend.setState(tunnel, Tunnel.State.UP, config)
                runOnUiThread {
                    statusText.text = "متصل"
                    detailText.text = "بدأ النفق محليًا. هذا لا يؤكد وحده أن الخادم متاح أو أن الإنترنت يمر عبره."
                    setBusy(false)
                    disconnectButton.isEnabled = true
                    startStatsUpdates()
                }
            } catch (error: Exception) {
                runOnUiThread {
                    setBusy(false)
                    showError("فشل الاتصال: ${error.message ?: "تعذر تشغيل النفق"}")
                }
            }
        }
    }

    private fun disconnect() {
        setBusy(true, "جارٍ قطع الاتصال…")
        worker.execute {
            try {
                backend.setState(tunnel, Tunnel.State.DOWN, null)
                runOnUiThread {
                    statusText.text = "غير متصل"
                    detailText.text = "تم إيقاف النفق."
                    setBusy(false)
                    connectButton.isEnabled = activeConfig != null
                    disconnectButton.isEnabled = false
                    stopStatsUpdates()
                }
            } catch (error: Exception) {
                runOnUiThread {
                    setBusy(false)
                    showError("تعذر قطع الاتصال: ${error.message ?: "خطأ غير معروف"}")
                }
            }
        }
    }

    private fun setBusy(busy: Boolean, message: String? = null) {
        if (message != null) detailText.text = message
        importButton.isEnabled = !busy
        connectButton.isEnabled = !busy && activeConfig != null
        disconnectButton.isEnabled = !busy && statusText.text == "متصل"
    }

    private fun startStatsUpdates() {
        mainHandler.removeCallbacks(statsRefresh)
        mainHandler.post(statsRefresh)
    }

    private fun stopStatsUpdates() {
        mainHandler.removeCallbacks(statsRefresh)
        statsText.text = "البيانات: —"
    }

    private fun formatBytes(value: Long): String {
        if (value < 1024) return "${value} B"
        val units = arrayOf("KB", "MB", "GB", "TB")
        var amount = value.toDouble()
        var index = -1
        do {
            amount /= 1024.0
            index++
        } while (amount >= 1024.0 && index < units.lastIndex)
        return String.format(Locale.US, "%.1f %s", amount, units[index])
    }

    private fun showError(message: String) {
        detailText.text = message
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }

    private fun toast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }

    override fun onDestroy() {
        mainHandler.removeCallbacks(statsRefresh)
        worker.shutdown()
        super.onDestroy()
    }

    private inner class NovraTunnel : Tunnel {
        override fun getName(): String = TUNNEL_NAME
        override fun onStateChange(newState: Tunnel.State) {
            runOnUiThread {
                val up = newState == Tunnel.State.UP
                statusText.text = if (up) "متصل" else "غير متصل"
                disconnectButton.isEnabled = up
                connectButton.isEnabled = !up && activeConfig != null
                if (up) startStatsUpdates() else stopStatsUpdates()
            }
        }
    }
}
