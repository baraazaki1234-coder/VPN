package com.novra.vpn

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.content.res.Configuration
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
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
    private val prefs by lazy { getSharedPreferences("vpn_settings", MODE_PRIVATE) }
    private lateinit var backend: GoBackend
    private lateinit var root: ScrollView
    private lateinit var statusCard: LinearLayout
    private lateinit var titleText: TextView
    private lateinit var subtitleText: TextView
    private lateinit var statusText: TextView
    private lateinit var detailText: TextView
    private lateinit var configName: TextView
    private lateinit var statsText: TextView
    private lateinit var securityNote: TextView
    private lateinit var settingsButton: Button
    private lateinit var importButton: Button
    private lateinit var connectButton: Button
    private lateinit var disconnectButton: Button

    private var activeConfig: Config? = null
    private val tunnel = VpnTunnel()
    private val statsRefresh = object : Runnable {
        override fun run() {
            if (!isTunnelUp) return
            worker.execute {
                try {
                    val stats = backend.getStatistics(tunnel)
                    runOnUiThread {
                        statsText.text = tr("Received: %1$s  •  Sent: %2$s", "استقبال: %1$s  •  إرسال: %2$s")
                            .format(formatBytes(stats.totalRx()), formatBytes(stats.totalTx()))
                    }
                } catch (_: Exception) { }
            }
            mainHandler.postDelayed(this, 3000)
        }
    }
    @Volatile private var isTunnelUp = false

    companion object {
        private const val REQUEST_IMPORT = 4101
        private const val REQUEST_VPN_PERMISSION = 4102
        private const val CONFIG_FILE = "tunnel.conf"
        private const val TUNNEL_NAME = "primary"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        bindViews()
        applyPreferences()

        try {
            backend = GoBackend(applicationContext)
        } catch (error: Throwable) {
            showError(tr("Could not initialize WireGuard: %1$s", "تعذر تشغيل محرك WireGuard: %1$s").format(error.message ?: ""))
            importButton.isEnabled = false
            return
        }

        settingsButton.setOnClickListener { showSettings() }
        importButton.setOnClickListener {
            val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "*/*"
            }
            startActivityForResult(intent, REQUEST_IMPORT)
        }
        connectButton.setOnClickListener { requestVpnPermission() }
        disconnectButton.setOnClickListener { disconnect() }
        loadSavedConfig()
    }

    private fun bindViews() {
        root = findViewById(R.id.rootView)
        statusCard = findViewById(R.id.statusCard)
        titleText = findViewById(R.id.titleText)
        subtitleText = findViewById(R.id.subtitleText)
        statusText = findViewById(R.id.statusText)
        detailText = findViewById(R.id.detailText)
        configName = findViewById(R.id.configName)
        statsText = findViewById(R.id.statsText)
        securityNote = findViewById(R.id.securityNote)
        settingsButton = findViewById(R.id.settingsButton)
        importButton = findViewById(R.id.importButton)
        connectButton = findViewById(R.id.connectButton)
        disconnectButton = findViewById(R.id.disconnectButton)
    }

    private fun tr(en: String, ar: String): String =
        if (prefs.getString("language", "ar") == "en") en else ar

    private fun applyPreferences() {
        val theme = prefs.getString("theme", "dark")
        val systemDark = (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) ==
            Configuration.UI_MODE_NIGHT_YES
        val dark = when (theme) {
            "light" -> false
            "system" -> systemDark
            else -> true
        }
        val bg = if (dark) 0xFF101114.toInt() else 0xFFF4F5F7.toInt()
        val card = if (dark) 0xFF1C1E23.toInt() else 0xFFFFFFFF.toInt()
        val primary = if (dark) 0xFFF4F4F5.toInt() else 0xFF17191D.toInt()
        val secondary = if (dark) 0xFFB6BAC3.toInt() else 0xFF5D6470.toInt()
        val accent = if (dark) 0xFFA7C7FF.toInt() else 0xFF315D9B.toInt()
        root.setBackgroundColor(bg)
        statusCard.setBackgroundColor(card)
        titleText.setTextColor(primary)
        statusText.setTextColor(primary)
        subtitleText.setTextColor(secondary)
        detailText.setTextColor(secondary)
        securityNote.setTextColor(secondary)
        configName.setTextColor(accent)
        statsText.setTextColor(accent)
        window.statusBarColor = bg
        window.navigationBarColor = bg
        @Suppress("DEPRECATION")
        window.decorView.systemUiVisibility = if (dark) 0 else View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR or View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR

        val english = prefs.getString("language", "ar") == "en"
        root.layoutDirection = if (english) View.LAYOUT_DIRECTION_LTR else View.LAYOUT_DIRECTION_RTL
        titleText.text = "VPN"
        subtitleText.text = tr("Private connection through an encrypted tunnel", "اتصال خاص عبر نفق مشفّر")
        settingsButton.text = tr("Settings", "الإعدادات")
        importButton.text = tr("Import WireGuard profile (.conf)", "استيراد ملف WireGuard (.conf)")
        connectButton.text = tr("Connect", "اتصال")
        disconnectButton.text = tr("Disconnect", "قطع الاتصال")
        securityNote.text = tr(
            "For leak protection, enable Always-on VPN and Block connections without VPN in Android VPN settings.",
            "لمنع تسرب الاتصال، فعّل دائمًا تشغيل VPN وحظر الاتصالات بدونه من إعدادات VPN في Android."
        )
        if (!isTunnelUp) statusText.text = tr("Disconnected", "غير متصل")
        if (activeConfig == null) {
            configName.text = tr("No profile imported", "لم يتم استيراد إعداد")
            detailText.text = tr("Import a WireGuard profile to get started.", "استورد ملف إعداد WireGuard للبدء.")
        }
    }

    private fun showSettings() {
        val options = arrayOf(
            tr("Appearance", "المظهر"),
            tr("Language", "اللغة"),
            tr("Set up kill switch in Android", "إعداد منع التسرب من Android")
        )
        AlertDialog.Builder(this)
            .setTitle(tr("Settings", "الإعدادات"))
            .setItems(options) { _, which ->
                when (which) {
                    0 -> chooseTheme()
                    1 -> chooseLanguage()
                    2 -> openVpnSettings()
                }
            }
            .setNegativeButton(tr("Close", "إغلاق"), null)
            .show()
    }

    private fun chooseTheme() {
        val values = arrayOf("dark", "light", "system")
        val labels = arrayOf(tr("Dark", "داكن"), tr("Light", "فاتح"), tr("Follow system", "حسب الجهاز"))
        val current = values.indexOf(prefs.getString("theme", "dark")).coerceAtLeast(0)
        AlertDialog.Builder(this)
            .setTitle(tr("Appearance", "المظهر"))
            .setSingleChoiceItems(labels, current) { dialog, which ->
                prefs.edit().putString("theme", values[which]).apply()
                applyPreferences()
                dialog.dismiss()
            }
            .setNegativeButton(tr("Cancel", "إلغاء"), null)
            .show()
    }

    private fun chooseLanguage() {
        val values = arrayOf("ar", "en")
        val labels = arrayOf("العربية", "English")
        val current = values.indexOf(prefs.getString("language", "ar")).coerceAtLeast(0)
        AlertDialog.Builder(this)
            .setTitle(tr("Language", "اللغة"))
            .setSingleChoiceItems(labels, current) { dialog, which ->
                prefs.edit().putString("language", values[which]).apply()
                applyPreferences()
                dialog.dismiss()
            }
            .setNegativeButton(tr("Cancel", "إلغاء"), null)
            .show()
    }

    private fun openVpnSettings() {
        AlertDialog.Builder(this)
            .setTitle(tr("Android leak protection", "منع تسرب الاتصال"))
            .setMessage(tr(
                "Open Android VPN settings, select this VPN, enable Always-on VPN, then enable Block connections without VPN. Android controls these switches; this app cannot force-enable them.",
                "افتح إعدادات VPN في Android، واختر هذا التطبيق، ثم فعّل «VPN دائم التشغيل» وبعدها «حظر الاتصالات بدون VPN». أندرويد هو الذي يتحكم في هذه الخيارات ولا يستطيع التطبيق فرض تفعيلها."
            ))
            .setPositiveButton(tr("Open settings", "فتح الإعدادات")) { _, _ ->
                try {
                    startActivity(Intent(Settings.ACTION_VPN_SETTINGS))
                } catch (_: Exception) {
                    showError(tr("Could not open VPN settings.", "تعذر فتح إعدادات VPN."))
                }
            }
            .setNegativeButton(tr("Cancel", "إلغاء"), null)
            .show()
    }

    @Deprecated("Uses Android document picker and VPN consent activity for broad API compatibility")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_IMPORT && resultCode == RESULT_OK) {
            val uri = data?.data ?: return
            worker.execute {
                try {
                    val bytes = contentResolver.openInputStream(uri)?.use { it.readBytes() }
                        ?: throw IllegalStateException("Cannot read selected file")
                    val parsed = Config.parse(ByteArrayInputStream(bytes))
                    File(filesDir, CONFIG_FILE).writeBytes(bytes)
                    activeConfig = parsed
                    runOnUiThread {
                        configName.text = tr("WireGuard profile imported", "تم استيراد إعداد WireGuard")
                        detailText.text = tr("Profile syntax is valid and ready to connect.", "تنسيق الإعداد صحيح وجاهز لمحاولة الاتصال.")
                        connectButton.isEnabled = true
                        toast(tr("Profile imported", "تم استيراد الإعداد"))
                    }
                } catch (error: Exception) {
                    runOnUiThread { showError(tr("Invalid profile: %1$s", "ملف غير صالح: %1$s").format(error.message ?: "")) }
                }
            }
        } else if (requestCode == REQUEST_VPN_PERMISSION) {
            if (resultCode == RESULT_OK) connect()
            else showError(tr("VPN permission is required.", "لازم توافق على إذن VPN."))
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
                    configName.text = tr("Saved profile loaded", "تم تحميل الإعداد المحفوظ")
                    detailText.text = tr("Your last profile is ready.", "آخر إعداد محفوظ جاهز.")
                    connectButton.isEnabled = true
                }
            } catch (_: Exception) {
                file.delete()
                runOnUiThread { showError(tr("Saved profile is invalid. Import another one.", "الإعداد المحفوظ غير صالح. استورد ملفًا آخر.")) }
            }
        }
    }

    private fun requestVpnPermission() {
        if (activeConfig == null) {
            showError(tr("Import a WireGuard profile first.", "استورد ملف WireGuard أولًا."))
            return
        }
        val permissionIntent = VpnService.prepare(this)
        if (permissionIntent != null) startActivityForResult(permissionIntent, REQUEST_VPN_PERMISSION)
        else connect()
    }

    private fun connect() {
        val config = activeConfig ?: return
        setBusy(true, tr("Starting tunnel…", "جارٍ تشغيل النفق…"))
        worker.execute {
            try {
                backend.setState(tunnel, Tunnel.State.UP, config)
                runOnUiThread {
                    isTunnelUp = true
                    statusText.text = tr("Tunnel active", "النفق يعمل")
                    detailText.text = tr(
                        "The local tunnel started. This does not yet confirm server reachability or internet routing.",
                        "بدأ النفق محليًا، لكن هذا لا يؤكد بعد الوصول للخادم أو مرور الإنترنت من خلاله."
                    )
                    setBusy(false)
                    disconnectButton.isEnabled = true
                    startStatsUpdates()
                }
            } catch (error: Exception) {
                runOnUiThread {
                    isTunnelUp = false
                    setBusy(false)
                    showError(tr("Connection failed: %1$s", "فشل الاتصال: %1$s").format(error.message ?: ""))
                }
            }
        }
    }

    private fun disconnect() {
        setBusy(true, tr("Disconnecting…", "جارٍ قطع الاتصال…"))
        worker.execute {
            try {
                backend.setState(tunnel, Tunnel.State.DOWN, null)
                runOnUiThread {
                    isTunnelUp = false
                    statusText.text = tr("Disconnected", "غير متصل")
                    detailText.text = tr("Tunnel stopped.", "تم إيقاف النفق.")
                    setBusy(false)
                    connectButton.isEnabled = activeConfig != null
                    disconnectButton.isEnabled = false
                    stopStatsUpdates()
                }
            } catch (error: Exception) {
                runOnUiThread {
                    setBusy(false)
                    showError(tr("Could not disconnect: %1$s", "تعذر قطع الاتصال: %1$s").format(error.message ?: ""))
                }
            }
        }
    }

    private fun setBusy(busy: Boolean, message: String? = null) {
        if (message != null) detailText.text = message
        importButton.isEnabled = !busy
        settingsButton.isEnabled = !busy
        connectButton.isEnabled = !busy && activeConfig != null && !isTunnelUp
        disconnectButton.isEnabled = !busy && isTunnelUp
    }

    private fun startStatsUpdates() {
        mainHandler.removeCallbacks(statsRefresh)
        mainHandler.post(statsRefresh)
    }

    private fun stopStatsUpdates() {
        mainHandler.removeCallbacks(statsRefresh)
        statsText.text = tr("Traffic: —", "البيانات: —")
    }

    private fun formatBytes(value: Long): String {
        if (value < 1024) return "$value B"
        val units = arrayOf("KB", "MB", "GB", "TB")
        var amount = value.toDouble()
        var index = -1
        do { amount /= 1024.0; index++ } while (amount >= 1024.0 && index < units.lastIndex)
        return String.format(Locale.US, "%.1f %s", amount, units[index])
    }

    private fun showError(message: String) {
        detailText.text = message
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }

    private fun toast(message: String) = Toast.makeText(this, message, Toast.LENGTH_SHORT).show()

    override fun onDestroy() {
        mainHandler.removeCallbacks(statsRefresh)
        worker.shutdown()
        super.onDestroy()
    }

    private inner class VpnTunnel : Tunnel {
        override fun getName(): String = TUNNEL_NAME
        override fun onStateChange(newState: Tunnel.State) {
            runOnUiThread {
                isTunnelUp = newState == Tunnel.State.UP
                statusText.text = if (isTunnelUp) tr("Tunnel active", "النفق يعمل") else tr("Disconnected", "غير متصل")
                disconnectButton.isEnabled = isTunnelUp
                connectButton.isEnabled = !isTunnelUp && activeConfig != null
                if (isTunnelUp) startStatsUpdates() else stopStatsUpdates()
            }
        }
    }
}
