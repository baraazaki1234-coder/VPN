package com.simplevpn.client

import android.app.Application
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import java.io.ByteArrayInputStream
import java.util.concurrent.Executors

class VpnApplication : Application() {
    val backend: GoBackend by lazy { GoBackend(this) }
    val tunnel: Tunnel = object : Tunnel {
        override fun getName(): String = "primary"
        override fun onStateChange(newState: Tunnel.State) {
            // The activity observes state through explicit backend operations and statistics.
        }
    }
    private val alwaysOnExecutor = Executors.newSingleThreadExecutor()

    override fun onCreate() {
        super.onCreate()
        // Android invokes this callback when the system starts the VPN service in Always-on mode.
        // Keep the profile in app-private storage so the system can restore it after a reboot.
        GoBackend.setAlwaysOnCallback {
            alwaysOnExecutor.execute {
                try {
                    val profile = DeviceVault(this).readBytes("tunnel.conf.enc")
                    if (profile != null) {
                        val config = Config.parse(ByteArrayInputStream(profile))
                        backend.setState(tunnel, Tunnel.State.UP, config)
                    }
                } catch (_: Exception) {
                    // Fail closed: with Android lockdown enabled, traffic remains blocked
                    // if the saved profile cannot be restored.
                }
            }
        }
    }
}
