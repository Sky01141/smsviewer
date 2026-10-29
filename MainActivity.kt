package local.smsviewer

import android.Manifest
import android.annotation.SuppressLint
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.Telephony
import android.telephony.SmsManager
import android.util.Base64
import android.view.WindowManager
import android.webkit.JavascriptInterface
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.webkit.WebViewAssetLoader
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class MainActivity : AppCompatActivity() {

    private lateinit var web: WebView

    // 認証状態とコードはネイティブ側だけが持つ。コードはWebへ渡さない。
    @Volatile private var authed = false
    private var code: String? = null
    private var codeAt = 0L
    private var tries = 0
    private var lastSend = 0L

    // リモート中継（任意・既定オフ）。パスフレーズと中継URLはメモリ内のみ、永続保存しない。
    @Volatile private var remoteOn = false
    @Volatile private var relayUrl = ""
    @Volatile private var relayPass = ""
    @Volatile private var relayRoom = ""

    private val windowMs = 30L * 60L * 1000L
    private val codeLifeMs = 5L * 60L * 1000L
    private val perms = arrayOf(Manifest.permission.READ_SMS, Manifest.permission.SEND_SMS)

    private val permLauncher =
        registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { r ->
            js("window.__onPerm(${perms.all { r[it] == true }})")
        }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)

        val loader = WebViewAssetLoader.Builder()
            .addPathHandler("/assets/", WebViewAssetLoader.AssetsPathHandler(this))
            .build()

        web = WebView(this)
        setContentView(web)
        web.settings.apply {
            javaScriptEnabled = true
            allowFileAccess = false
            allowContentAccess = false
            domStorageEnabled = false
            databaseEnabled = false
            setSupportZoom(false)
        }
        web.webViewClient = object : WebViewClient() {
            override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest): WebResourceResponse? {
                if (request.url.host == WebViewAssetLoader.DEFAULT_DOMAIN) {
                    return loader.shouldInterceptRequest(request.url)
                }
                return WebResourceResponse("text/plain", "utf-8", 403, "Blocked", emptyMap(), ByteArrayInputStream(ByteArray(0)))
            }
            // ブリッジで使うのはローカルコンテンツのみ。他ページへの遷移は許可しない。
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest) = true
        }
        web.addJavascriptInterface(Bridge(), "Android")
        web.loadUrl("https://${WebViewAssetLoader.DEFAULT_DOMAIN}/assets/index.html")
    }

    override fun onStop() {
        super.onStop()
        lockNow()
        js("window.__lock&&window.__lock()")
    }

    override fun onDestroy() {
        lockNow()
        web.removeJavascriptInterface("Android")
        web.destroy()
        super.onDestroy()
    }

    @Synchronized private fun lockNow() {
        authed = false
        code = null
        tries = 0
        wipeRelayAsync()
        remoteOn = false
        relayUrl = ""
        relayPass = ""
        relayRoom = ""
    }

    private fun js(c: String) = runOnUiThread { web.evaluateJavascript(c, null) }

    private fun hasPerms() = perms.all {
        ContextCompat.checkSelfPermission(this, it) == PackageManager.PERMISSION_GRANTED
    }

    private fun queryRecent(): String {
        val now = System.currentTimeMillis()
        val arr = JSONArray()
        contentResolver.query(
            Telephony.Sms.Inbox.CONTENT_URI,
            arrayOf(Telephony.Sms._ID, Telephony.Sms.ADDRESS, Telephony.Sms.BODY, Telephony.Sms.DATE),
            "${Telephony.Sms.DATE} >= ? AND ${Telephony.Sms.DATE} <= ?",
            arrayOf((now - windowMs).toString(), now.toString()),
            "${Telephony.Sms.DATE} DESC LIMIT 50"
        )?.use { c ->
            while (c.moveToNext()) {
                arr.put(JSONObject().put("id", c.getLong(0)).put("a", c.getString(1) ?: "")
                    .put("b", c.getString(2) ?: "").put("d", c.getLong(3)))
            }
        }
        return arr.toString()
    }

    @Suppress("DEPRECATION")
    private fun smsManager(): SmsManager =
        if (Build.VERSION.SDK_INT >= 31) getSystemService(SmsManager::class.java) else SmsManager.getDefault()

    // ---- リモート中継用の暗号化（AES-256-GCM、鍵はPBKDF2でパスフレーズから導出） ----
    // ビューア側(JS/WebCrypto)と定数(ソルト・反復回数・IV長)を必ず一致させること。
    private fun deriveKey(pass: String): SecretKeySpec {
        val salt = "private30-v1-key".toByteArray(Charsets.UTF_8)
        val spec = PBEKeySpec(pass.toCharArray(), salt, 150_000, 256)
        val raw = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        return SecretKeySpec(raw, "AES")
    }

    private fun roomIdFor(pass: String): String {
        val d = MessageDigest.getInstance("SHA-256").digest((pass + ":room").toByteArray(Charsets.UTF_8))
        return d.joinToString("") { "%02x".format(it) }
    }

    private fun encryptForRelay(pass: String, plaintext: String): String {
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, deriveKey(pass), GCMParameterSpec(128, iv))
        val ct = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(iv + ct, Base64.NO_WRAP)
    }

    private fun pushRelay(json: String) {
        if (!remoteOn || relayUrl.isEmpty() || relayPass.isEmpty()) return
        val url = relayUrl; val pass = relayPass; val room = relayRoom
        Thread {
            try {
                val body = JSONObject()
                    .put("payload", encryptForRelay(pass, json))
                    .put("exp", System.currentTimeMillis() + windowMs)
                    .toString()
                val conn = URL("$url/api/push/$room").openConnection() as HttpURLConnection
                conn.requestMethod = "POST"
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/json")
                conn.connectTimeout = 8000; conn.readTimeout = 8000
                conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
                conn.inputStream.close()
                js("window.__onRelay(${conn.responseCode == 200},'')")
            } catch (e: Exception) {
                js("window.__onRelay(false,'通信に失敗しました')")
            }
        }.start()
    }

    private fun wipeRelayAsync() {
        if (relayUrl.isEmpty() || relayRoom.isEmpty()) return
        val url = relayUrl; val room = relayRoom
        Thread {
            try {
                val conn = URL("$url/api/push/$room").openConnection() as HttpURLConnection
                conn.requestMethod = "DELETE"
                conn.connectTimeout = 5000; conn.readTimeout = 5000
                conn.inputStream.close()
            } catch (e: Exception) { /* ベストエフォート */ }
        }.start()
    }

    inner class Bridge {
        @JavascriptInterface
        fun status(): String = JSONObject().put("perm", hasPerms()).put("authed", authed).put("remote", remoteOn).toString()

        @JavascriptInterface
        fun requestPermission() {
            runOnUiThread { permLauncher.launch(perms) }
        }

        /** 6桁コードを作り、入力された番号へSMSで送る。1分に1回まで。 */
        @JavascriptInterface
        @Synchronized
        fun sendCode(number: String) {
            if (!hasPerms()) { js("window.__onSent(false,'権限がありません')"); return }
            if (!Regex("^\\+?\\d{8,15}$").matches(number)) { js("window.__onSent(false,'電話番号の形式が正しくありません')"); return }
            val now = System.currentTimeMillis()
            if (now - lastSend < 60_000) { js("window.__onSent(false,'1分ほど待ってから送ってください')"); return }
            val c = String.format("%06d", SecureRandom().nextInt(1_000_000))
            try {
                smsManager().sendTextMessage(number, null, "Private30 code: $c (valid 5 min)", null, null)
            } catch (e: Exception) {
                js("window.__onSent(false,'送信に失敗しました')"); return
            }
            code = c; codeAt = now; tries = 0; lastSend = now
            js("window.__onSent(true,'コードを送りました。届くまで少し待ってください。')")
        }

        /** コードの照合はネイティブ側で行う。成功すると1回で無効になる。 */
        @JavascriptInterface
        @Synchronized
        fun verifyCode(input: String) {
            val c = code
            if (c == null || System.currentTimeMillis() - codeAt > codeLifeMs) {
                code = null; js("window.__onAuth(false,'コードが無効です。送信し直してください')"); return
            }
            if (MessageDigest.isEqual(c.toByteArray(), input.toByteArray())) {
                code = null; authed = true; js("window.__onAuth(true,'')")
            } else {
                tries++
                if (tries >= 3) { code = null; js("window.__onAuth(false,'3回間違えました。送信し直してください')") }
                else js("window.__onAuth(false,'コードが違います（残り${3 - tries}回）')")
            }
        }

        @JavascriptInterface
        fun fetchRecent() {
            if (!authed || !hasPerms()) { js("window.__onSms(null)"); return }
            Thread {
                val json = try { queryRecent() } catch (e: Exception) { "[]" }
                js("window.__onSms(" + JSONObject.quote(json) + ")")
                pushRelay(json)
            }.start()
        }

        /** リモート閲覧を有効化。中継URLとパスフレーズはメモリ内のみに保持し、ロックで消える。 */
        @JavascriptInterface
        @Synchronized
        fun remoteConfigure(url: String, pass: String) {
            if (!url.startsWith("https://")) { js("window.__onRelay(false,'中継サーバーはhttps://のURLが必要です')"); return }
            if (pass.length < 8) { js("window.__onRelay(false,'パスフレーズは8文字以上にしてください')"); return }
            relayUrl = url.trimEnd('/')
            relayPass = pass
            relayRoom = roomIdFor(pass)
            remoteOn = true
            fetchRecent()
        }

        @JavascriptInterface
        @Synchronized
        fun remoteOff() {
            wipeRelayAsync()
            remoteOn = false; relayUrl = ""; relayPass = ""; relayRoom = ""
        }

        @JavascriptInterface
        fun lock() = lockNow()
    }
}
