package me.bmax.apatch.ui.screen

import android.os.Bundle
import android.util.Base64
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import me.bmax.apatch.R
import me.bmax.apatch.util.getRootShell
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.text.DateFormat
import java.util.Date
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

private fun execWithOutput(command: String): Pair<Int, String> {
    val result = getRootShell().newJob().add(command).exec()
    return Pair(result.code, result.out.joinToString("\n"))
}

// --- Attestation Data Model ---

data class AttestationData(
    val attestationVersion: Int = 0,
    val attestationSecurityLevel: Int = 0,
    val keymasterVersion: Int = 0,
    val keymasterSecurityLevel: Int = 0,
    val attestationChallenge: ByteArray? = null,
    val uniqueId: ByteArray? = null,
    val softwareEnforced: AuthorizationListData = AuthorizationListData(),
    val teeEnforced: AuthorizationListData = AuthorizationListData(),
    val certificateChain: List<CertificateChainInfo> = emptyList()
) {
    fun getCertificateChainEncoded(): ByteArray {
        val factory = CertificateFactory.getInstance("X.509")
        val certs = certificateChain.mapNotNull { it.certificate }
        if (certs.isEmpty()) return ByteArray(0)
        val certPath = factory.generateCertPath(certs)
        return certPath.getEncoded("PKCS7")
    }

    companion object {
        fun parseCertificateChain(certs: List<X509Certificate>): AttestationData {
            val chainInfo = certs.map { cert ->
                CertificateChainInfo(
                    subject = cert.subjectX500Principal.name,
                    issuer = cert.issuerX500Principal.name,
                    serialNumber = cert.serialNumber.toString(16),
                    notBefore = cert.notBefore,
                    notAfter = cert.notAfter,
                    certificate = cert
                )
            }
            // Parse attestation extension from the leaf certificate
            val leafCert = certs.firstOrNull() ?: return AttestationData(certificateChain = chainInfo)
            val attestation = parseAttestationExtension(leafCert)
            return attestation.copy(certificateChain = chainInfo)
        }

        private fun parseAttestationExtension(cert: X509Certificate): AttestationData {
            val oid = "1.3.6.1.4.1.11129.2.17"
            val extValue = cert.getExtensionValue(oid) ?: return AttestationData()
            try {
                // Parse ASN.1 attestation extension
                val octetStringBytes = parseAsn1OctetString(extValue)
                val sequence = parseAsn1Sequence(octetStringBytes)

                val attestationVersion = readAsn1Integer(sequence, 0)
                val attestationSecurityLevel = readAsn1Integer(sequence, 1)
                val keymasterVersion = readAsn1Integer(sequence, 2)
                val keymasterSecurityLevel = readAsn1Integer(sequence, 3)
                val attestationChallenge = readAsn1OctetString(sequence, 4)
                val uniqueId = if (sequence.size > 5) readAsn1OctetString(sequence, 5) else null
                val softwareEnforced = if (sequence.size > 6) parseAuthorizationList(sequence[6]) else AuthorizationListData()
                val teeEnforced = if (sequence.size > 7) parseAuthorizationList(sequence[7]) else AuthorizationListData()

                return AttestationData(
                    attestationVersion = attestationVersion,
                    attestationSecurityLevel = attestationSecurityLevel,
                    keymasterVersion = keymasterVersion,
                    keymasterSecurityLevel = keymasterSecurityLevel,
                    attestationChallenge = attestationChallenge,
                    uniqueId = uniqueId,
                    softwareEnforced = softwareEnforced,
                    teeEnforced = teeEnforced
                )
            } catch (e: Exception) {
                return AttestationData()
            }
        }

        // Minimal ASN.1 parsing helpers (for the attestation extension structure)
        // These are simplified parsers - production code should use BouncyCastle
        private fun parseAsn1OctetString(data: ByteArray): ByteArray {
            // Skip tag and length bytes, return content
            if (data.isEmpty()) return ByteArray(0)
            val tag = data[0].toInt() and 0xFF
            if (tag != 0x04) return data // Not OCTET STRING, return as-is
            return skipTagAndLength(data)
        }

        private fun parseAsn1Sequence(data: ByteArray): List<ByteArray> {
            val result = mutableListOf<ByteArray>()
            if (data.isEmpty()) return result
            val tag = data[0].toInt() and 0xFF
            if (tag != 0x30) return result
            val content = skipTagAndLength(data)
            var offset = 0
            while (offset < content.size) {
                val element = parseAsn1Element(content, offset)
                result.add(element.first)
                offset += element.second
            }
            return result
        }

        private fun parseAsn1Element(data: ByteArray, offset: Int): Pair<ByteArray, Int> {
            if (offset >= data.size) return Pair(ByteArray(0), 0)
            val tag = data[offset].toInt() and 0xFF
            val lenAndContent = readLength(data, offset + 1)
            val length = lenAndContent.first
            val headerSize = lenAndContent.second
            val totalSize = 1 + headerSize + length
            val element = data.sliceArray(offset until minOf(offset + totalSize, data.size))
            return Pair(element, totalSize)
        }

        private fun readLength(data: ByteArray, offset: Int): Pair<Int, Int> {
            if (offset >= data.size) return Pair(0, 1)
            val first = data[offset].toInt() and 0xFF
            if (first < 0x80) return Pair(first, 1)
            val numBytes = first and 0x7F
            if (numBytes == 0) return Pair(-1, 1) // Indefinite length
            var length = 0
            for (i in 0 until numBytes) {
                if (offset + 1 + i >= data.size) break
                length = (length shl 8) or (data[offset + 1 + i].toInt() and 0xFF)
            }
            return Pair(length, 1 + numBytes)
        }

        private fun skipTagAndLength(data: ByteArray): ByteArray {
            if (data.isEmpty()) return ByteArray(0)
            val lenAndContent = readLength(data, 1)
            val length = lenAndContent.first
            val headerSize = lenAndContent.second + 1
            if (length < 0 || headerSize + length > data.size) {
                return data.sliceArray(headerSize until data.size)
            }
            return data.sliceArray(headerSize until headerSize + length)
        }

        private fun readAsn1Integer(elements: List<ByteArray>, index: Int): Int {
            if (index >= elements.size) return 0
            val element = elements[index]
            if (element.isEmpty()) return 0
            val tag = element[0].toInt() and 0xFF
            if (tag != 0x02) return 0 // Not INTEGER
            val content = skipTagAndLength(element)
            var value = 0
            for (b in content) {
                value = (value shl 8) or (b.toInt() and 0xFF)
            }
            return value
        }

        private fun readAsn1OctetString(elements: List<ByteArray>, index: Int): ByteArray? {
            if (index >= elements.size) return null
            val element = elements[index]
            if (element.isEmpty()) return null
            return skipTagAndLength(element)
        }

        private fun parseAuthorizationList(element: ByteArray): AuthorizationListData {
            val seq = parseAsn1Sequence(element)
            val data = mutableMapOf<Int, Any>()
            for (item in seq) {
                if (item.size < 2) continue
                val tag = item[0].toInt() and 0xFF
                val content = skipTagAndLength(item)
                // Tag number is the last byte of the tag (for context-specific tags)
                val tagNo = tag and 0x1F
                // For constructed tags (bit 5 set), the value is nested
                val isConstructed = (tag and 0x20) != 0
                if (isConstructed) {
                    data[tagNo] = parseAsn1Sequence(content)
                } else {
                    data[tagNo] = content
                }
            }
            return AuthorizationListData(rawEntries = data)
        }
    }
}

data class CertificateChainInfo(
    val subject: String = "",
    val issuer: String = "",
    val serialNumber: String = "",
    val notBefore: Date = Date(0),
    val notAfter: Date = Date(0),
    val certificate: X509Certificate? = null
)

data class AuthorizationListData(
    val rawEntries: Map<Int, Any> = emptyMap()
) {
    private val TAG_TYPE_MASK = 0x0FFFFFFF

    private fun getInt(tag: Int): Int? {
        val value = rawEntries[tag and TAG_TYPE_MASK] as? ByteArray ?: return null
        if (value.isEmpty()) return null
        var result = 0
        for (b in value) {
            result = (result shl 8) or (b.toInt() and 0xFF)
        }
        return result
    }

    private fun getBytes(tag: Int): ByteArray? {
        return rawEntries[tag and TAG_TYPE_MASK] as? ByteArray
    }

    private fun getIntSet(tag: Int): Set<Int>? {
        val elements = rawEntries[tag and TAG_TYPE_MASK] as? List<ByteArray> ?: return null
        return elements.mapNotNull { elem ->
            val content = if (elem.size >= 2) {
                val tagByte = elem[0].toInt() and 0xFF
                if (tagByte == 0x02) {
                    // INTEGER
                    var value = 0
                    for (b in elem.sliceArray(2 until elem.size)) {
                        value = (value shl 8) or (b.toInt() and 0xFF)
                    }
                    value
                } else null
            } else null
        }.toSet()
    }

    private fun getBoolean(tag: Int): Boolean {
        return rawEntries.containsKey(tag and TAG_TYPE_MASK)
    }

    val purposes: Set<Int>?
        get() = getIntSet(KM_TAG_PURPOSE)

    val algorithm: Int?
        get() = getInt(KM_TAG_ALGORITHM)

    val keySize: Int?
        get() = getInt(KM_TAG_KEY_SIZE)

    val digests: Set<Int>?
        get() = getIntSet(KM_TAG_DIGEST)

    val ecCurve: Int?
        get() = getInt(KM_TAG_EC_CURVE)

    val noAuthRequired: Boolean
        get() = getBoolean(KM_TAG_NO_AUTH_REQUIRED)

    val origin: Int?
        get() = getInt(KM_TAG_ORIGIN)

    val rootOfTrust: ByteArray?
        get() = getBytes(KM_TAG_ROOT_OF_TRUST)

    val osVersion: Int?
        get() = getInt(KM_TAG_OS_VERSION)

    val osPatchLevel: Int?
        get() = getInt(KM_TAG_OS_PATCHLEVEL)

    val vendorPatchLevel: Int?
        get() = getInt(KM_TAG_VENDOR_PATCHLEVEL)

    val bootPatchLevel: Int?
        get() = getInt(KM_TAG_BOOT_PATCHLEVEL)

    val attestationApplicationId: ByteArray?
        get() = getBytes(KM_TAG_ATTESTATION_APPLICATION_ID)

    companion object {
        const val KM_TAG_PURPOSE = 0x10000001
        const val KM_TAG_ALGORITHM = 0x50000002
        const val KM_TAG_KEY_SIZE = 0x30000003
        const val KM_TAG_DIGEST = 0x50000005
        const val KM_TAG_EC_CURVE = 0x5000000A
        const val KM_TAG_NO_AUTH_REQUIRED = 0x70000207
        const val KM_TAG_ORIGIN = 0x5000020E
        const val KM_TAG_ROOT_OF_TRUST = 0x900002C0
        const val KM_TAG_OS_VERSION = 0x300002C1
        const val KM_TAG_OS_PATCHLEVEL = 0x300002C2
        const val KM_TAG_VENDOR_PATCHLEVEL = 0x300002CE
        const val KM_TAG_BOOT_PATCHLEVEL = 0x300002CF
        const val KM_TAG_ATTESTATION_APPLICATION_ID = 0x900002C5
    }
}

// --- ViewModel ---

class KeyAttestationViewModel {
    var attestationData by mutableStateOf<AttestationData?>(null)
    var certificateChain by mutableStateOf<ByteArray?>(null)
    var isLoading by mutableStateOf(false)
    var error by mutableStateOf<String?>(null)
    var keyboxExists by mutableStateOf(false)
    var bootloaderLocked by mutableStateOf(true)

    private val executor: ExecutorService = Executors.newSingleThreadExecutor()

    init {
        checkKeyboxStatus()
        checkBootloaderStatus()
    }

    private fun checkKeyboxStatus() {
        executor.execute {
            val (code, _) = execWithOutput("test -f /data/adb/tricky_store/keybox.xml && echo exists || echo not_found")
            keyboxExists = code == 0
        }
    }

    private fun checkBootloaderStatus() {
        executor.execute {
            val (_, output) = execWithOutput("getprop ro.boot.verifiedbootstate")
            bootloaderLocked = output.trim() == "green"
        }
    }

    fun generateAttestation() {
        isLoading = true
        error = null
        executor.execute {
            try {
                val keyStore = KeyStore.getInstance("AndroidKeyStore")
                keyStore.load(null)
                val alias = "folkpatch_attestation_${System.currentTimeMillis()}"
                val keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
                )
                val spec = KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
                )
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(byteArrayOf(1, 2, 3, 4))
                    .build()
                keyPairGenerator.initialize(spec)
                keyPairGenerator.generateKeyPair()
                val chain = keyStore.getCertificateChain(alias)
                val certs = chain.map { it as X509Certificate }
                val result = AttestationData.parseCertificateChain(certs)
                attestationData = result
                certificateChain = result.getCertificateChainEncoded()
                error = null
            } catch (e: Exception) {
                error = e.message ?: "Unknown error"
                attestationData = null
                certificateChain = null
            } finally {
                isLoading = false
            }
        }
    }

    fun loadCertificateFromUri(inputStream: InputStream?) {
        if (inputStream == null) {
            error = "Failed to open file"
            return
        }
        isLoading = true
        error = null
        executor.execute {
            try {
                val bytes = inputStream.readBytes()
                inputStream.close()
                val factory = CertificateFactory.getInstance("X.509")
                val certs = factory.generateCertificates(ByteArrayInputStream(bytes))
                    .map { it as X509Certificate }
                if (certs.isEmpty()) {
                    throw Exception("No certificate found")
                }
                val result = AttestationData.parseCertificateChain(certs)
                attestationData = result
                certificateChain = bytes
                error = null
            } catch (e: Exception) {
                error = e.message ?: "Failed to load certificate"
                attestationData = null
                certificateChain = null
            } finally {
                isLoading = false
            }
        }
    }

    fun replaceKeyBox() {
        executor.execute {
            val (code, output) = execWithOutput("ls /sdcard/keybox.xml")
            if (code != 0) {
                error = "keybox.xml not found in /sdcard/"
                return@execute
            }
            val (code2, output2) = execWithOutput("cp /sdcard/keybox.xml /data/adb/tricky_store/keybox.xml && chmod 644 /data/adb/tricky_store/keybox.xml")
            if (code2 == 0) {
                keyboxExists = true
                error = null
            } else {
                error = output2
            }
        }
    }

    fun viewKeyBox() {
        executor.execute {
            val (code, output) = execWithOutput("cat /data/adb/tricky_store/keybox.xml")
            if (code == 0) {
                // Could display the content, for now just log
                error = null
            } else {
                error = "Failed to read keybox: $output"
            }
        }
    }

    fun clearError() {
        error = null
    }
}

// --- Helper functions ---

fun securityLevelToString(level: Int): String {
    return when (level) {
        0 -> "Software"
        1 -> "TEE"
        2 -> "StrongBox"
        else -> "Unknown ($level)"
    }
}

fun attestationVersionToString(version: Int): String {
    return when (version) {
        1 -> "Keymaster 2.0"
        2 -> "Keymaster 3.0"
        3 -> "Keymaster 4.0"
        4 -> "Keymaster 4.1"
        100 -> "KeyMint 1.0"
        200 -> "KeyMint 2.0"
        300 -> "KeyMint 3.0"
        400 -> "KeyMint 4.0"
        else -> "Unknown ($version)"
    }
}

fun keymasterVersionToString(version: Int): String {
    return when (version) {
        0 -> "Keymaster 0.2 or 0.3"
        1 -> "Keymaster 1.0"
        2 -> "Keymaster 2.0"
        3 -> "Keymaster 3.0"
        4 -> "Keymaster 4.0"
        41 -> "Keymaster 4.1"
        100 -> "KeyMint 1.0"
        200 -> "KeyMint 2.0"
        300 -> "KeyMint 3.0"
        400 -> "KeyMint 4.0"
        else -> "Unknown ($version)"
    }
}

fun algorithmToString(algorithm: Int?): String {
    return when (algorithm) {
        1 -> "RSA"
        3 -> "EC"
        32 -> "AES"
        128 -> "HMAC"
        else -> "Unknown"
    }
}

fun ecCurveToString(curve: Int?): String {
    return when (curve) {
        0 -> "P-224"
        1 -> "secp256r1 (P-256)"
        2 -> "P-384"
        3 -> "P-521"
        4 -> "Curve25519"
        else -> "Unknown"
    }
}

fun purposeToString(purpose: Int): String {
    return when (purpose) {
        0 -> "DECRYPT"
        1 -> "ENCRYPT"
        2 -> "SIGN"
        3 -> "VERIFY"
        5 -> "WRAP"
        6 -> "AGREE_KEY"
        7 -> "ATTEST_KEY"
        else -> "UNKNOWN($purpose)"
    }
}

fun digestToString(digest: Int): String {
    return when (digest) {
        0 -> "NONE"
        1 -> "MD5"
        2 -> "SHA1"
        3 -> "SHA-224"
        4 -> "SHA-256"
        5 -> "SHA-384"
        6 -> "SHA-512"
        else -> "UNKNOWN($digest)"
    }
}

fun patchLevelToString(patchLevel: Int?): String {
    if (patchLevel == null) return "N/A"
    val year = patchLevel / 10000
    val month = patchLevel % 10000 / 100
    return "%04d-%02d".format(year, month)
}

fun bytesToHex(bytes: ByteArray?): String {
    if (bytes == null) return "N/A"
    return bytes.joinToString("") { "%02x".format(it) }
}

fun verifiedBootStateToString(state: Int): String {
    return when (state) {
        0 -> "Verified"
        1 -> "Self-signed"
        2 -> "Unverified"
        3 -> "Failed"
        else -> "Unknown ($state)"
    }
}

// --- Composable UI ---

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KeyAttestationScreen(
    viewModel: KeyAttestationViewModel = remember { KeyAttestationViewModel() }
) {
    var selectedTab by remember { mutableIntStateOf(0) }
    val tabs = listOf("认证", "证书", "加载")

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.key_attestation_title)) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer
                )
            )
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
        ) {
            TabRow(selectedTabIndex = selectedTab) {
                tabs.forEachIndexed { index, title ->
                    Tab(
                        selected = selectedTab == index,
                        onClick = { selectedTab = index },
                        text = { Text(title) }
                    )
                }
            }

            when (selectedTab) {
                0 -> AttestationTab(viewModel)
                1 -> CertificateTab(viewModel)
                2 -> LoadTab(viewModel)
            }
        }
    }
}

@Composable
fun AttestationTab(viewModel: KeyAttestationViewModel) {
    val scrollState = rememberScrollState()

    Box(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(16.dp)
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            // ===== 操作按钮区域（固定在顶部）=====
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                )
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    // 生成认证按钮
                    Button(
                        onClick = { viewModel.generateAttestation() },
                        modifier = Modifier.fillMaxWidth(),
                        enabled = !viewModel.isLoading
                    ) {
                        Icon(Icons.Filled.VerifiedUser, contentDescription = null)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("生成认证")
                    }

                    // 加载证书 + 保存证书 按钮行
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        OutlinedButton(
                            onClick = { /* TODO: load certificate */ },
                            modifier = Modifier.weight(1f)
                        ) {
                            Icon(Icons.Filled.FileOpen, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("加载证书")
                        }
                        OutlinedButton(
                            onClick = { /* TODO: save certificate */ },
                            modifier = Modifier.weight(1f)
                        ) {
                            Icon(Icons.Filled.Save, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("保存证书")
                        }
                    }
                }
            }

            // Loading indicator
            if (viewModel.isLoading) {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.Center
                    ) {
                        CircularProgressIndicator(modifier = Modifier.size(24.dp))
                        Spacer(modifier = Modifier.width(12.dp))
                        Text("正在生成认证...")
                    }
                }
            }

            // Error display
            viewModel.error?.let { errorMsg ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.errorContainer
                    )
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            text = errorMsg,
                            color = MaterialTheme.colorScheme.onErrorContainer,
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.weight(1f)
                        )
                        IconButton(onClick = { viewModel.clearError() }) {
                            Icon(Icons.Filled.Close, contentDescription = "Dismiss")
                        }
                    }
                }
            }

            // 设备信息卡片（始终显示）
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "设备信息",
                        style = MaterialTheme.typography.titleMedium
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    KAInfoRow("品牌", android.os.Build.BRAND ?: "Unknown")
                    KAInfoRow("型号", android.os.Build.MODEL ?: "Unknown")
                    KAInfoRow("Android 版本", android.os.Build.VERSION.RELEASE ?: "Unknown")
                    KAInfoRow("安全补丁级别", android.os.Build.VERSION.SECURITY_PATCH ?: "Unknown")
                    KAInfoRow("设备标识符", android.os.Build.FINGERPRINT ?: "Unknown")
                }
            }

            // ===== 生成的结果卡片（在按钮下方，用户往下滑查看）=====
            viewModel.attestationData?.let { data ->
                // Certificate Root Trust Status
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            text = "证书根信任状态",
                            style = MaterialTheme.typography.titleMedium
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Filled.Warning,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.error
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "未验证证书",
                                color = MaterialTheme.colorScheme.error
                            )
                        }
                        Text(
                            text = "根证书不是来自已知可信源",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }

                // Certificate Chain
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            text = "证书链 (${data.certificateChain.size} 证书)",
                            style = MaterialTheme.typography.titleMedium
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        data.certificateChain.forEachIndexed { index, cert ->
                            CertificateChainItem(index + 1, cert)
                            if (index < data.certificateChain.size - 1) {
                                HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                            }
                        }
                    }
                }

                // Basic Info
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            text = "基本信息",
                            style = MaterialTheme.typography.titleMedium
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        KAInfoRow("认证版本", attestationVersionToString(data.attestationVersion))
                        KAInfoRow("认证安全级别", securityLevelToString(data.attestationSecurityLevel))
                        KAInfoRow("Keymaster 版本", keymasterVersionToString(data.keymasterVersion))
                        KAInfoRow("Keymaster 安全级别", securityLevelToString(data.keymasterSecurityLevel))
                    }
                }

                // TEE Enforced Authorization List
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            text = "授权列表 (TEE 强制执行)",
                            style = MaterialTheme.typography.titleMedium
                        )
                        Spacer(modifier = Modifier.height(8.dp))

                        data.teeEnforced.purposes?.let { purposes ->
                            KAInfoRow("用途", purposes.joinToString(", ") { purposeToString(it) })
                        }
                        data.teeEnforced.algorithm?.let {
                            KAInfoRow("算法", algorithmToString(it))
                        }
                        data.teeEnforced.keySize?.let {
                            KAInfoRow("密钥大小", it.toString())
                        }
                        data.teeEnforced.digests?.let { digests ->
                            KAInfoRow("摘要", digests.joinToString(", ") { digestToString(it) })
                        }
                        data.teeEnforced.ecCurve?.let {
                            KAInfoRow("椭圆曲线", ecCurveToString(it))
                        }
                        KAInfoRow("不需要身份验证", data.teeEnforced.noAuthRequired.toString())

                        // Root of Trust
                        data.teeEnforced.rootOfTrust?.let { rootBytes ->
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                text = "信任根 (Root of Trust)",
                                style = MaterialTheme.typography.titleSmall
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            // Parse minimal root of trust from raw bytes
                            val deviceLocked = parseDeviceLocked(rootBytes)
                            val vbState = parseVerifiedBootState(rootBytes)
                            val vbKey = parseVerifiedBootKey(rootBytes)
                            val vbHash = parseVerifiedBootHash(rootBytes)

                            KAInfoRow("DeviceLocked", deviceLocked.toString())
                            KAInfoRow("VerifiedBootState", verifiedBootStateToString(vbState))
                            KAInfoRow(
                                "VerifiedBootKey",
                                bytesToHex(vbKey).chunked(2).joinToString(":")
                                    .takeIf { it.length > 64 }
                                    ?: bytesToHex(vbKey)
                            )
                            vbHash?.let {
                                KAInfoRow("VerifiedBootHash", bytesToHex(it))
                            }
                        }

                        // Patch levels
                        data.teeEnforced.osPatchLevel?.let {
                            KAInfoRow("系统补丁级别", patchLevelToString(it))
                        }
                        data.teeEnforced.vendorPatchLevel?.let {
                            KAInfoRow("Vendor 补丁级别", patchLevelToString(it))
                        }
                        data.teeEnforced.bootPatchLevel?.let {
                            KAInfoRow("Boot 补丁级别", patchLevelToString(it))
                        }

                        // Application ID
                        data.teeEnforced.attestationApplicationId?.let { appId ->
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                text = "应用 ID",
                                style = MaterialTheme.typography.titleSmall
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = Base64.encodeToString(appId, Base64.NO_WRAP),
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace,
                                modifier = Modifier.fillMaxWidth()
                            )
                        }
                    }
                }

                // Software Enforced (if non-empty)
                if (data.softwareEnforced.rawEntries.isNotEmpty()) {
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Text(
                                text = "授权列表 (软件强制执行)",
                                style = MaterialTheme.typography.titleMedium
                            )
                            Spacer(modifier = Modifier.height(8.dp))
                            data.softwareEnforced.purposes?.let { purposes ->
                                KAInfoRow("用途", purposes.joinToString(", ") { purposeToString(it) })
                            }
                            data.softwareEnforced.algorithm?.let {
                                KAInfoRow("算法", algorithmToString(it))
                            }
                            data.softwareEnforced.osPatchLevel?.let {
                                KAInfoRow("系统补丁级别", patchLevelToString(it))
                            }
                        }
                    }
                }
            }

            // KeyBox 管理卡片（始终显示）
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "KeyBox 管理",
                        style = MaterialTheme.typography.titleMedium
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    // KeyBox 状态
                    val keyboxStatus = remember { mutableStateOf("检测中...") }
                    LaunchedEffect(Unit) {
                        val result = execWithOutput("ls -la /data/adb/tricky_store/keybox.xml 2>/dev/null && echo EXISTS || echo NOT_FOUND")
                        keyboxStatus.value = if (result.second.contains("EXISTS")) "已存在" else "不存在"
                    }
                    KAInfoRow("状态", keyboxStatus.value)
                    KAInfoRow("路径", "/data/adb/tricky_store/keybox.xml")
                }
            }
        }
    }
}

@Composable
fun CertificateTab(viewModel: KeyAttestationViewModel) {
    val scrollState = rememberScrollState()
    val context = LocalContext.current

    val saveLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument()
    ) { uri ->
        uri?.let {
            try {
                context.contentResolver.openOutputStream(it)?.use { os ->
                    viewModel.certificateChain?.let { bytes ->
                        os.write(bytes)
                    }
                }
            } catch (e: Exception) {
                viewModel.error = "保存失败: ${e.message}"
            }
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(16.dp)
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            if (viewModel.certificateChain != null) {
                Button(
                    onClick = {
                        saveLauncher.launch("attestation_certificates.p7b")
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Filled.Save, contentDescription = null)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("保存证书链 (PKCS7)")
                }
            }

            viewModel.attestationData?.let { data ->
                data.certificateChain.forEachIndexed { index, cert ->
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text(
                                    text = "证书 #${index + 1}",
                                    style = MaterialTheme.typography.titleMedium
                                )
                            }
                            Spacer(modifier = Modifier.height(8.dp))
                            KAInfoRow("主题", cert.subject)
                            KAInfoRow("颁发者", cert.issuer)
                            KAInfoRow("序列号", cert.serialNumber.toString(16))
                            KAInfoRow(
                                "有效期从",
                                DateFormat.getDateTimeInstance()
                                    .format(cert.notBefore)
                            )
                            KAInfoRow(
                                "有效期至",
                                DateFormat.getDateTimeInstance()
                                    .format(cert.notAfter)
                            )
                        }
                    }
                }
            } ?: run {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(32.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            text = "暂无证书数据",
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun LoadTab(viewModel: KeyAttestationViewModel) {
    val context = LocalContext.current

    val loadLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        uri?.let {
            try {
                val inputStream = context.contentResolver.openInputStream(it)
                viewModel.loadCertificateFromUri(inputStream)
            } catch (e: Exception) {
                viewModel.error = "加载失败: ${e.message}"
            }
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Icon(
                imageVector = Icons.Filled.FileOpen,
                contentDescription = null,
                modifier = Modifier.size(64.dp),
                tint = MaterialTheme.colorScheme.primary
            )
            Text(
                text = "加载证书链",
                style = MaterialTheme.typography.titleLarge
            )
            Text(
                text = "选择包含证书链的文件（PKCS7、PEM 或 DER 格式）",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(16.dp))
            Button(onClick = { loadLauncher.launch(arrayOf("*/*")) }) {
                Icon(Icons.Filled.FolderOpen, contentDescription = null)
                Spacer(modifier = Modifier.width(8.dp))
                Text("选择文件")
            }

            if (viewModel.isLoading) {
                Spacer(modifier = Modifier.height(16.dp))
                CircularProgressIndicator()
            }
        }
    }
}

@Composable
fun CertificateChainItem(index: Int, cert: CertificateChainInfo) {
    Column {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                text = "#$index",
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.primary
            )
            Text(
                text = "序列号: ${cert.serialNumber}",
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f, fill = false)
            )
        }
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = "颁发者: ${cert.issuer}",
            style = MaterialTheme.typography.bodySmall,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis
        )
        Text(
            text = "有效期至: ${DateFormat.getDateInstance().format(cert.notAfter)}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
fun KAKAInfoRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(0.4f)
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.weight(0.6f)
        )
    }
}

// --- Minimal Root of Trust parsing from raw ASN.1 bytes ---

private fun parseDeviceLocked(rootBytes: ByteArray): Boolean {
    // RootOfTrust ::= SEQUENCE { verifiedBootKey OCTET_STRING, deviceLocked BOOLEAN, ... }
    try {
        val content = AttestationData.skipTagAndLength(rootBytes)
        var offset = 0
        // Skip verifiedBootKey (OCTET_STRING)
        if (offset >= content.size) return false
        val tag1 = content[offset].toInt() and 0xFF
        val len1 = AttestationData.readLength(content, offset + 1)
        offset += 1 + len1.second + maxOf(len1.first, 0)
        // Read deviceLocked (BOOLEAN)
        if (offset >= content.size) return false
        val tag2 = content[offset].toInt() and 0xFF
        if (tag2 == 0x01 && offset + 2 < content.size) {
            return content[offset + 2].toInt() != 0
        }
    } catch (_: Exception) {}
    return false
}

private fun parseVerifiedBootState(rootBytes: ByteArray): Int {
    try {
        val content = AttestationData.skipTagAndLength(rootBytes)
        var offset = 0
        // Skip verifiedBootKey
        if (offset >= content.size) return 3
        val len1 = AttestationData.readLength(content, offset + 1)
        offset += 1 + len1.second + maxOf(len1.first, 0)
        // Skip deviceLocked (BOOLEAN)
        if (offset >= content.size) return 3
        val len2 = AttestationData.readLength(content, offset + 1)
        offset += 1 + len2.second + maxOf(len2.first, 0)
        // Read verifiedBootState (ENUMERATED)
        if (offset >= content.size) return 3
        val tag3 = content[offset].toInt() and 0xFF
        if (tag3 == 0x0A && offset + 2 < content.size) {
            return content[offset + 2].toInt() and 0xFF
        }
    } catch (_: Exception) {}
    return 3
}

private fun parseVerifiedBootKey(rootBytes: ByteArray): ByteArray {
    try {
        val content = AttestationData.skipTagAndLength(rootBytes)
        if (content.isEmpty()) return ByteArray(0)
        // First element is verifiedBootKey (OCTET_STRING)
        return AttestationData.skipTagAndLength(content)
    } catch (_: Exception) {}
    return ByteArray(0)
}

private fun parseVerifiedBootHash(rootBytes: ByteArray): ByteArray? {
    try {
        val content = AttestationData.skipTagAndLength(rootBytes)
        var offset = 0
        // Skip verifiedBootKey
        if (offset >= content.size) return null
        val len1 = AttestationData.readLength(content, offset + 1)
        offset += 1 + len1.second + maxOf(len1.first, 0)
        // Skip deviceLocked
        if (offset >= content.size) return null
        val len2 = AttestationData.readLength(content, offset + 1)
        offset += 1 + len2.second + maxOf(len2.first, 0)
        // Skip verifiedBootState
        if (offset >= content.size) return null
        val len3 = AttestationData.readLength(content, offset + 1)
        offset += 1 + len3.second + maxOf(len3.first, 0)
        // Read verifiedBootHash (OCTET_STRING)
        if (offset >= content.size) return null
        return AttestationData.skipTagAndLength(content.sliceArray(offset until content.size))
    } catch (_: Exception) {}
    return null
}
