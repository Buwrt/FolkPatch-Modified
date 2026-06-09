package me.bmax.apatch.ui.screen

import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewmodel.compose.viewModel
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import com.ramcosta.composedestinations.navigation.DestinationsNavigator
import io.github.vvb2060.keyattestation.attestation.Attestation
import io.github.vvb2060.keyattestation.attestation.AuthorizationList
import io.github.vvb2060.keyattestation.attestation.RootOfTrust
import io.github.vvb2060.keyattestation.repository.AttestationData
import me.bmax.apatch.R
import me.bmax.apatch.util.getRootShell
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties

private fun execWithOutput(command: String): Pair<Int, String> {
    val result = getRootShell().newJob().add(command).exec()
    return Pair(result.code, result.out.joinToString("\n"))
}

@Destination<RootGraph>
@Composable
fun KeyAttestationScreen(navigator: DestinationsNavigator) {
    val viewModel: KeyAttestationViewModel = viewModel()
    val context = LocalContext.current

    // File picker for loading certificate
    val filePickerLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        uri?.let {
            viewModel.loadCertificateFromUri(context.contentResolver.openInputStream(it))
        }
    }

    // File saver for saving certificate
    val fileSaverLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri: Uri? ->
        uri?.let {
            viewModel.saveCertificateToUri(context.contentResolver.openOutputStream(it))
        }
    }

    // File picker for KeyBox replacement
    val keyboxPickerLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        uri?.let {
            viewModel.replaceKeyBox(context, it)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.key_attestation)) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color.Transparent
                ),
                actions = {
                    IconButton(onClick = { filePickerLauncher.launch(arrayOf("*/*")) }) {
                        Icon(Icons.Outlined.FolderOpen, contentDescription = "Load")
                    }
                    IconButton(onClick = { viewModel.generateAttestation() }) {
                        Icon(Icons.Outlined.Refresh, contentDescription = "Refresh")
                    }
                }
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .padding(innerPadding)
                .padding(horizontal = 16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Spacer(Modifier.height(4.dp))

            // 1. 密钥认证检测状态卡片
            AttestationStatusCard(viewModel)

            // 2. 操作按钮组：生成认证 + 保存证书
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Button(
                    onClick = { viewModel.generateAttestation() },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.primary
                    )
                ) {
                    Icon(Icons.Filled.VerifiedUser, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.ka_generate))
                }

                OutlinedButton(
                    onClick = {
                        viewModel.certificateChain?.let {
                            fileSaverLauncher.launch("attestation_${System.currentTimeMillis()}.bin")
                        } ?: run {
                            Toast.makeText(context, context.getString(R.string.ka_no_data), Toast.LENGTH_SHORT).show()
                        }
                    },
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(Icons.Outlined.Save, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.ka_save))
                }
            }

            // 3. KeyBox 管理卡片
            KeyBoxManagementCard(viewModel, keyboxPickerLauncher)

            // 4. 证书根信任状态卡片
            viewModel.attestationData?.let { data ->
                CertificateRootTrustCard(data)
            }

            // 5. 引导加载程序状态卡片
            viewModel.attestationData?.let { data ->
                BootloaderStatusCard(data)
            }

            // 6. 认证结果详情
            viewModel.attestationData?.let { data ->
                AttestationResultCard(data)
            }

            // Error Display
            viewModel.error?.let { error ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.errorContainer
                    )
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp)
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                Icons.Filled.Error,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.error
                            )
                            Spacer(Modifier.width(8.dp))
                            Text(
                                stringResource(R.string.ka_error),
                                style = MaterialTheme.typography.titleMedium,
                                color = MaterialTheme.colorScheme.error
                            )
                        }
                        Spacer(Modifier.height(8.dp))
                        Text(
                            error,
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onErrorContainer
                        )
                    }
                }
            }

            // Loading Indicator
            if (viewModel.isLoading) {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(32.dp),
                    contentAlignment = Alignment.Center
                ) {
                    CircularProgressIndicator()
                }
            }

            Spacer(Modifier.height(80.dp))
        }
    }
}

// ==================== 密钥认证检测状态卡片 ====================
@Composable
fun AttestationStatusCard(viewModel: KeyAttestationViewModel) {
    val statusColor = when {
        viewModel.attestationData != null && viewModel.error == null ->
            MaterialTheme.colorScheme.primaryContainer
        viewModel.error != null ->
            MaterialTheme.colorScheme.errorContainer
        else ->
            MaterialTheme.colorScheme.surfaceVariant
    }

    val statusIcon = when {
        viewModel.attestationData != null && viewModel.error == null -> Icons.Filled.CheckCircle
        viewModel.error != null -> Icons.Filled.Error
        else -> Icons.Outlined.Info
    }

    val statusText = when {
        viewModel.attestationData != null && viewModel.error == null ->
            stringResource(R.string.ka_status_verified)
        viewModel.error != null -> stringResource(R.string.ka_status_error)
        else -> stringResource(R.string.ka_status_ready)
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = statusColor)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                statusIcon,
                contentDescription = null,
                modifier = Modifier.size(48.dp),
                tint = when {
                    viewModel.attestationData != null && viewModel.error == null ->
                        MaterialTheme.colorScheme.primary
                    viewModel.error != null -> MaterialTheme.colorScheme.error
                    else -> MaterialTheme.colorScheme.onSurfaceVariant
                }
            )
            Spacer(Modifier.width(16.dp))
            Column {
                Text(
                    stringResource(R.string.ka_detect_title),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    statusText,
                    style = MaterialTheme.typography.bodyMedium
                )
            }
        }
    }
}

// ==================== KeyBox 管理卡片 ====================
@Composable
fun KeyBoxManagementCard(
    viewModel: KeyAttestationViewModel,
    keyboxPickerLauncher: androidx.activity.result.ActivityResultLauncher<Array<String>>
) {
    val keyboxStatus = viewModel.keyboxStatus
    val keyboxContent = viewModel.keyboxContent

    Card(
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                stringResource(R.string.ka_keybox_manage),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            HorizontalDivider()

            // 当前状态
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    stringResource(R.string.ka_keybox_current_status),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    keyboxStatus,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium,
                    color = if (keyboxStatus.contains("不存在") || keyboxStatus.contains("Not found"))
                        MaterialTheme.colorScheme.error
                    else MaterialTheme.colorScheme.primary
                )
            }

            // 路径
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    stringResource(R.string.ka_keybox_path_label),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    stringResource(R.string.ka_keybox_path),
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f).padding(start = 8.dp)
                )
            }

            Spacer(Modifier.height(4.dp))

            // 操作按钮
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedButton(
                    onClick = { keyboxPickerLauncher.launch(arrayOf("*/*")) },
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(Icons.Outlined.UploadFile, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(4.dp))
                    Text(stringResource(R.string.ka_keybox_replace), fontSize = 13.sp)
                }

                OutlinedButton(
                    onClick = { viewModel.viewKeyBoxContent() },
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(Icons.Outlined.Visibility, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(4.dp))
                    Text(stringResource(R.string.ka_keybox_view), fontSize = 13.sp)
                }
            }

            // KeyBox 内容展示
            if (keyboxContent.isNotEmpty()) {
                Spacer(Modifier.height(4.dp))
                HorizontalDivider()
                Text(
                    stringResource(R.string.ka_keybox_content),
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.Bold
                )
                Spacer(Modifier.height(4.dp))
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(8.dp))
                        .background(MaterialTheme.colorScheme.surfaceVariant)
                        .padding(12.dp)
                ) {
                    Text(
                        keyboxContent,
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        maxLines = 15,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
        }
    }
}

// ==================== 证书根信任状态卡片 ====================
@Composable
fun CertificateRootTrustCard(data: AttestationData) {
    val attestation = data.getAttestation()
    val certInfos = data.getCertificateInfos()

    // 检测根证书颁发者
    val rootIssuer = certInfos.lastOrNull()?.getIssuer()?.name ?: "Unknown"

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                Icons.Filled.Security,
                contentDescription = null,
                modifier = Modifier.size(48.dp),
                tint = MaterialTheme.colorScheme.primary
            )
            Spacer(Modifier.width(16.dp))
            Column {
                Text(
                    stringResource(R.string.ka_cert_root_trust),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    rootIssuer,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.primary,
                    fontWeight = FontWeight.Medium
                )
            }
        }
    }
}

// ==================== 引导加载程序状态卡片 ====================
@Composable
fun BootloaderStatusCard(data: AttestationData) {
    val attestation = data.getAttestation()
    val rot = attestation.getRootOfTrust()

    Card(
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                stringResource(R.string.ka_bootloader_status),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            HorizontalDivider()

            // 引导状态
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    stringResource(R.string.ka_boot_state_label),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    if (rot != null) bootStateToString(rot.verifiedBootState) else "N/A",
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium,
                    color = MaterialTheme.colorScheme.primary
                )
            }

            // Bootloader 锁定状态
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    stringResource(R.string.ka_bootloader_label),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    if (rot != null && rot.isDeviceLocked)
                        stringResource(R.string.ka_bootloader_locked)
                    else
                        stringResource(R.string.ka_bootloader_unlocked),
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium,
                    color = MaterialTheme.colorScheme.primary
                )
            }

            // 验证启动密钥
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    stringResource(R.string.ka_verified_boot_key),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    if (rot != null) formatByteArray(rot.verifiedBootKey) else "N/A",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace
                )
            }

            // 验证启动哈希
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    stringResource(R.string.ka_verified_boot_hash),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    if (rot != null) formatByteArray(rot.verifiedBootHash) else "N/A",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace
                )
            }
        }
    }
}

// ==================== 认证结果详情卡片 ====================
@Composable
fun AttestationResultCard(data: AttestationData) {
    val attestation = data.getAttestation()

    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        // Basic Info Card
        Card(
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    stringResource(R.string.ka_basic_info),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                HorizontalDivider()

                AttestationItem(stringResource(R.string.ka_attest_version),
                    Attestation.attestationVersionToString(attestation.getAttestationVersion()))
                AttestationItem(stringResource(R.string.ka_attest_security),
                    Attestation.securityLevelToString(attestation.getAttestationSecurityLevel()))
                AttestationItem(stringResource(R.string.ka_km_version),
                    Attestation.keymasterVersionToString(attestation.getKeymasterVersion()))
                AttestationItem(stringResource(R.string.ka_km_security),
                    Attestation.securityLevelToString(attestation.getKeymasterSecurityLevel()))
            }
        }

        // Software Enforced Card
        Card(
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    stringResource(R.string.ka_sw_enforced),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                HorizontalDivider()

                AuthorizationListItems(attestation.getSoftwareEnforced())
            }
        }

        // TEE Enforced Card
        Card(
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    stringResource(R.string.ka_tee_enforced),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                HorizontalDivider()

                AuthorizationListItems(attestation.getTeeEnforced())
            }
        }

        // Certificate Chain Card
        Card(
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Text(
                    stringResource(R.string.ka_cert_chain),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                HorizontalDivider()

                data.getCertificateInfos().forEachIndexed { index, certInfo ->
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(8.dp))
                            .background(MaterialTheme.colorScheme.surfaceVariant)
                            .padding(8.dp)
                    ) {
                        Text(
                            "${stringResource(R.string.ka_certificate)} #${index + 1}",
                            style = MaterialTheme.typography.labelLarge
                        )
                        Text(
                            "${stringResource(R.string.ka_issuer)}: ${certInfo.getIssuer().name}",
                            style = MaterialTheme.typography.bodySmall
                        )
                        Text(
                            "${stringResource(R.string.ka_subject)}: ${certInfo.getCert().subjectX500Principal.name}",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun AttestationItem(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium
        )
    }
}

@Composable
fun AuthorizationListItems(list: AuthorizationList?) {
    list?.let { authList ->
        if (authList.purposes != null) {
            AttestationItem(stringResource(R.string.ka_purposes), authList.purposes.toString())
        }
        if (authList.algorithm != null) {
            AttestationItem(stringResource(R.string.ka_algorithm),
                algorithmToString(authList.algorithm))
        }
        if (authList.keySize != null) {
            AttestationItem(stringResource(R.string.ka_key_size), "${authList.keySize} bits")
        }
        if (authList.digests != null) {
            AttestationItem(stringResource(R.string.ka_digests), authList.digests.toString())
        }
        if (authList.paddingModes != null) {
            AttestationItem(stringResource(R.string.ka_padding), authList.paddingModes.toString())
        }
        if (authList.origin != null) {
            AttestationItem(stringResource(R.string.ka_origin), originToString(authList.origin))
        }
        if (authList.applicationId != null) {
            AttestationItem(stringResource(R.string.ka_app_id), authList.applicationId.toString())
        }
        if (authList.creationDateTime != null) {
            AttestationItem(stringResource(R.string.ka_creation_time),
                authList.creationDateTime.toString())
        }
    } ?: run {
        Text(
            stringResource(R.string.ka_no_data),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

// Helper functions
private fun formatByteArray(bytes: ByteArray?): String {
    if (bytes == null) return "N/A"
    return bytes.take(8).joinToString("") { "%02X".format(it) } +
            if (bytes.size > 8) "..." else ""
}

private fun bootStateToString(state: Int): String {
    return when (state) {
        RootOfTrust.KM_VERIFIED_BOOT_VERIFIED -> "Verified"
        RootOfTrust.KM_VERIFIED_BOOT_SELF_SIGNED -> "Self Signed"
        RootOfTrust.KM_VERIFIED_BOOT_UNVERIFIED -> "Unverified"
        RootOfTrust.KM_VERIFIED_BOOT_FAILED -> "Failed"
        else -> "Unknown ($state)"
    }
}

private fun algorithmToString(algorithm: Int): String {
    return when (algorithm) {
        AuthorizationList.KM_ALGORITHM_RSA -> "RSA"
        AuthorizationList.KM_ALGORITHM_EC -> "EC"
        AuthorizationList.KM_ALGORITHM_AES -> "AES"
        AuthorizationList.KM_ALGORITHM_HMAC -> "HMAC"
        else -> "Unknown ($algorithm)"
    }
}

private fun originToString(origin: Int): String {
    return when (origin) {
        0 -> "Generated"
        1 -> "Derived"
        2 -> "Imported"
        3 -> "Reserved"
        else -> "Unknown ($origin)"
    }
}

class KeyAttestationViewModel : ViewModel() {
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()

    var attestationData by mutableStateOf<AttestationData?>(null)
        private set

    var certificateChain by mutableStateOf<ByteArray?>(null)
        private set

    var error by mutableStateOf<String?>(null)
        private set

    var isLoading by mutableStateOf(false)
        private set

    // KeyBox 状态
    var keyboxStatus by mutableStateOf("检测中...")
        private set

    var keyboxContent by mutableStateOf("")
        private set

    init {
        checkKeyBoxStatus()
    }

    private fun checkKeyBoxStatus() {
        executor.execute {
            try {
                val result = execWithOutput(
                    "ls -la /data/adb/tricky_store/keybox.xml 2>/dev/null && echo EXISTS || echo NOT_FOUND"
                )
                val output = result.second.trim()
                if (output.contains("EXISTS")) {
                    // 获取文件大小
                    val sizeResult = execWithOutput(
                        "stat -c%s /data/adb/tricky_store/keybox.xml 2>/dev/null || echo 0"
                    )
                    val sizeBytes = sizeResult.second.trim().toLongOrNull() ?: 0
                    val sizeKB = if (sizeBytes > 1024) String.format("%.1f KB", sizeBytes / 1024.0) else "$sizeBytes B"
                    keyboxStatus = "已存在 ($sizeKB)"
                } else {
                    keyboxStatus = "不存在"
                }
            } catch (_: Exception) {
                keyboxStatus = "检测失败"
            }
        }
    }

    fun viewKeyBoxContent() {
        executor.execute {
            try {
                val result = execWithOutput("cat /data/adb/tricky_store/keybox.xml 2>/dev/null")
                if (result.first == 0 && result.second.isNotBlank()) {
                    keyboxContent = result.second
                } else {
                    keyboxContent = "无法读取 KeyBox 内容"
                }
            } catch (_: Exception) {
                keyboxContent = "读取失败"
            }
        }
    }

    fun replaceKeyBox(context: android.content.Context, uri: Uri) {
        executor.execute {
            try {
                // 从 URI 读取文件内容
                val inputStream = context.contentResolver.openInputStream(uri)
                val content = inputStream?.readBytes() ?: throw Exception("无法读取文件")
                inputStream.close()

                // 写入到目标路径
                val tempPath = "/data/local/tmp/keybox_temp.xml"
                val targetPath = "/data/adb/tricky_store/keybox.xml"

                // 先写入临时文件
                val writeResult = execWithOutput(
                    "cat > $tempPath << 'KEYBOX_EOF'\n${String(content)}\nKEYBOX_EOF"
                )

                if (writeResult.first != 0) {
                    keyboxStatus = "替换失败：写入临时文件失败"
                    return@execute
                }

                // 确保目标目录存在
                execWithOutput("mkdir -p /data/adb/tricky_store")

                // 移动到目标位置
                val moveResult = execWithOutput(
                    "cp $tempPath $targetPath && chmod 644 $targetPath && rm $tempPath"
                )

                if (moveResult.first == 0) {
                    keyboxStatus = "替换成功"
                    keyboxContent = ""
                    // 重新检查状态
                    checkKeyBoxStatus()
                } else {
                    keyboxStatus = "替换失败"
                }
            } catch (e: Exception) {
                keyboxStatus = "替换失败: ${e.message}"
            }
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
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                val spec = KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
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
                if (certs.isEmpty()) throw Exception("No certificate found")
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

    fun saveCertificateToUri(outputStream: OutputStream?) {
        if (outputStream == null || certificateChain == null) {
            return
        }

        executor.execute {
            try {
                outputStream.write(certificateChain)
                outputStream.close()
            } catch (e: Exception) {
                error = "Failed to save: ${e.message}"
            }
        }
    }

    override fun onCleared() {
        super.onCleared()
        executor.shutdown()
    }
}
