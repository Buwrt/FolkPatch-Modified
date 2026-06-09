package me.bmax.apatch.ui.screen

import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
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
import io.github.vvb2060.keyattestation.attestation.CertificateInfo
import io.github.vvb2060.keyattestation.attestation.RootOfTrust
import io.github.vvb2060.keyattestation.attestation.RootPublicKey
import io.github.vvb2060.keyattestation.repository.AttestationData
import me.bmax.apatch.util.getRootShell
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties

// ==================== 辅助函数 ====================

private fun execWithOutput(command: String): Pair<Int, String> {
    return try {
        val shell = getRootShell()
        val result = shell.newJob().add(command).exec()
        val stdout = result.out?.joinToString("\n") ?: ""
        Pair(if (result.isSuccess) 0 else 1, stdout)
    } catch (e: Exception) {
        Pair(-1, "")
    }
}

private fun formatByteArray(bytes: ByteArray?): String {
    if (bytes == null) return "N/A"
    return bytes.take(8).joinToString("") { "%02X".format(it) } +
            if (bytes.size > 8) "..." else ""
}

private fun formatDate(date: Date?): String {
    if (date == null) return "N/A"
    val sdf = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
    return sdf.format(date)
}

private fun formatOsVersion(version: Int?): String {
    if (version == null) return "N/A"
    val major = (version shr 24) and 0xFF
    val minor = (version shr 16) and 0xFF
    val patch = (version shr 8) and 0xFF
    return "$major.$minor.$patch"
}

private fun formatPatchLevel(patchLevel: Int?): String {
    if (patchLevel == null) return "N/A"
    val year = patchLevel shr 4
    val month = patchLevel and 0x0F
    return String.format("%04d-%02d", year, month)
}

private fun ecCurveToString(ecCurve: Int?): String {
    if (ecCurve == null) return "N/A"
    return AuthorizationList.ecCurveAsString(ecCurve)
}

// ==================== Tab 枚举 ====================

private enum class AttestationTab(val label: String) {
    ATTESTATION("认证"),
    CERTIFICATE("证书"),
    LOAD("加载")
}

// ==================== 主屏幕 ====================

@Destination<RootGraph>
@Composable
fun KeyAttestationScreen(navigator: DestinationsNavigator) {
    val viewModel: KeyAttestationViewModel = viewModel()
    val context = LocalContext.current
    var selectedTab by remember { mutableStateOf(AttestationTab.ATTESTATION) }

    // 文件选择器 - 加载证书
    val filePickerLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        uri?.let {
            viewModel.loadCertificateFromUri(context.contentResolver.openInputStream(it))
        }
    }

    // 文件保存器 - 保存证书
    val fileSaverLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri: Uri? ->
        uri?.let {
            viewModel.saveCertificateToUri(context.contentResolver.openOutputStream(it))
        }
    }

    // 文件选择器 - 替换 KeyBox
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
                title = {
                    Text(
                        "密钥认证",
                        fontWeight = FontWeight.Bold
                    )
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color.Transparent
                ),
                actions = {
                    IconButton(onClick = { filePickerLauncher.launch(arrayOf("*/*")) }) {
                        Icon(Icons.Outlined.FolderOpen, contentDescription = "加载")
                    }
                    IconButton(onClick = { viewModel.generateAttestation() }) {
                        Icon(Icons.Outlined.Refresh, contentDescription = "刷新")
                    }
                }
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .padding(innerPadding)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp)
        ) {
            Spacer(Modifier.height(8.dp))

            // 分段 Tab 控件
            SegmentedControl(
                selectedTab = selectedTab,
                onTabSelected = { selectedTab = it }
            )

            Spacer(Modifier.height(12.dp))

            // 根据 Tab 显示不同内容
            when (selectedTab) {
                AttestationTab.ATTESTATION -> {
                    AttestationTabContent(viewModel, keyboxPickerLauncher)
                }
                AttestationTab.CERTIFICATE -> {
                    CertificateTabContent(viewModel)
                }
                AttestationTab.LOAD -> {
                    LoadTabContent(viewModel, fileSaverLauncher, filePickerLauncher, context)
                }
            }

            Spacer(Modifier.height(80.dp))
        }
    }
}

// ==================== 分段控件 ====================

@Composable
private fun SegmentedControl(
    selectedTab: AttestationTab,
    onTabSelected: (AttestationTab) -> Unit
) {
    val tabs = AttestationTab.entries

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .padding(2.dp),
        horizontalArrangement = Arrangement.spacedBy(2.dp)
    ) {
        tabs.forEach { tab ->
            val isSelected = tab == selectedTab
            val bgColor = if (isSelected) {
                MaterialTheme.colorScheme.primary
            } else {
                Color.Transparent
            }
            val textColor = if (isSelected) {
                Color.White
            } else {
                MaterialTheme.colorScheme.onSurfaceVariant
            }

            Box(
                modifier = Modifier
                    .weight(1f)
                    .clip(RoundedCornerShape(6.dp))
                    .background(bgColor)
                    .padding(vertical = 8.dp),
                contentAlignment = Alignment.Center
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.Center
                ) {
                    if (isSelected) {
                        Icon(
                            Icons.Filled.Check,
                            contentDescription = null,
                            tint = textColor,
                            modifier = Modifier.size(14.dp)
                        )
                        Spacer(Modifier.width(4.dp))
                    }
                    Text(
                        tab.label,
                        color = textColor,
                        fontSize = 13.sp,
                        fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal
                    )
                }
            }
        }
    }
}

// ==================== 认证 Tab 内容 ====================

@Composable
private fun AttestationTabContent(
    viewModel: KeyAttestationViewModel,
    keyboxPickerLauncher: androidx.activity.result.ActivityResultLauncher<Array<String>>
) {
    Column(
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // 卡片1: KeyBox 管理
        KeyBoxManagementCard(viewModel, keyboxPickerLauncher)

        // 卡片2: 引导加载程序状态
        viewModel.attestationData?.let { data ->
            BootloaderStatusCard(data)
        }

        // 卡片3: 证书根信任状态
        viewModel.attestationData?.let { data ->
            CertificateRootTrustCard(data)
        }

        // 卡片4: 证书链
        viewModel.attestationData?.let { data ->
            CertificateChainCard(data)
        }

        // 卡片5: 基本信息
        viewModel.attestationData?.let { data ->
            BasicInfoCard(data)
        }

        // 卡片6: 授权列表 - TEE 强制执行
        viewModel.attestationData?.let { data ->
            TeeEnforcedCard(data)
        }

        // 卡片7: 授权列表 - 软件强制执行
        viewModel.attestationData?.let { data ->
            SoftwareEnforcedCard(data)
        }

        // 错误显示
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
                            Icons.Outlined.Error,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.error
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(
                            "错误",
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

        // 加载指示器
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
    }
}

// ==================== 证书 Tab 内容 ====================

@Composable
private fun CertificateTabContent(viewModel: KeyAttestationViewModel) {
    val data = viewModel.attestationData

    if (data == null) {
        Card(
            modifier = Modifier.fillMaxWidth()
        ) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(32.dp),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    "暂无数据",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    } else {
        Column(
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            data.getCertificateInfos().forEachIndexed { index, certInfo ->
                CertificateDetailCard(certInfo, index)
            }
        }
    }
}

// ==================== 加载 Tab 内容 ====================

@Composable
private fun LoadTabContent(
    viewModel: KeyAttestationViewModel,
    fileSaverLauncher: androidx.activity.result.ActivityResultLauncher<String>,
    filePickerLauncher: androidx.activity.result.ActivityResultLauncher<Array<String>>,
    context: android.content.Context
) {
    Column(
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // 状态卡片
        Card(
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                // 生成认证按钮
                Button(
                    onClick = { viewModel.generateAttestation() },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.primary
                    )
                ) {
                    Icon(Icons.Outlined.VerifiedUser, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("生成认证")
                }

                // 保存证书按钮
                OutlinedButton(
                    onClick = {
                        viewModel.certificateChain?.let {
                            fileSaverLauncher.launch("attestation_${System.currentTimeMillis()}.bin")
                        } ?: run {
                            Toast.makeText(context, "暂无数据", Toast.LENGTH_SHORT).show()
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Outlined.Save, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("保存证书")
                }

                // 加载证书按钮
                OutlinedButton(
                    onClick = { filePickerLauncher.launch(arrayOf("*/*")) },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Outlined.FileOpen, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("加载证书")
                }
            }
        }

        // 认证状态
        Card(
            modifier = Modifier.fillMaxWidth()
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    when {
                        viewModel.attestationData != null && viewModel.error == null -> Icons.Filled.Check
                        viewModel.error != null -> Icons.Outlined.Error
                        else -> Icons.Outlined.Info
                    },
                    contentDescription = null,
                    tint = when {
                        viewModel.attestationData != null && viewModel.error == null -> Color(0xFF4CAF50)
                        viewModel.error != null -> MaterialTheme.colorScheme.error
                        else -> MaterialTheme.colorScheme.onSurfaceVariant
                    },
                    modifier = Modifier.size(24.dp)
                )
                Spacer(Modifier.width(12.dp))
                Text(
                    when {
                        viewModel.attestationData != null && viewModel.error == null -> "认证完成"
                        viewModel.error != null -> "认证失败"
                        else -> "准备生成认证"
                    },
                    style = MaterialTheme.typography.bodyMedium
                )
            }
        }
    }
}

// ==================== KeyBox 管理卡片 ====================

@Composable
private fun KeyBoxManagementCard(
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
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // 标题行：图标 + 标题 + 状态徽章
            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(36.dp)
                        .clip(CircleShape)
                        .background(MaterialTheme.colorScheme.primaryContainer),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        Icons.Filled.Key,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(20.dp)
                    )
                }
                Spacer(Modifier.width(12.dp))
                Text(
                    "KeyBox 管理",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                Spacer(Modifier.width(8.dp))
                // 状态徽章
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = if (keyboxStatus.contains("不存在") || keyboxStatus.contains("检测失败"))
                        MaterialTheme.colorScheme.errorContainer
                    else
                        Color(0xFFE8F5E9)
                ) {
                    Text(
                        keyboxStatus,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                        fontSize = 11.sp,
                        color = if (keyboxStatus.contains("不存在") || keyboxStatus.contains("检测失败"))
                            MaterialTheme.colorScheme.error
                        else
                            Color(0xFF4CAF50),
                        fontWeight = FontWeight.Medium
                    )
                }
            }

            HorizontalDivider()

            // 路径行
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    Icons.Outlined.Folder,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(16.dp)
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    "路径",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    "/data/data/com.ricky.store/keybox.xml",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f)
                )
            }

            // 按钮行
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
                    Text("替换 KeyBox", fontSize = 13.sp)
                }

                OutlinedButton(
                    onClick = { viewModel.viewKeyBoxContent() },
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(Icons.Outlined.Visibility, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("查看 KeyBox", fontSize = 13.sp)
                }
            }

            // KeyBox 内容展示
            if (keyboxContent.isNotEmpty()) {
                HorizontalDivider()
                Text(
                    "KeyBox 内容",
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

// ==================== 引导加载程序状态卡片 ====================

@Composable
private fun BootloaderStatusCard(data: AttestationData) {
    val attestation = data.getAttestation()
    val rot = attestation.getRootOfTrust()

    Card(
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // 标题行
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(36.dp)
                        .clip(CircleShape)
                        .background(MaterialTheme.colorScheme.primaryContainer),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        Icons.Outlined.Lock,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(20.dp)
                    )
                }
                Spacer(Modifier.width(12.dp))
                Text(
                    "引导加载程序状态",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
            }

            HorizontalDivider()

            // 当前状态
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    "当前状态",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.weight(1f))
                Text(
                    if (rot != null && rot.isDeviceLocked) "引导加载程序已锁定" else "引导加载程序已解锁",
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium,
                    color = if (rot != null && rot.isDeviceLocked) Color(0xFF4CAF50) else MaterialTheme.colorScheme.error
                )
            }
        }
    }
}

// ==================== 证书根信任状态卡片 ====================

@Composable
private fun CertificateRootTrustCard(data: AttestationData) {
    val certInfos = data.getCertificateInfos()
    val rootIssuer = certInfos.lastOrNull()?.getIssuer()

    val isTrusted = rootIssuer == RootPublicKey.Status.GOOGLE
            || rootIssuer == RootPublicKey.Status.GOOGLE_RKP
            || rootIssuer == RootPublicKey.Status.AOSP
            || rootIssuer == RootPublicKey.Status.KNOX

    Card(
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // 标题行
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(36.dp)
                        .clip(CircleShape)
                        .background(MaterialTheme.colorScheme.primaryContainer),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        Icons.Outlined.VerifiedUser,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(20.dp)
                    )
                }
                Spacer(Modifier.width(12.dp))
                Text(
                    "证书根信任状态",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
            }

            HorizontalDivider()

            // 根证书状态
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    "根证书",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.weight(1f))
                Text(
                    if (isTrusted) "根证书是已知可信的证书颁发机构"
                    else "根证书不是已知可信的证书颁发机构",
                    style = MaterialTheme.typography.bodySmall,
                    color = if (isTrusted) Color(0xFF4CAF50) else MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

// ==================== 证书链卡片 ====================

@Composable
private fun CertificateChainCard(data: AttestationData) {
    val certInfos = data.getCertificateInfos()

    Card(
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // 标题行
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(36.dp)
                        .clip(CircleShape)
                        .background(MaterialTheme.colorScheme.primaryContainer),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        Icons.Outlined.Description,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(20.dp)
                    )
                }
                Spacer(Modifier.width(12.dp))
                Text(
                    "证书链 (${certInfos.size} 证书)",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
            }

            HorizontalDivider()

            // 证书子卡片
            certInfos.forEachIndexed { index, certInfo ->
                val cert = certInfo.getCert()
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(8.dp))
                        .background(MaterialTheme.colorScheme.surfaceVariant)
                        .padding(12.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    Text(
                        "证书 #${index + 1}",
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = FontWeight.Bold
                    )
                    InfoRow("颁发于", cert.issuerX500Principal.name)
                    InfoRow("不早于", formatDate(cert.notBefore))
                    InfoRow("不晚于", formatDate(cert.notAfter))
                }
                if (index < certInfos.size - 1) {
                    Spacer(Modifier.height(4.dp))
                }
            }
        }
    }
}

// ==================== 证书详情卡片（证书 Tab） ====================

@Composable
private fun CertificateDetailCard(certInfo: CertificateInfo, index: Int) {
    val cert = certInfo.getCert()

    Card(
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                "证书 #${index + 1}",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            HorizontalDivider()
            InfoRow("颁发于", cert.issuerX500Principal.name)
            InfoRow("主体", cert.subjectX500Principal.name)
            InfoRow("不早于", formatDate(cert.notBefore))
            InfoRow("不晚于", formatDate(cert.notAfter))
            InfoRow("序列号", cert.serialNumber.toString(16).uppercase())
        }
    }
}

// ==================== 基本信息卡片 ====================

@Composable
private fun BasicInfoCard(data: AttestationData) {
    val attestation = data.getAttestation()

    Card(
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                "基本信息",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            HorizontalDivider()

            InfoRow("认证版本", Attestation.attestationVersionToString(attestation.attestationVersion))
            InfoRow("安全等级", Attestation.securityLevelToString(attestation.getAttestationSecurityLevel()))
            InfoRow("Keymaster 版本", Attestation.keymasterVersionToString(attestation.keymasterVersion))
            InfoRow("Keymaster 安全等级", Attestation.securityLevelToString(attestation.keymasterSecurityLevel))
        }
    }
}

// ==================== TEE 强制执行卡片 ====================

@Composable
private fun TeeEnforcedCard(data: AttestationData) {
    val attestation = data.getAttestation()
    val tee = attestation.getTeeEnforced()

    Card(
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                "授权列表 — TEE 强制执行",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            HorizontalDivider()

            if (tee != null) {
                // 用途
                tee.purposes?.let {
                    InfoRow("用途", AuthorizationList.purposesToString(it))
                }
                // 算法
                tee.algorithm?.let {
                    InfoRow("算法", AuthorizationList.algorithmToString(it))
                }
                // 密钥大小
                tee.keySize?.let {
                    InfoRow("密钥大小", "$it bits")
                }
                // 摘要
                tee.digests?.let {
                    InfoRow("摘要", AuthorizationList.digestsToString(it))
                }
                // 椭圆曲线
                tee.ecCurve?.let {
                    InfoRow("椭圆曲线", ecCurveToString(it))
                }
                // 不需要身份验证
                if (tee.noAuthRequired != null) {
                    InfoRow("身份验证", "不需要身份验证")
                }

                Spacer(Modifier.height(4.dp))
                Text(
                    "信任根",
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.primary
                )

                // Root of Trust
                val rot = tee.rootOfTrust
                if (rot != null) {
                    InfoRow("verifiedBootKey", formatByteArray(rot.verifiedBootKey))
                    InfoRow("deviceLocked", if (rot.isDeviceLocked) "true" else "false")
                    InfoRow("verifiedBootState", RootOfTrust.verifiedBootStateToString(rot.verifiedBootState))
                    rot.verifiedBootHash?.let {
                        InfoRow("verifiedBootHash", formatByteArray(it))
                    }
                }

                Spacer(Modifier.height(4.dp))
                Text(
                    "系统版本",
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.primary
                )

                // 系统版本
                tee.osVersion?.let {
                    InfoRow("osVersion", formatOsVersion(it))
                }
                tee.osPatchLevel?.let {
                    InfoRow("osPatchLevel", formatPatchLevel(it))
                }
                tee.vendorPatchLevel?.let {
                    InfoRow("Vendor补丁", formatPatchLevel(it))
                }
                tee.bootPatchLevel?.let {
                    InfoRow("Boot补丁", formatPatchLevel(it))
                }
            } else {
                Text(
                    "暂无数据",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

// ==================== 软件强制执行卡片 ====================

@Composable
private fun SoftwareEnforcedCard(data: AttestationData) {
    val attestation = data.getAttestation()
    val sw = attestation.getSoftwareEnforced()

    Card(
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                "授权列表 — 软件强制执行",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            HorizontalDivider()

            if (sw != null) {
                // 创建时间
                sw.creationDateTime?.let {
                    InfoRow("创建时间", formatDate(it))
                }
                // 应用 ID
                sw.applicationId?.let {
                    InfoRow("应用 ID", it)
                }
                // 证书序列号 (从 attestationApplicationId)
                sw.attestationApplicationId?.let { appId ->
                    InfoRow("证书序列号", appId.toString())
                }
                // 唯一标识
                attestation.uniqueId?.let {
                    InfoRow("唯一标识", String(it))
                }
            } else {
                Text(
                    "暂无数据",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

// ==================== 通用信息行 ====================

@Composable
private fun InfoRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
        verticalAlignment = Alignment.Top
    ) {
        Text(
            label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.width(120.dp)
        )
        Text(
            value,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.Medium,
            modifier = Modifier.weight(1f)
        )
    }
}

// ==================== ViewModel ====================

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
                    "ls -la /data/data/com.ricky.store/keybox.xml 2>/dev/null && echo EXISTS || echo NOT_FOUND"
                )
                val output = result.second.trim()
                if (output.contains("EXISTS")) {
                    val sizeResult = execWithOutput(
                        "stat -c%s /data/data/com.ricky.store/keybox.xml 2>/dev/null || echo 0"
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
                val result = execWithOutput("cat /data/data/com.ricky.store/keybox.xml 2>/dev/null")
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
                val inputStream = context.contentResolver.openInputStream(uri)
                val content = inputStream?.readBytes() ?: throw Exception("无法读取文件")
                inputStream.close()

                val tempPath = "/data/local/tmp/keybox_temp.xml"
                val targetPath = "/data/data/com.ricky.store/keybox.xml"

                val writeResult = execWithOutput(
                    "cat > $tempPath << 'KEYBOX_EOF'\n${String(content)}\nKEYBOX_EOF"
                )

                if (writeResult.first != 0) {
                    keyboxStatus = "替换失败：写入临时文件失败"
                    return@execute
                }

                execWithOutput("mkdir -p /data/data/com.ricky.store")

                val moveResult = execWithOutput(
                    "cp $tempPath $targetPath && chmod 644 $targetPath && rm $tempPath"
                )

                if (moveResult.first == 0) {
                    keyboxStatus = "替换成功"
                    keyboxContent = ""
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
                val certInfos = mutableListOf<CertificateInfo>()
                CertificateInfo.parse(certs, certInfos)
                val result = AttestationData.parseCertificateChain(certs)
                attestationData = result
                certificateChain = try {
                    val bos = java.io.ByteArrayOutputStream()
                    val dos = java.io.DataOutputStream(bos)
                    dos.writeInt(certs.size)
                    for (cert in certs) {
                        dos.writeInt(cert.encoded.size)
                        dos.write(cert.encoded)
                    }
                    dos.flush()
                    bos.toByteArray()
                } catch (_: Exception) { null }
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
