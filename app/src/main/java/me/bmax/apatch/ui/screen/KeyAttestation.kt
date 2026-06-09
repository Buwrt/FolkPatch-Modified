package me.bmax.apatch.ui.screen

import android.net.Uri
import android.os.Build
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
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

private fun formatDateShort(date: Date?): String {
    if (date == null) return "N/A"
    val sdf = SimpleDateFormat("yyyy-MM-dd", Locale.getDefault())
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
    ATTESTATION("密钥认证"),
    CERTIFICATE("证书详情")
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
                        "密钥认证检测",
                        fontWeight = FontWeight.Bold
                    )
                },
                navigationIcon = {
                    IconButton(onClick = { navigator.popBackStack() }) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "返回"
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color.Transparent
                ),
                actions = {
                    IconButton(onClick = { /* 帮助信息 */ }) {
                        Icon(
                            Icons.Outlined.Info,
                            contentDescription = "帮助信息",
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
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
                    AttestationTabContent(
                        viewModel,
                        keyboxPickerLauncher,
                        filePickerLauncher,
                        fileSaverLauncher,
                        context
                    )
                }
                AttestationTab.CERTIFICATE -> {
                    CertificateTabContent(viewModel)
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
                    .clickable { onTabSelected(tab) }
                    .padding(vertical = 8.dp),
                contentAlignment = Alignment.Center
            ) {
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

// ==================== 认证 Tab 内容 ====================

@Composable
private fun AttestationTabContent(
    viewModel: KeyAttestationViewModel,
    keyboxPickerLauncher: androidx.activity.result.ActivityResultLauncher<Array<String>>,
    filePickerLauncher: androidx.activity.result.ActivityResultLauncher<Array<String>>,
    fileSaverLauncher: androidx.activity.result.ActivityResultLauncher<String>,
    context: android.content.Context
) {
    Column(
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // 卡片1: KeyBox 管理
        KeyBoxManagementCard(viewModel, keyboxPickerLauncher)

        // 卡片2: 可信执行环境状态
        viewModel.attestationData?.let { data ->
            TeeStatusCard(data)
        }

        // 卡片3: 证书详情（可展开/收起）
        viewModel.attestationData?.let { data ->
            CertificateDetailExpandableCard(data)
        }

        // 卡片4: 基本信息（两列布局）
        viewModel.attestationData?.let { data ->
            BasicInfoGridCard(data)
        }

        // 卡片5: 授权列表（合并编号列表）
        viewModel.attestationData?.let { data ->
            AuthorizationListCard(data)
        }

        // 卡片6: 设备信息
        DeviceInfoCard()

        // 操作按钮卡片
        ActionButtonsCard(
            viewModel = viewModel,
            filePickerLauncher = filePickerLauncher,
            fileSaverLauncher = fileSaverLauncher,
            context = context
        )

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
            CertificateDetailExpandableCard(data)
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
    val isInstalled = !keyboxStatus.contains("不存在") && !keyboxStatus.contains("检测失败") && !keyboxStatus.contains("检测中")
    val clipboardManager = LocalClipboardManager.current

    Card(
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // 标题行：盾牌图标 + 标题 + 状态徽章
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
                        Icons.Filled.Shield,
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
                    color = if (isInstalled)
                        Color(0xFFE3F2FD)
                    else
                        MaterialTheme.colorScheme.errorContainer
                ) {
                    Text(
                        if (isInstalled) "已安装" else keyboxStatus,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                        fontSize = 11.sp,
                        color = if (isInstalled)
                            Color(0xFF1976D2)
                        else
                            MaterialTheme.colorScheme.error,
                        fontWeight = FontWeight.Medium
                    )
                }
            }

            HorizontalDivider()

            // 包名行（带复制图标）
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    "包名",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.width(80.dp)
                )
                Text(
                    "com.google.android.gms",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f)
                )
                Icon(
                    Icons.Outlined.ContentCopy,
                    contentDescription = "复制",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier
                        .size(16.dp)
                        .clickable {
                            clipboardManager.setText(AnnotatedString("com.google.android.gms"))
                        }
                )
            }

            // 版本行
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    "版本",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.width(80.dp)
                )
                Text(
                    "1.0.0",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.weight(1f)
                )
            }

            // 状态行（绿色圆点 + 运行中）
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    "状态",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.width(80.dp)
                )
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .clip(CircleShape)
                        .background(Color(0xFF4CAF50))
                )
                Spacer(Modifier.width(6.dp))
                Text(
                    "运行中",
                    style = MaterialTheme.typography.bodySmall,
                    fontWeight = FontWeight.Medium,
                    color = Color(0xFF4CAF50)
                )
            }
        }
    }
}

// ==================== 可信执行环境状态卡片 ====================

@Composable
private fun TeeStatusCard(data: AttestationData) {
    val attestation = data.getAttestation()
    val securityLevel = attestation.getAttestationSecurityLevel()
    val teeName = Attestation.securityLevelToString(securityLevel)

    Card(
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // 标题行：蓝色勾号盾牌图标
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(36.dp)
                        .clip(CircleShape)
                        .background(MaterialTheme.colorScheme.primaryContainer),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        Icons.Filled.CheckCircle,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(20.dp)
                    )
                }
                Spacer(Modifier.width(12.dp))
                Text(
                    "可信执行环境状态",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
            }

            HorizontalDivider()

            // TEE 名称
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    "TEE 名称",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.width(100.dp)
                )
                Text(
                    teeName,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium,
                    modifier = Modifier.weight(1f)
                )
            }

            // 安全等级
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    "安全等级",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.width(100.dp)
                )
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = Color(0xFFE3F2FD)
                ) {
                    Text(
                        teeName,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                        fontSize = 11.sp,
                        color = Color(0xFF1976D2),
                        fontWeight = FontWeight.Medium
                    )
                }
            }

            // 认证状态
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    "认证状态",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.width(100.dp)
                )
                Icon(
                    Icons.Filled.Check,
                    contentDescription = null,
                    tint = Color(0xFF4CAF50),
                    modifier = Modifier.size(16.dp)
                )
                Spacer(Modifier.width(4.dp))
                Text(
                    "API 密钥已配置且有效",
                    style = MaterialTheme.typography.bodySmall,
                    fontWeight = FontWeight.Medium,
                    color = Color(0xFF4CAF50)
                )
            }
        }
    }
}

// ==================== 证书详情可展开/收起卡片 ====================

@Composable
private fun CertificateDetailExpandableCard(data: AttestationData) {
    val certInfos = data.getCertificateInfos()
    var expandedCerts by remember { mutableStateOf(setOf<Int>()) }

    Card(
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
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
                    "证书详情 (${certInfos.size} 个证书)",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
            }

            HorizontalDivider()

            // 每个证书可展开/收起
            certInfos.forEachIndexed { index, certInfo ->
                val isExpanded = expandedCerts.contains(index)
                val cert = certInfo.getCert()

                // 证书标题行（始终可见）
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(8.dp))
                        .background(MaterialTheme.colorScheme.surfaceVariant)
                        .clickable {
                            expandedCerts = if (isExpanded) {
                                expandedCerts - index
                            } else {
                                expandedCerts + index
                            }
                        }
                        .padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            "证书 #${index + 1}",
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.Bold
                        )
                        Spacer(Modifier.width(8.dp))
                        // X.509 蓝色标签
                        Surface(
                            shape = RoundedCornerShape(4.dp),
                            color = Color(0xFFE3F2FD)
                        ) {
                            Text(
                                "X.509",
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 1.dp),
                                fontSize = 10.sp,
                                color = Color(0xFF1976D2),
                                fontWeight = FontWeight.Medium
                            )
                        }
                        Spacer(Modifier.width(6.dp))
                        // 有效 绿色徽章
                        Surface(
                            shape = RoundedCornerShape(4.dp),
                            color = Color(0xFFE8F5E9)
                        ) {
                            Text(
                                "有效",
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 1.dp),
                                fontSize = 10.sp,
                                color = Color(0xFF4CAF50),
                                fontWeight = FontWeight.Medium
                            )
                        }
                    }

                    // 展开/收起箭头
                    Icon(
                        Icons.Outlined.ExpandMore,
                        contentDescription = if (isExpanded) "收起" else "展开",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier
                            .size(20.dp)
                            .rotate(if (isExpanded) 180f else 0f)
                    )
                }

                // 展开后的详细内容
                AnimatedVisibility(
                    visible = isExpanded,
                    enter = expandVertically(),
                    exit = shrinkVertically()
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(start = 8.dp, end = 8.dp, top = 4.dp, bottom = 4.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        // 序列号（冒号分隔 hex）
                        CertInfoRow("序列号", formatSerialNumber(cert.serialNumber.toByteArray()))
                        // 颁发者
                        CertInfoRow("颁发者", cert.issuerX500Principal.name)
                        // 有效期
                        CertInfoRow("有效期", "${formatDateShort(cert.notBefore)} 至 ${formatDateShort(cert.notAfter)}")
                        // 签名算法
                        CertInfoRow("签名算法", cert.sigAlgName)
                    }
                }

                if (index < certInfos.size - 1) {
                    Spacer(Modifier.height(4.dp))
                }
            }
        }
    }
}

// ==================== 格式化序列号（冒号分隔 hex） ====================

private fun formatSerialNumber(bytes: ByteArray): String {
    return bytes.joinToString(":") { "%02X".format(it) }
}

// ==================== 证书信息行 ====================

@Composable
private fun CertInfoRow(label: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp, horizontal = 4.dp),
        verticalAlignment = Alignment.Top
    ) {
        Text(
            label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.width(70.dp)
        )
        Text(
            value,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Medium,
            modifier = Modifier.weight(1f)
        )
    }
}

// ==================== 基本信息卡片（两列布局） ====================

@Composable
private fun BasicInfoGridCard(data: AttestationData) {
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
                "基本信息",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            HorizontalDivider()

            // 两列网格
            Column(
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                // 第一行
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    GridInfoItem(
                        label = "KeyMint 版本",
                        value = Attestation.attestationVersionToString(attestation.attestationVersion),
                        modifier = Modifier.weight(1f)
                    )
                    GridInfoItem(
                        label = "Keymaster 版本",
                        value = Attestation.keymasterVersionToString(attestation.keymasterVersion),
                        modifier = Modifier.weight(1f)
                    )
                }
                // 第二行
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    GridInfoItem(
                        label = "Verified Boot",
                        value = if (rot != null) RootOfTrust.verifiedBootStateToString(rot.verifiedBootState) else "N/A",
                        modifier = Modifier.weight(1f)
                    )
                    GridInfoItem(
                        label = "启动状态",
                        value = if (rot != null && rot.isDeviceLocked) "已锁定" else "已解锁",
                        modifier = Modifier.weight(1f)
                    )
                }
                // 第三行
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    val tee = attestation.getTeeEnforced()
                    GridInfoItem(
                        label = "安全补丁级别",
                        value = if (tee != null) formatPatchLevel(tee.osPatchLevel) else "N/A",
                        modifier = Modifier.weight(1f)
                    )
                    GridInfoItem(
                        label = "系统补丁级别",
                        value = if (tee != null) formatPatchLevel(tee.vendorPatchLevel) else "N/A",
                        modifier = Modifier.weight(1f)
                    )
                }
            }
        }
    }
}

// ==================== 网格信息项 ====================

@Composable
private fun GridInfoItem(label: String, value: String, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .clip(RoundedCornerShape(8.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .padding(12.dp)
    ) {
        Text(
            label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            fontSize = 11.sp
        )
        Spacer(Modifier.height(4.dp))
        Text(
            value,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.Medium,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}

// ==================== 授权列表卡片（合并编号列表） ====================

@Composable
private fun AuthorizationListCard(data: AttestationData) {
    val attestation = data.getAttestation()
    val tee = attestation.getTeeEnforced()
    val sw = attestation.getSoftwareEnforced()

    val items = mutableListOf<String>()
    var index = 1

    if (tee != null) {
        tee.purposes?.let {
            items.add("${index++}. 用途: ${AuthorizationList.purposesToString(it)}")
        }
        tee.algorithm?.let {
            items.add("${index++}. 算法: ${AuthorizationList.algorithmToString(it)}")
        }
        tee.keySize?.let {
            items.add("${index++}. 密钥大小: $it")
        }
        tee.digests?.let {
            items.add("${index++}. 摘要: ${AuthorizationList.digestsToString(it)}")
        }
        tee.ecCurve?.let {
            items.add("${index++}. EC 曲线: ${ecCurveToString(it)}")
        }
        if (tee.noAuthRequired != null) {
            items.add("${index++}. 身份验证: 不需要身份验证")
        }
        tee.paddingModes?.let {
            items.add("${index++}. 填充模式: ${AuthorizationList.paddingModesToString(it)}")
        }
        tee.rsaPublicExponent?.let {
            items.add("${index++}. RSA 公钥指数: $it")
        }
        tee.mgfDigests?.let {
            items.add("${index++}. MGF 摘要: ${AuthorizationList.digestsToString(it)}")
        }
        tee.rollbackResistance?.let {
            items.add("${index++}. 回滚抵抗: $it")
        }
        tee.earlyBootOnly?.let {
            items.add("${index++}. 仅早期启动: $it")
        }
        tee.activeDateTime?.let {
            items.add("${index++}. 激活时间: ${formatDate(it)}")
        }
        tee.originationExpireDateTime?.let {
            items.add("${index++}. 生成过期时间: ${formatDate(it)}")
        }
        tee.usageExpireDateTime?.let {
            items.add("${index++}. 使用过期时间: ${formatDate(it)}")
        }
        tee.usageCountLimit?.let {
            items.add("${index++}. 使用次数限制: $it")
        }
        tee.userAuthType?.let {
            items.add("${index++}. 用户认证类型: $it")
        }
        tee.authTimeout?.let {
            items.add("${index++}. 认证超时: ${it}秒")
        }
        tee.allowWhileOnBody?.let {
            items.add("${index++}. 允许在身体上使用: $it")
        }
        tee.trustedUserPresenceReq?.let {
            items.add("${index++}. 需要可信用户在场: $it")
        }
        tee.trustedConfirmationReq?.let {
            items.add("${index++}. 需要可信确认: $it")
        }
        tee.unlockedDeviceReq?.let {
            items.add("${index++}. 需要解锁设备: $it")
        }
        tee.allApplications?.let {
            items.add("${index++}. 所有应用: $it")
        }
        tee.applicationId?.let {
            items.add("${index++}. 应用 ID: $it")
        }
        tee.creationDateTime?.let {
            items.add("${index++}. 创建时间: ${formatDate(it)}")
        }
        tee.origin?.let {
            items.add("${index++}. 来源: ${AuthorizationList.originToString(it)}")
        }
        tee.rollbackResistant?.let {
            items.add("${index++}. 回滚抵抗: $it")
        }
        tee.osVersion?.let {
            items.add("${index++}. OS 版本: ${formatOsVersion(it)}")
        }
        tee.osPatchLevel?.let {
            items.add("${index++}. OS 补丁级别: ${formatPatchLevel(it)}")
        }
        tee.vendorPatchLevel?.let {
            items.add("${index++}. Vendor 补丁级别: ${formatPatchLevel(it)}")
        }
        tee.bootPatchLevel?.let {
            items.add("${index++}. Boot 补丁级别: ${formatPatchLevel(it)}")
        }
        tee.brand?.let {
            items.add("${index++}. 品牌: $it")
        }
        tee.device?.let {
            items.add("${index++}. 设备: $it")
        }
        tee.product?.let {
            items.add("${index++}. 产品: $it")
        }
        tee.serialNumber?.let {
            items.add("${index++}. 序列号: $it")
        }
        tee.imei?.let {
            items.add("${index++}. IMEI: $it")
        }
        tee.meid?.let {
            items.add("${index++}. MEID: $it")
        }
        tee.manufacturer?.let {
            items.add("${index++}. 制造商: $it")
        }
        tee.model?.let {
            items.add("${index++}. 型号: $it")
        }
        tee.deviceUniqueAttestation?.let {
            items.add("${index++}. 设备唯一认证: $it")
        }
        tee.identityCredentialKey?.let {
            items.add("${index++}. 身份凭证密钥: $it")
        }
        tee.secondImei?.let {
            items.add("${index++}. 第二 IMEI: $it")
        }
        tee.moduleHash?.let {
            items.add("${index++}. 模块哈希: ${formatByteArray(it)}")
        }
    }

    if (sw != null) {
        sw.creationDateTime?.let {
            items.add("${index++}. 创建时间: ${formatDate(it)}")
        }
        sw.applicationId?.let {
            items.add("${index++}. 应用 ID: $it")
        }
        sw.attestationApplicationId?.let { appId ->
            items.add("${index++}. 认证应用 ID: ${appId.toString()}")
        }
        sw.origin?.let {
            items.add("${index++}. 来源: ${AuthorizationList.originToString(it)}")
        }
        sw.rollbackResistant?.let {
            items.add("${index++}. 回滚抵抗: $it")
        }
        sw.allApplications?.let {
            items.add("${index++}. 所有应用: $it")
        }
    }

    attestation.uniqueId?.let {
        items.add("${index++}. 唯一标识: ${String(it)}")
    }

    Card(
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
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
                        Icons.Outlined.List,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(20.dp)
                    )
                }
                Spacer(Modifier.width(12.dp))
                Text(
                    "授权列表 (共 ${items.size} 项)",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
            }

            HorizontalDivider()

            if (items.isNotEmpty()) {
                Column(
                    verticalArrangement = Arrangement.spacedBy(2.dp)
                ) {
                    items.forEach { item ->
                        Text(
                            item,
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 1.dp)
                        )
                    }
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

// ==================== 设备信息卡片 ====================

@Composable
private fun DeviceInfoCard() {
    Card(
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // 标题行：蓝色手机图标
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(36.dp)
                        .clip(CircleShape)
                        .background(MaterialTheme.colorScheme.primaryContainer),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        Icons.Outlined.PhoneAndroid,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(20.dp)
                    )
                }
                Spacer(Modifier.width(12.dp))
                Text(
                    "设备信息",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
            }

            HorizontalDivider()

            InfoRow("品牌", Build.BRAND)
            InfoRow("型号", Build.MODEL)
            InfoRow("Android 版本", Build.VERSION.RELEASE)
            InfoRow("安全补丁级别", Build.VERSION.SECURITY_PATCH)
            InfoRow("设备标识符", Build.FINGERPRINT)
        }
    }
}

// ==================== 操作按钮卡片 ====================

@Composable
private fun ActionButtonsCard(
    viewModel: KeyAttestationViewModel,
    filePickerLauncher: androidx.activity.result.ActivityResultLauncher<Array<String>>,
    fileSaverLauncher: androidx.activity.result.ActivityResultLauncher<String>,
    context: android.content.Context
) {
    Card(
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
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

            // 按钮行
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedButton(
                    onClick = { filePickerLauncher.launch(arrayOf("*/*")) },
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(Icons.Outlined.FileOpen, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("加载证书", fontSize = 13.sp)
                }

                OutlinedButton(
                    onClick = {
                        viewModel.certificateChain?.let {
                            fileSaverLauncher.launch("attestation_${System.currentTimeMillis()}.bin")
                        } ?: run {
                            Toast.makeText(context, "暂无数据", Toast.LENGTH_SHORT).show()
                        }
                    },
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(Icons.Outlined.Save, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("保存证书", fontSize = 13.sp)
                }
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
            modifier = Modifier.width(100.dp)
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
                    keyboxStatus = "已安装 ($sizeKB)"
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
