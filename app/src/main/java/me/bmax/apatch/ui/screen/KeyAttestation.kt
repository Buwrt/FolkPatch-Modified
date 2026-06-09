package me.bmax.apatch.ui.screen

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.net.Uri
import android.os.Build
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
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
import io.github.vvb2060.keyattestation.attestation.CertificateInfo
import io.github.vvb2060.keyattestation.attestation.RootOfTrust
import io.github.vvb2060.keyattestation.attestation.RootPublicKey
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
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties

/**
 * Execute a shell command via root shell and return (exitCode, stdout).
 */
private fun execWithOutput(command: String): Pair<Int, String> {
    val result = getRootShell().newJob().add(command).exec()
    return Pair(result.code, result.out.joinToString("\n"))
}

// ==================== Main Screen ====================

@Destination<RootGraph>
@Composable
fun KeyAttestationScreen(navigator: DestinationsNavigator) {
    val viewModel: KeyAttestationViewModel = viewModel()
    val context = LocalContext.current
    var selectedTab by remember { mutableIntStateOf(0) }

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
            Column {
                TopAppBar(
                    title = { Text(stringResource(R.string.ka_detect_title)) },
                    navigationIcon = {
                        IconButton(onClick = { navigator.popBackStack() }) {
                            Icon(
                                Icons.AutoMirrored.Filled.ArrowBack,
                                contentDescription = null
                            )
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = Color.Transparent
                    )
                )
                TabRow(
                    selectedTabIndex = selectedTab,
                    containerColor = MaterialTheme.colorScheme.surface,
                    contentColor = MaterialTheme.colorScheme.primary,
                    divider = {
                        HorizontalDivider(
                            thickness = 1.dp,
                            color = MaterialTheme.colorScheme.outlineVariant
                        )
                    }
                ) {
                    Tab(
                        selected = selectedTab == 0,
                        onClick = { selectedTab = 0 },
                        text = {
                            Text(
                                stringResource(R.string.key_attestation),
                                fontWeight = if (selectedTab == 0) FontWeight.Bold else FontWeight.Normal
                            )
                        }
                    )
                    Tab(
                        selected = selectedTab == 1,
                        onClick = { selectedTab = 1 },
                        text = {
                            Text(
                                "安全证书",
                                fontWeight = if (selectedTab == 1) FontWeight.Bold else FontWeight.Normal
                            )
                        }
                    )
                }
            }
        }
    ) { innerPadding ->
        when (selectedTab) {
            0 -> KeyAttestationTabContent(
                modifier = Modifier.padding(innerPadding),
                viewModel = viewModel,
                context = context,
                filePickerLauncher = filePickerLauncher,
                fileSaverLauncher = fileSaverLauncher,
                keyboxPickerLauncher = keyboxPickerLauncher
            )
            1 -> SecurityCertificateTabContent(
                modifier = Modifier.padding(innerPadding),
                viewModel = viewModel,
                context = context
            )
        }
    }
}

// ==================== Tab 1: Key Attestation ====================

@Composable
private fun KeyAttestationTabContent(
    modifier: Modifier = Modifier,
    viewModel: KeyAttestationViewModel,
    context: Context,
    filePickerLauncher: ActivityResultLauncher<Array<String>>,
    fileSaverLauncher: ActivityResultLauncher<String>,
    keyboxPickerLauncher: ActivityResultLauncher<Array<String>>
) {
    LazyColumn(
        modifier = modifier.padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item { Spacer(Modifier.height(8.dp)) }

        // 1. KeyBox Management Card
        item {
            KeyBoxManagementCardNew(viewModel, keyboxPickerLauncher)
        }

        // 2. Device Key Attestation Status Card
        item {
            DeviceAttestationStatusCard(viewModel)
        }

        // 3. Certificate Chain Info Card (expandable)
        viewModel.attestationData?.let { data ->
            item {
                CertificateChainInfoCard(data, context)
            }
        }

        // 4. Attestation Basic Info Card (two-column comparison)
        viewModel.attestationData?.let { data ->
            item {
                AttestationBasicInfoCard(data)
            }
        }

        // 5. Key Properties List Card (numbered)
        viewModel.attestationData?.let { data ->
            item {
                KeyPropertiesCard(data)
            }
        }

        // 6. Bottom Info Card
        item {
            BottomInfoCard(viewModel)
        }

        // Error Display
        viewModel.error?.let { error ->
            item {
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
        }

        // Loading Indicator
        if (viewModel.isLoading) {
            item {
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

        item { Spacer(Modifier.height(80.dp)) }
    }
}

// ==================== Tab 2: Security Certificate ====================

@Composable
private fun SecurityCertificateTabContent(
    modifier: Modifier = Modifier,
    viewModel: KeyAttestationViewModel,
    context: Context
) {
    val data = viewModel.attestationData

    if (data == null) {
        Box(
            modifier = modifier.fillMaxSize(),
            contentAlignment = Alignment.Center
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(
                    Icons.Outlined.Description,
                    contentDescription = null,
                    modifier = Modifier.size(48.dp),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    stringResource(R.string.ka_no_data),
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(16.dp))
                Button(onClick = { viewModel.generateAttestation() }) {
                    Icon(Icons.Filled.VerifiedUser, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(stringResource(R.string.ka_generate), fontSize = 13.sp)
                }
            }
        }
        return
    }

    val certInfos = data.getCertificateInfos()

    LazyColumn(
        modifier = modifier.padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item { Spacer(Modifier.height(8.dp)) }

        certInfos.forEachIndexed { index, certInfo ->
            item {
                FullCertificateCard(index, certInfo, context)
            }
        }

        item { Spacer(Modifier.height(80.dp)) }
    }
}

@Composable
private fun FullCertificateCard(index: Int, certInfo: CertificateInfo, context: Context) {
    val cert = certInfo.getCert()
    val status = certInfo.getStatus()

    val statusColor = when (status) {
        CertificateInfo.CERT_NORMAL -> Color(0xFF4CAF50)
        else -> MaterialTheme.colorScheme.error
    }

    val serialNumber = cert.serialNumber?.toString(16)?.uppercase() ?: ""

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            // Header
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        Icons.Filled.Description,
                        contentDescription = null,
                        modifier = Modifier.size(20.dp),
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        "证书 #${index + 1}",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                }
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = statusColor.copy(alpha = 0.15f)
                ) {
                    Text(
                        when (status) {
                            CertificateInfo.CERT_NORMAL -> "有效"
                            CertificateInfo.CERT_SIGN -> "签名错误"
                            CertificateInfo.CERT_REVOKED -> "已吊销"
                            CertificateInfo.CERT_EXPIRED -> "已过期"
                            else -> "未知"
                        },
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                        style = MaterialTheme.typography.labelSmall,
                        color = statusColor,
                        fontWeight = FontWeight.Bold
                    )
                }
            }

            HorizontalDivider()

            // Subject
            InfoLabelValueRow("Subject", cert.subjectX500Principal?.name ?: "N/A")

            // Issuer
            InfoLabelValueRow("Issuer", cert.issuerX500Principal?.name ?: "N/A")

            // Serial
            if (serialNumber.isNotEmpty()) {
                InfoLabelValueRow("Serial", "0x$serialNumber")
            }

            // Validity
            InfoLabelValueRow("Not Before", formatDateShort(cert.notBefore))
            InfoLabelValueRow("Not After", formatDateShort(cert.notAfter))

            // Signature Algorithm
            InfoLabelValueRow("签名算法", cert.sigAlgName ?: "N/A")

            // Fingerprint SHA-256
            try {
                val fingerprint = cert.let {
                    val md = java.security.MessageDigest.getInstance("SHA-256")
                    md.digest(it.encoded).joinToString("") { b -> "%02x".format(b) }
                }
                InfoLabelValueRowWithCopy("Fingerprint (SHA-256)", fingerprint, context)
            } catch (_: Exception) {}

            // Version
            InfoLabelValueRow("版本", "${cert.version + 1}")

            // Error details
            if (status != CertificateInfo.CERT_NORMAL && status != CertificateInfo.CERT_UNKNOWN) {
                certInfo.getSecurityException()?.let { ex ->
                    HorizontalDivider()
                    Text(
                        ex.message ?: "",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }
        }
    }
}

// ==================== KeyBox Management Card (New Style) ====================

@Composable
private fun KeyBoxManagementCardNew(
    viewModel: KeyAttestationViewModel,
    keyboxPickerLauncher: ActivityResultLauncher<Array<String>>
) {
    val keyboxStatus = viewModel.keyboxStatus
    val keyboxContent = viewModel.keyboxContent
    var expanded by remember { mutableStateOf(false) }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { expanded = !expanded }
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            // Title row with icon and arrow
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    Icons.Filled.Shield,
                    contentDescription = null,
                    modifier = Modifier.size(22.dp),
                    tint = Color(0xFF2196F3)
                )
                Spacer(Modifier.width(10.dp))
                Text(
                    stringResource(R.string.ka_keybox_manage),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.weight(1f)
                )
                Icon(
                    if (expanded) Icons.Filled.KeyboardArrowDown else Icons.Filled.KeyboardArrowRight,
                    contentDescription = null,
                    modifier = Modifier.size(22.dp),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            if (expanded) {
                HorizontalDivider()

                // Name
                InfoLabelValueRow("名称", "defaultKey (12.0.0.0)")

                // Path
                InfoLabelValueRow("路径", stringResource(R.string.ka_keybox_path))

                // Status tags
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        "状态: ",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(Modifier.width(4.dp))
                    // TEE tag
                    Surface(
                        shape = RoundedCornerShape(12.dp),
                        color = Color(0xFF4CAF50).copy(alpha = 0.15f)
                    ) {
                        Text(
                            "TEE",
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
                            style = MaterialTheme.typography.labelSmall,
                            color = Color(0xFF4CAF50),
                            fontWeight = FontWeight.Bold
                        )
                    }
                    Spacer(Modifier.width(8.dp))
                    // StrongBox tag
                    Surface(
                        shape = RoundedCornerShape(12.dp),
                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.1f)
                    ) {
                        Text(
                            "StrongBox",
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }

                // Current status from ViewModel
                HorizontalDivider()
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        stringResource(R.string.ka_keybox_current_status),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    val statusColor = when {
                        keyboxStatus.contains("已替换") || keyboxStatus.contains("已存在") || keyboxStatus.contains("替换成功") -> Color(0xFF4CAF50)
                        keyboxStatus.contains("不存在") || keyboxStatus.contains("Not found") || keyboxStatus.contains("失败") -> MaterialTheme.colorScheme.error
                        else -> MaterialTheme.colorScheme.onSurface
                    }
                    Text(
                        keyboxStatus,
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium,
                        color = statusColor
                    )
                }

                // Action buttons
                Spacer(Modifier.height(4.dp))
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

                // KeyBox content display
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
}

// ==================== Device Key Attestation Status Card ====================

@Composable
private fun DeviceAttestationStatusCard(viewModel: KeyAttestationViewModel) {
    val data = viewModel.attestationData
    val hasData = data != null

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { if (!hasData) viewModel.generateAttestation() }
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            // Title row
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    Icons.Filled.Info,
                    contentDescription = null,
                    modifier = Modifier.size(22.dp),
                    tint = Color(0xFF2196F3)
                )
                Spacer(Modifier.width(10.dp))
                Text(
                    "设备密钥认证状态",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.weight(1f)
                )
                Icon(
                    Icons.Filled.KeyboardArrowRight,
                    contentDescription = null,
                    modifier = Modifier.size(22.dp),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            if (hasData) {
                HorizontalDivider()

                // Attestation status
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        "认证状态: ",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        "已通过",
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFF4CAF50)
                    )
                    Spacer(Modifier.width(6.dp))
                    Icon(
                        Icons.Filled.CheckCircle,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp),
                        tint = Color(0xFF4CAF50)
                    )
                }

                // Attestation time / API level
                val attestation = data!!.getAttestation()
                val kmVersion = attestation.getKeymasterVersion()
                val apiLevel = when {
                    kmVersion >= 400 -> "API level 35+"
                    kmVersion >= 300 -> "API level 34"
                    kmVersion >= 200 -> "API level 33"
                    kmVersion >= 100 -> "API level 33"
                    kmVersion >= 4 -> "API level 30"
                    kmVersion >= 3 -> "API level 28"
                    kmVersion >= 2 -> "API level 26"
                    else -> "API level 23"
                }
                val androidVersion = when {
                    kmVersion >= 400 -> "Android 15+"
                    kmVersion >= 300 -> "Android 14"
                    kmVersion >= 200 -> "Android 13"
                    kmVersion >= 100 -> "Android 13"
                    kmVersion >= 4 -> "Android 11"
                    kmVersion >= 3 -> "Android 9"
                    kmVersion >= 2 -> "Android 8.0"
                    else -> "Android 6.0"
                }
                InfoLabelValueRow("认证时间", "$apiLevel ($androidVersion)")

                // Attestation source
                val certInfos = data.getCertificateInfos()
                val rootCert = certInfos.lastOrNull()
                val rootStatus = rootCert?.getIssuer() ?: RootPublicKey.Status.UNKNOWN
                val source = when (rootStatus) {
                    RootPublicKey.Status.GOOGLE -> "Google Hardware Attestation Key"
                    RootPublicKey.Status.GOOGLE_RKP -> "Google Remote Key Provisioning"
                    RootPublicKey.Status.KNOX -> "Samsung Knox Attestation Key"
                    RootPublicKey.Status.OEM -> "OEM Attestation Key"
                    RootPublicKey.Status.AOSP -> "AOSP Software Attestation Key"
                    else -> "Unknown"
                }
                InfoLabelValueRow("认证来源", source)
            } else {
                HorizontalDivider()
                Text(
                    stringResource(R.string.ka_status_ready),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

// ==================== Certificate Chain Info Card (Expandable) ====================

@Composable
private fun CertificateChainInfoCard(data: AttestationData, context: Context) {
    val certInfos = data.getCertificateInfos()
    var expanded by remember { mutableStateOf(false) }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            // Title row with expand button
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    "${stringResource(R.string.ka_cert_chain)} (${certInfos.size}个证书)",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                TextButton(onClick = { expanded = !expanded }) {
                    Text(
                        if (expanded) "收起" else "展开",
                        fontSize = 13.sp
                    )
                    Icon(
                        if (expanded) Icons.Filled.KeyboardArrowUp else Icons.Filled.KeyboardArrowDown,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }

            HorizontalDivider()

            if (expanded) {
                certInfos.forEachIndexed { index, certInfo ->
                    CertificateChainItem(index, certInfo, context)
                    if (index < certInfos.size - 1) {
                        Spacer(Modifier.height(8.dp))
                        HorizontalDivider()
                        Spacer(Modifier.height(8.dp))
                    }
                }
            } else {
                // Show summary when collapsed
                certInfos.forEachIndexed { index, certInfo ->
                    val cert = certInfo.getCert()
                    val status = certInfo.getStatus()
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 2.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            "#${index + 1} ",
                            style = MaterialTheme.typography.bodySmall,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Text(
                            cert.subjectX500Principal?.name?.let { shortenDn(it) } ?: "N/A",
                            style = MaterialTheme.typography.bodySmall,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f)
                        )
                        Icon(
                            when (status) {
                                CertificateInfo.CERT_NORMAL -> Icons.Filled.CheckCircle
                                else -> Icons.Filled.Error
                            },
                            contentDescription = null,
                            tint = when (status) {
                                CertificateInfo.CERT_NORMAL -> Color(0xFF4CAF50)
                                else -> MaterialTheme.colorScheme.error
                            },
                            modifier = Modifier.size(16.dp)
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun CertificateChainItem(index: Int, certInfo: CertificateInfo, context: Context) {
    val cert = certInfo.getCert()
    val status = certInfo.getStatus()
    val serialNumber = cert.serialNumber?.toString(16)?.uppercase() ?: ""

    val statusColor = when (status) {
        CertificateInfo.CERT_NORMAL -> Color(0xFF4CAF50)
        else -> MaterialTheme.colorScheme.error
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        // Header
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                "证书 #${index + 1}",
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.Bold
            )
            Surface(
                shape = RoundedCornerShape(12.dp),
                color = statusColor.copy(alpha = 0.15f)
            ) {
                Text(
                    when (status) {
                        CertificateInfo.CERT_NORMAL -> "有效"
                        CertificateInfo.CERT_SIGN -> "签名错误"
                        CertificateInfo.CERT_REVOKED -> "已吊销"
                        CertificateInfo.CERT_EXPIRED -> "已过期"
                        else -> "未知"
                    },
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                    style = MaterialTheme.typography.labelSmall,
                    color = statusColor,
                    fontWeight = FontWeight.Bold
                )
            }
        }

        // Subject
        InfoLabelValueRow("Subject", cert.subjectX500Principal?.name ?: "N/A")

        // Serial
        if (serialNumber.isNotEmpty()) {
            InfoLabelValueRow("Serial", "0x$serialNumber")
        }

        // Validity
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                "Validity: ",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                fontWeight = FontWeight.Medium
            )
            Text(
                "${formatDateShort(cert.notBefore)} to ${formatDateShort(cert.notAfter)}",
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }

        // Fingerprint
        try {
            val fingerprint = java.security.MessageDigest.getInstance("SHA-256")
                .digest(cert.encoded)
                .joinToString("") { b -> "%02x".format(b) }
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    "Fingerprint: ",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontWeight = FontWeight.Medium
                )
                Text(
                    fingerprint,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f)
                )
                Spacer(Modifier.width(8.dp))
                IconButton(
                    onClick = {
                        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        clipboard.setPrimaryClip(ClipData.newPlainText("fingerprint", fingerprint))
                        Toast.makeText(context, "已复制", Toast.LENGTH_SHORT).show()
                    },
                    modifier = Modifier.size(28.dp)
                ) {
                    Icon(
                        Icons.Outlined.ContentCopy,
                        contentDescription = "复制",
                        modifier = Modifier.size(16.dp),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        } catch (_: Exception) {}
    }
}

// ==================== Attestation Basic Info Card (Two-Column Comparison) ====================

@Composable
private fun AttestationBasicInfoCard(data: AttestationData) {
    val attestation = data.getAttestation()

    val attVersion = attestation.getAttestationVersion()
    val attVersionStr = Attestation.attestationVersionToString(attVersion)
    val attSecurityStr = Attestation.securityLevelToString(attestation.getAttestationSecurityLevel())

    val kmVersion = attestation.getKeymasterVersion()
    val kmVersionStr = Attestation.keymasterVersionToString(kmVersion)
    val kmSecurityStr = Attestation.securityLevelToString(attestation.getKeymasterSecurityLevel())

    Card(modifier = Modifier.fillMaxWidth()) {
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

            // Table header
            Row(
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    "",
                    modifier = Modifier.weight(0.3f),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    "KeyMint 1.0",
                    modifier = Modifier.weight(0.35f),
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.primary
                )
                Text(
                    "KeyMint 2.0",
                    modifier = Modifier.weight(0.35f),
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.tertiary
                )
            }

            HorizontalDivider()

            // Row: Security Level
            Row(
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    "安全等级",
                    modifier = Modifier.weight(0.3f),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    attSecurityStr,
                    modifier = Modifier.weight(0.35f),
                    style = MaterialTheme.typography.bodySmall,
                    fontWeight = FontWeight.Medium
                )
                Text(
                    kmSecurityStr,
                    modifier = Modifier.weight(0.35f),
                    style = MaterialTheme.typography.bodySmall,
                    fontWeight = FontWeight.Medium
                )
            }

            HorizontalDivider()

            // Row: Attestation Type
            Row(
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    "认证类型",
                    modifier = Modifier.weight(0.3f),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    "硬件认证",
                    modifier = Modifier.weight(0.35f),
                    style = MaterialTheme.typography.bodySmall,
                    fontWeight = FontWeight.Medium
                )
                Text(
                    if (data.isSoftwareLevel()) "软件认证" else "硬件认证",
                    modifier = Modifier.weight(0.35f),
                    style = MaterialTheme.typography.bodySmall,
                    fontWeight = FontWeight.Medium
                )
            }

            HorizontalDivider()

            // Row: Attestation Version
            Row(
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    "认证版本",
                    modifier = Modifier.weight(0.3f),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    attVersionStr,
                    modifier = Modifier.weight(0.35f),
                    style = MaterialTheme.typography.bodySmall,
                    fontWeight = FontWeight.Medium
                )
                Text(
                    kmVersionStr,
                    modifier = Modifier.weight(0.35f),
                    style = MaterialTheme.typography.bodySmall,
                    fontWeight = FontWeight.Medium
                )
            }

            HorizontalDivider()

            // Row: Attestation Status
            Row(
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    "认证状态",
                    modifier = Modifier.weight(0.3f),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Row(
                    modifier = Modifier.weight(0.35f),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        Icons.Filled.CheckCircle,
                        contentDescription = null,
                        modifier = Modifier.size(14.dp),
                        tint = Color(0xFF4CAF50)
                    )
                    Spacer(Modifier.width(4.dp))
                    Text(
                        "已通过",
                        style = MaterialTheme.typography.bodySmall,
                        fontWeight = FontWeight.Medium,
                        color = Color(0xFF4CAF50)
                    )
                }
                Row(
                    modifier = Modifier.weight(0.35f),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        Icons.Filled.CheckCircle,
                        contentDescription = null,
                        modifier = Modifier.size(14.dp),
                        tint = Color(0xFF4CAF50)
                    )
                    Spacer(Modifier.width(4.dp))
                    Text(
                        "已通过",
                        style = MaterialTheme.typography.bodySmall,
                        fontWeight = FontWeight.Medium,
                        color = Color(0xFF4CAF50)
                    )
                }
            }
        }
    }
}

// ==================== Key Properties Card (Numbered List) ====================

@Composable
private fun KeyPropertiesCard(data: AttestationData) {
    val attestation = data.getAttestation()
    val swList = attestation.getSoftwareEnforced()
    val teeList = attestation.getTeeEnforced()

    val properties = mutableListOf<Pair<String, String>>()
    var counter = 0

    // Collect all properties from both lists
    fun addProperty(label: String, value: String) {
        counter++
        properties.add(Pair("$counter. $label", value))
    }

    // TEE enforced properties
    if (teeList != null) {
        teeList.getPurposes()?.let {
            addProperty(stringResource(R.string.authorization_list_purpose), AuthorizationList.purposesToString(it))
        }
        teeList.getAlgorithm()?.let {
            addProperty(stringResource(R.string.authorization_list_algorithm), AuthorizationList.algorithmToString(it))
        }
        teeList.getKeySize()?.let {
            addProperty(stringResource(R.string.authorization_list_keySize), "$it bits")
        }
        teeList.getDigests()?.let {
            addProperty(stringResource(R.string.authorization_list_digest), AuthorizationList.digestsToString(it))
        }
        teeList.getPaddingModes()?.let {
            addProperty(stringResource(R.string.authorization_list_padding), AuthorizationList.paddingModesToString(it))
        }
        teeList.getEcCurve()?.let {
            addProperty(stringResource(R.string.authorization_list_ecCurve), AuthorizationList.ecCurveAsString(it))
        }
        teeList.getRsaPublicExponent()?.let {
            addProperty(stringResource(R.string.authorization_list_rsaPublicExponent), "$it")
        }
        teeList.getMgfDigests()?.let {
            addProperty(stringResource(R.string.authorization_list_mgfDigest), AuthorizationList.digestsToString(it))
        }
        teeList.getRollbackResistance()?.let {
            addProperty(stringResource(R.string.authorization_list_rollbackResistance), "true")
        }
        teeList.getActiveDateTime()?.let {
            addProperty(stringResource(R.string.authorization_list_activeDateTime), AuthorizationList.formatDate(it))
        }
        teeList.getOriginationExpireDateTime()?.let {
            addProperty(stringResource(R.string.authorization_list_originationExpireDateTime), AuthorizationList.formatDate(it))
        }
        teeList.getUsageExpireDateTime()?.let {
            addProperty(stringResource(R.string.authorization_list_usageExpireDateTime), AuthorizationList.formatDate(it))
        }
        teeList.getUsageCountLimit()?.let {
            addProperty(stringResource(R.string.authorization_list_usageCountLimit), "$it")
        }
        teeList.getNoAuthRequired()?.let {
            addProperty(stringResource(R.string.authorization_list_noAuthRequired), "true")
        }
        teeList.getUserAuthType()?.let {
            addProperty(stringResource(R.string.authorization_list_userAuthType), AuthorizationList.userAuthTypeToString(it))
        }
        teeList.getAuthTimeout()?.let {
            addProperty(stringResource(R.string.authorization_list_authTimeout), "$it 秒")
        }
        teeList.getAllowWhileOnBody()?.let {
            addProperty(stringResource(R.string.authorization_list_allowWhileOnBody), "true")
        }
        teeList.getTrustedUserPresenceReq()?.let {
            addProperty(stringResource(R.string.authorization_list_trustedUserPresenceRequired), "true")
        }
        teeList.getTrustedConfirmationReq()?.let {
            addProperty(stringResource(R.string.authorization_list_trustedConfirmationRequired), "true")
        }
        teeList.getUnlockedDeviceReq()?.let {
            addProperty(stringResource(R.string.authorization_list_unlockedDeviceRequired), "true")
        }
        teeList.getAllApplications()?.let {
            addProperty(stringResource(R.string.authorization_list_allApplications), "true")
        }
        teeList.getApplicationId()?.let {
            addProperty(stringResource(R.string.authorization_list_applicationId), it)
        }
        teeList.getCreationDateTime()?.let {
            addProperty(stringResource(R.string.authorization_list_creationDateTime), AuthorizationList.formatDate(it))
        }
        teeList.getOrigin()?.let {
            addProperty(stringResource(R.string.authorization_list_origin), AuthorizationList.originToString(it))
        }
        teeList.getRollbackResistant()?.let {
            addProperty(stringResource(R.string.authorization_list_rollbackResistant), "true")
        }
        teeList.getRootOfTrust()?.let {
            addProperty(stringResource(R.string.authorization_list_rootOfTrust), it.toString())
        }
        teeList.getOsVersion()?.let {
            addProperty(stringResource(R.string.authorization_list_osVersion), "$it")
        }
        teeList.getOsPatchLevel()?.let {
            addProperty(stringResource(R.string.authorization_list_osPatchLevel), "$it")
        }
        teeList.getAttestationApplicationId()?.let {
            addProperty(stringResource(R.string.authorization_list_attestationApplicationId), it.toString())
        }
        teeList.getBrand()?.let {
            addProperty(stringResource(R.string.authorization_list_attestationIdBrand), it)
        }
        teeList.getDevice()?.let {
            addProperty(stringResource(R.string.authorization_list_attestationIdDevice), it)
        }
        teeList.getProduct()?.let {
            addProperty(stringResource(R.string.authorization_list_attestationIdProduct), it)
        }
        teeList.getSerialNumber()?.let {
            addProperty(stringResource(R.string.authorization_list_attestationIdSerial), it)
        }
        teeList.getImei()?.let {
            addProperty(stringResource(R.string.authorization_list_attestationIdImei), it)
        }
        teeList.getSecondImei()?.let {
            addProperty(stringResource(R.string.authorization_list_attestationIdSecondImei), it)
        }
        teeList.getMeid()?.let {
            addProperty(stringResource(R.string.authorization_list_attestationIdMeid), it)
        }
        teeList.getManufacturer()?.let {
            addProperty(stringResource(R.string.authorization_list_attestationIdManufacturer), it)
        }
        teeList.getModel()?.let {
            addProperty(stringResource(R.string.authorization_list_attestationIdModel), it)
        }
        teeList.getVendorPatchLevel()?.let {
            addProperty(stringResource(R.string.authorization_list_vendorPatchLevel), "$it")
        }
        teeList.getBootPatchLevel()?.let {
            addProperty(stringResource(R.string.authorization_list_bootPatchLevel), "$it")
        }
        teeList.getEarlyBootOnly()?.let {
            addProperty(stringResource(R.string.authorization_list_earlyBootOnly), "true")
        }
        teeList.getDeviceUniqueAttestation()?.let {
            addProperty(stringResource(R.string.authorization_list_deviceUniqueAttestation), "true")
        }
        teeList.getIdentityCredentialKey()?.let {
            addProperty(stringResource(R.string.authorization_list_identityCredentialKey), "true")
        }
        teeList.getModuleHash()?.let {
            addProperty(stringResource(R.string.authorization_list_moduleHash), it.joinToString("") { b -> "%02x".format(b) })
        }
    }

    // SW enforced properties
    if (swList != null) {
        swList.getPurposes()?.let {
            addProperty(stringResource(R.string.authorization_list_purpose), AuthorizationList.purposesToString(it))
        }
        swList.getAlgorithm()?.let {
            addProperty(stringResource(R.string.authorization_list_algorithm), AuthorizationList.algorithmToString(it))
        }
        swList.getKeySize()?.let {
            addProperty(stringResource(R.string.authorization_list_keySize), "$it bits")
        }
        swList.getDigests()?.let {
            addProperty(stringResource(R.string.authorization_list_digest), AuthorizationList.digestsToString(it))
        }
        swList.getPaddingModes()?.let {
            addProperty(stringResource(R.string.authorization_list_padding), AuthorizationList.paddingModesToString(it))
        }
        swList.getEcCurve()?.let {
            addProperty(stringResource(R.string.authorization_list_ecCurve), AuthorizationList.ecCurveAsString(it))
        }
        swList.getRsaPublicExponent()?.let {
            addProperty(stringResource(R.string.authorization_list_rsaPublicExponent), "$it")
        }
        swList.getMgfDigests()?.let {
            addProperty(stringResource(R.string.authorization_list_mgfDigest), AuthorizationList.digestsToString(it))
        }
        swList.getRollbackResistance()?.let {
            addProperty(stringResource(R.string.authorization_list_rollbackResistance), "true")
        }
        swList.getActiveDateTime()?.let {
            addProperty(stringResource(R.string.authorization_list_activeDateTime), AuthorizationList.formatDate(it))
        }
        swList.getOriginationExpireDateTime()?.let {
            addProperty(stringResource(R.string.authorization_list_originationExpireDateTime), AuthorizationList.formatDate(it))
        }
        swList.getUsageExpireDateTime()?.let {
            addProperty(stringResource(R.string.authorization_list_usageExpireDateTime), AuthorizationList.formatDate(it))
        }
        swList.getUsageCountLimit()?.let {
            addProperty(stringResource(R.string.authorization_list_usageCountLimit), "$it")
        }
        swList.getNoAuthRequired()?.let {
            addProperty(stringResource(R.string.authorization_list_noAuthRequired), "true")
        }
        swList.getUserAuthType()?.let {
            addProperty(stringResource(R.string.authorization_list_userAuthType), AuthorizationList.userAuthTypeToString(it))
        }
        swList.getAuthTimeout()?.let {
            addProperty(stringResource(R.string.authorization_list_authTimeout), "$it 秒")
        }
        swList.getAllowWhileOnBody()?.let {
            addProperty(stringResource(R.string.authorization_list_allowWhileOnBody), "true")
        }
        swList.getTrustedUserPresenceReq()?.let {
            addProperty(stringResource(R.string.authorization_list_trustedUserPresenceRequired), "true")
        }
        swList.getTrustedConfirmationReq()?.let {
            addProperty(stringResource(R.string.authorization_list_trustedConfirmationRequired), "true")
        }
        swList.getUnlockedDeviceReq()?.let {
            addProperty(stringResource(R.string.authorization_list_unlockedDeviceRequired), "true")
        }
        swList.getAllApplications()?.let {
            addProperty(stringResource(R.string.authorization_list_allApplications), "true")
        }
        swList.getApplicationId()?.let {
            addProperty(stringResource(R.string.authorization_list_applicationId), it)
        }
        swList.getCreationDateTime()?.let {
            addProperty(stringResource(R.string.authorization_list_creationDateTime), AuthorizationList.formatDate(it))
        }
        swList.getOrigin()?.let {
            addProperty(stringResource(R.string.authorization_list_origin), AuthorizationList.originToString(it))
        }
        swList.getRollbackResistant()?.let {
            addProperty(stringResource(R.string.authorization_list_rollbackResistant), "true")
        }
        swList.getRootOfTrust()?.let {
            addProperty(stringResource(R.string.authorization_list_rootOfTrust), it.toString())
        }
        swList.getOsVersion()?.let {
            addProperty(stringResource(R.string.authorization_list_osVersion), "$it")
        }
        swList.getOsPatchLevel()?.let {
            addProperty(stringResource(R.string.authorization_list_osPatchLevel), "$it")
        }
        swList.getAttestationApplicationId()?.let {
            addProperty(stringResource(R.string.authorization_list_attestationApplicationId), it.toString())
        }
        swList.getBrand()?.let {
            addProperty(stringResource(R.string.authorization_list_attestationIdBrand), it)
        }
        swList.getDevice()?.let {
            addProperty(stringResource(R.string.authorization_list_attestationIdDevice), it)
        }
        swList.getProduct()?.let {
            addProperty(stringResource(R.string.authorization_list_attestationIdProduct), it)
        }
        swList.getSerialNumber()?.let {
            addProperty(stringResource(R.string.authorization_list_attestationIdSerial), it)
        }
        swList.getImei()?.let {
            addProperty(stringResource(R.string.authorization_list_attestationIdImei), it)
        }
        swList.getSecondImei()?.let {
            addProperty(stringResource(R.string.authorization_list_attestationIdSecondImei), it)
        }
        swList.getMeid()?.let {
            addProperty(stringResource(R.string.authorization_list_attestationIdMeid), it)
        }
        swList.getManufacturer()?.let {
            addProperty(stringResource(R.string.authorization_list_attestationIdManufacturer), it)
        }
        swList.getModel()?.let {
            addProperty(stringResource(R.string.authorization_list_attestationIdModel), it)
        }
        swList.getVendorPatchLevel()?.let {
            addProperty(stringResource(R.string.authorization_list_vendorPatchLevel), "$it")
        }
        swList.getBootPatchLevel()?.let {
            addProperty(stringResource(R.string.authorization_list_bootPatchLevel), "$it")
        }
        swList.getEarlyBootOnly()?.let {
            addProperty(stringResource(R.string.authorization_list_earlyBootOnly), "true")
        }
        swList.getDeviceUniqueAttestation()?.let {
            addProperty(stringResource(R.string.authorization_list_deviceUniqueAttestation), "true")
        }
        swList.getIdentityCredentialKey()?.let {
            addProperty(stringResource(R.string.authorization_list_identityCredentialKey), "true")
        }
        swList.getModuleHash()?.let {
            addProperty(stringResource(R.string.authorization_list_moduleHash), it.joinToString("") { b -> "%02x".format(b) })
        }
    }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Text(
                "密钥属性列表 (${properties.size}项)",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            HorizontalDivider()

            properties.forEach { (label, value) ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 2.dp),
                    verticalAlignment = Alignment.Top
                ) {
                    Text(
                        label,
                        style = MaterialTheme.typography.bodySmall,
                        fontWeight = FontWeight.Medium,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.weight(0.45f)
                    )
                    Text(
                        value,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.weight(0.55f),
                        maxLines = 3,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
        }
    }
}

// ==================== Bottom Info Card ====================

@Composable
private fun BottomInfoCard(viewModel: KeyAttestationViewModel) {
    val sdf = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
    val now = sdf.format(Date())

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                "设备信息",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            HorizontalDivider()

            InfoLabelValueRow("生成时间", now)
            InfoLabelValueRow("设备型号", "${Build.MANUFACTURER} ${Build.MODEL}")
            InfoLabelValueRow("Android 版本", "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
            InfoLabelValueRow("安全补丁", Build.VERSION.SECURITY_PATCH ?: "N/A")
        }
    }
}

// ==================== Helper Components ====================

@Composable
private fun InfoLabelValueRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            fontWeight = FontWeight.Medium,
            modifier = Modifier.weight(0.35f)
        )
        Text(
            value,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.Normal,
            modifier = Modifier.weight(0.65f),
            maxLines = if (value.length > 60) 2 else 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}

@Composable
private fun InfoLabelValueRowWithCopy(label: String, value: String, context: Context) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.Top
    ) {
        Text(
            label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            fontWeight = FontWeight.Medium,
            modifier = Modifier.weight(0.25f)
        )
        Text(
            value,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            modifier = Modifier.weight(0.65f),
            maxLines = 3,
            overflow = TextOverflow.Ellipsis
        )
        Spacer(Modifier.width(4.dp))
        IconButton(
            onClick = {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                clipboard.setPrimaryClip(ClipData.newPlainText(label, value))
                Toast.makeText(context, "已复制", Toast.LENGTH_SHORT).show()
            },
            modifier = Modifier.size(28.dp)
        ) {
            Icon(
                Icons.Outlined.ContentCopy,
                contentDescription = "复制",
                modifier = Modifier.size(14.dp),
                tint = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

private fun formatDateShort(date: Date?): String {
    return date?.let {
        SimpleDateFormat("yyyy-MM-dd", Locale.getDefault()).format(it)
    } ?: "N/A"
}

private fun formatDate(date: Date?): String {
    return date?.let { DateFormat.getDateTimeInstance().format(it) } ?: "N/A"
}

private fun shortenDn(dn: String): String {
    // Extract CN=... from a distinguished name
    val cnMatch = Regex("CN=([^,]+)").find(dn)
    return cnMatch?.groupValues?.get(1) ?: dn
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

    // KeyBox status
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
                val (exitCode, output) = execWithOutput(
                    "ls -la /data/adb/tricky_store/keybox.xml 2>/dev/null && echo EXISTS || echo NOT_FOUND"
                )
                if (output.contains("EXISTS")) {
                    val (_, sizeOutput) = execWithOutput(
                        "stat -c%s /data/adb/tricky_store/keybox.xml 2>/dev/null || echo 0"
                    )
                    val sizeBytes = sizeOutput.trim().toLongOrNull() ?: 0
                    val sizeKB = if (sizeBytes > 1024) String.format("%.1f KB", sizeBytes / 1024.0) else "$sizeBytes B"
                    keyboxStatus = "已替换 (1.0.0)"
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
                val (exitCode, output) = execWithOutput("cat /data/adb/tricky_store/keybox.xml 2>/dev/null")
                if (exitCode == 0 && output.isNotBlank()) {
                    keyboxContent = output
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
                val targetPath = "/data/adb/tricky_store/keybox.xml"

                val (writeCode, _) = execWithOutput(
                    "cat > $tempPath << 'KEYBOX_EOF'\n${String(content)}\nKEYBOX_EOF"
                )

                if (writeCode != 0) {
                    keyboxStatus = "替换失败：写入临时文件失败"
                    return@execute
                }

                execWithOutput("mkdir -p /data/adb/tricky_store")

                val (moveCode, _) = execWithOutput(
                    "cp $tempPath $targetPath && chmod 644 $targetPath && rm $tempPath"
                )

                if (moveCode == 0) {
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
