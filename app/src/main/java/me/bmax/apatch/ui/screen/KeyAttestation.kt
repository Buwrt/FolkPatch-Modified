package me.bmax.apatch.ui.screen

import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
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
import java.text.DateFormat
import java.util.Date
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
                )
            )
        }
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .padding(innerPadding)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item { Spacer(Modifier.height(4.dp)) }

            // 1. Title bar with action buttons
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Button(
                        onClick = { viewModel.generateAttestation() },
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(Icons.Filled.VerifiedUser, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        Text(stringResource(R.string.ka_generate), fontSize = 13.sp)
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
                        Spacer(Modifier.width(6.dp))
                        Text(stringResource(R.string.ka_save), fontSize = 13.sp)
                    }

                    OutlinedButton(
                        onClick = { filePickerLauncher.launch(arrayOf("*/*")) },
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(Icons.Outlined.FolderOpen, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        Text(stringResource(R.string.ka_load), fontSize = 13.sp)
                    }
                }
            }

            // 2. KeyBox Management Card
            item {
                KeyBoxManagementCard(viewModel, keyboxPickerLauncher)
            }

            // 3. Bootloader Status Card
            viewModel.attestationData?.let { data ->
                item {
                    BootloaderStatusCard(data)
                }
            }

            // 4. Certificate Root Trust Status Card
            viewModel.attestationData?.let { data ->
                item {
                    CertificateRootTrustCard(data)
                }
            }

            // 5. Certificate Chain Card
            viewModel.attestationData?.let { data ->
                item {
                    CertificateChainCard(data)
                }
            }

            // 6. Attestation Basic Info Card
            viewModel.attestationData?.let { data ->
                item {
                    AttestationInfoCard(data)
                }
            }

            // 7. Authorization List Card
            viewModel.attestationData?.let { data ->
                item {
                    AuthorizationListCard(data)
                }
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
}

// ==================== KeyBox Management Card ====================
@Composable
fun KeyBoxManagementCard(
    viewModel: KeyAttestationViewModel,
    keyboxPickerLauncher: ActivityResultLauncher<Array<String>>
) {
    val keyboxStatus = viewModel.keyboxStatus
    val keyboxContent = viewModel.keyboxContent

    Card(modifier = Modifier.fillMaxWidth()) {
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
                    keyboxStatus.contains("已替换") || keyboxStatus.contains("已存在") -> MaterialTheme.colorScheme.primary
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

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
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
                    modifier = Modifier.padding(start = 8.dp)
                )
            }

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

// ==================== Bootloader Status Card ====================
@Composable
fun BootloaderStatusCard(data: AttestationData) {
    val attestation = data.getAttestation()
    val rot = attestation.getRootOfTrust()

    val isSoftwareLevel = data.isSoftwareLevel()

    val (iconTint, titleText, descText) = when {
        rot == null -> Triple(
            MaterialTheme.colorScheme.onSurfaceVariant,
            stringResource(R.string.bootloader_unknown),
            ""
        )
        !rot.isDeviceLocked && rot.verifiedBootState == RootOfTrust.KM_VERIFIED_BOOT_SELF_SIGNED -> Triple(
            MaterialTheme.colorScheme.primary,
            stringResource(R.string.bootloader_user),
            ""
        )
        rot.isDeviceLocked -> Triple(
            MaterialTheme.colorScheme.primary,
            stringResource(R.string.bootloader_locked),
            stringResource(R.string.ka_bootloader_locked)
        )
        else -> Triple(
            MaterialTheme.colorScheme.tertiary,
            stringResource(R.string.bootloader_unlocked),
            stringResource(R.string.ka_bootloader_unlocked)
        )
    }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    Icons.Filled.Lock,
                    contentDescription = null,
                    modifier = Modifier.size(28.dp),
                    tint = iconTint
                )
                Spacer(Modifier.width(12.dp))
                Column {
                    Text(
                        stringResource(R.string.ka_bootloader_status),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        titleText,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
            }

            if (isSoftwareLevel) {
                HorizontalDivider()
                Text(
                    stringResource(R.string.bootloader_summary_sw_level),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

// ==================== Certificate Root Trust Card ====================
@Composable
fun CertificateRootTrustCard(data: AttestationData) {
    val certInfos = data.getCertificateInfos()
    val rootCert = certInfos.lastOrNull()
    val rootStatus = rootCert?.getIssuer() ?: RootPublicKey.Status.UNKNOWN

    val hasChainError = certInfos.any { it.getStatus() != CertificateInfo.CERT_NORMAL }

    val (iconTint, titleText, summaryText) = when {
        hasChainError -> Triple(
            MaterialTheme.colorScheme.error,
            stringResource(R.string.cert_chain_not_trusted),
            stringResource(R.string.cert_chain_not_trusted_summary)
        )
        rootStatus == RootPublicKey.Status.GOOGLE -> Triple(
            MaterialTheme.colorScheme.primary,
            stringResource(R.string.google_root_cert),
            stringResource(R.string.google_root_cert_summary)
        )
        rootStatus == RootPublicKey.Status.GOOGLE_RKP -> Triple(
            MaterialTheme.colorScheme.primary,
            stringResource(R.string.google_root_cert_rkp),
            stringResource(R.string.google_root_cert_rkp_summary)
        )
        rootStatus == RootPublicKey.Status.KNOX -> Triple(
            MaterialTheme.colorScheme.primary,
            stringResource(R.string.knox_root_cert),
            stringResource(R.string.knox_root_cert_summary)
        )
        rootStatus == RootPublicKey.Status.OEM -> Triple(
            MaterialTheme.colorScheme.primary,
            stringResource(R.string.oem_root_cert),
            stringResource(R.string.oem_root_cert_summary)
        )
        rootStatus == RootPublicKey.Status.AOSP -> Triple(
            MaterialTheme.colorScheme.tertiary,
            stringResource(R.string.aosp_root_cert),
            stringResource(R.string.aosp_root_cert_summary)
        )
        rootStatus == RootPublicKey.Status.UNKNOWN -> Triple(
            MaterialTheme.colorScheme.onSurfaceVariant,
            stringResource(R.string.unknown_root_cert),
            stringResource(R.string.unknown_root_cert_summary)
        )
        else -> Triple(
            MaterialTheme.colorScheme.onSurfaceVariant,
            stringResource(R.string.unknown_root_cert),
            stringResource(R.string.unknown_root_cert_summary)
        )
    }

    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                Icons.Filled.Security,
                contentDescription = null,
                modifier = Modifier.size(28.dp),
                tint = iconTint
            )
            Spacer(Modifier.width(12.dp))
            Column {
                Text(
                    stringResource(R.string.ka_cert_root_trust),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    titleText,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium,
                    color = iconTint
                )
                if (summaryText.isNotEmpty()) {
                    Text(
                        summaryText,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}

// ==================== Certificate Chain Card ====================
@Composable
fun CertificateChainCard(data: AttestationData) {
    val certInfos = data.getCertificateInfos()

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                stringResource(R.string.cert_chain) + " (${certInfos.size} ${stringResource(R.string.ka_certificate)})",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            HorizontalDivider()

            certInfos.forEachIndexed { index, certInfo ->
                CertificateItem(index, certInfo)
                if (index < certInfos.size - 1) {
                    Spacer(Modifier.height(4.dp))
                }
            }
        }
    }
}

@Composable
fun CertificateItem(index: Int, certInfo: CertificateInfo) {
    var expanded by remember { mutableStateOf(false) }
    val cert = certInfo.getCert()
    val status = certInfo.getStatus()
    val issuer = certInfo.getIssuer()

    val statusIcon = when (status) {
        CertificateInfo.CERT_NORMAL -> Icons.Filled.CheckCircle
        CertificateInfo.CERT_SIGN -> Icons.Filled.Error
        CertificateInfo.CERT_REVOKED -> Icons.Filled.Error
        CertificateInfo.CERT_EXPIRED -> Icons.Filled.Error
        else -> Icons.Outlined.Help
    }

    val statusTint = when (status) {
        CertificateInfo.CERT_NORMAL -> MaterialTheme.colorScheme.primary
        else -> MaterialTheme.colorScheme.error
    }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .clickable { expanded = !expanded }
            .padding(12.dp)
            .animateContentSize()
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                "#${index + 1} ${stringResource(R.string.ka_certificate)}",
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.Bold
            )
            Icon(
                statusIcon,
                contentDescription = null,
                tint = statusTint,
                modifier = Modifier.size(20.dp)
            )
        }

        Spacer(Modifier.height(4.dp))

        // Always show: serial, issuer, validity
        val serialNumber = cert.serialNumber?.toString(16)?.uppercase() ?: ""
        InfoRow(label = stringResource(R.string.ka_issuer), value = cert.issuerX500Principal?.name ?: "")
        InfoRow(label = stringResource(R.string.cert_not_before), value = formatDate(cert.notBefore))
        InfoRow(label = stringResource(R.string.cert_not_after), value = formatDate(cert.notAfter))

        if (expanded) {
            Spacer(Modifier.height(4.dp))
            InfoRow(label = stringResource(R.string.ka_subject), value = cert.subjectX500Principal?.name ?: "")
            if (serialNumber.isNotEmpty()) {
                InfoRow(label = stringResource(R.string.ka_serial), value = serialNumber)
            }

            if (status != CertificateInfo.CERT_NORMAL && status != CertificateInfo.CERT_UNKNOWN) {
                val errorText = when (status) {
                    CertificateInfo.CERT_SIGN -> stringResource(R.string.cert_error_sign)
                    CertificateInfo.CERT_REVOKED -> stringResource(R.string.cert_error_revoked)
                    CertificateInfo.CERT_EXPIRED -> stringResource(R.string.cert_error_expired)
                    else -> ""
                }
                certInfo.getSecurityException()?.let { ex ->
                    Text(
                        "$errorText ${ex.message}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }
        }
    }
}

@Composable
fun InfoRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(0.4f)
        )
        Text(
            value,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.Medium,
            modifier = Modifier.weight(0.6f),
            maxLines = if (value.length > 60) 2 else 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}

// ==================== Attestation Info Card ====================
@Composable
fun AttestationInfoCard(data: AttestationData) {
    val attestation = data.getAttestation()

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(
                stringResource(R.string.ka_basic_info),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            HorizontalDivider()

            // Attestation Version
            AttestationInfoItem(
                title = stringResource(R.string.ka_attest_version),
                summary = stringResource(
                    R.string.attestation_summary_format,
                    Attestation.attestationVersionToString(attestation.getAttestationVersion()),
                    Attestation.securityLevelToString(attestation.getAttestationSecurityLevel())
                )
            )

            HorizontalDivider()

            // Keymaster Version
            AttestationInfoItem(
                title = stringResource(R.string.ka_km_version),
                summary = stringResource(
                    R.string.attestation_summary_format,
                    Attestation.keymasterVersionToString(attestation.getKeymasterVersion()),
                    Attestation.securityLevelToString(attestation.getKeymasterSecurityLevel())
                )
            )

            HorizontalDivider()

            // Attestation Challenge
            val challenge = attestation.getAttestationChallenge()
            AttestationInfoItem(
                title = stringResource(R.string.attestation_challenge),
                summary = if (challenge != null && challenge.isNotEmpty()) {
                    val stringChallenge = String(challenge)
                    if (challenge.contentEquals(stringChallenge.toByteArray())) {
                        stringChallenge
                    } else {
                        android.util.Base64.encodeToString(challenge, android.util.Base64.DEFAULT)
                    }
                } else {
                    stringResource(R.string.empty)
                }
            )
        }
    }
}

@Composable
fun AttestationInfoItem(title: String, summary: String) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(
            title,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.height(2.dp))
        Text(
            summary,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.SemiBold
        )
    }
}

// ==================== Authorization List Card ====================
@Composable
fun AuthorizationListCard(data: AttestationData) {
    val attestation = data.getAttestation()
    val swList = attestation.getSoftwareEnforced()
    val teeList = attestation.getTeeEnforced()

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                stringResource(R.string.authorization_list),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            HorizontalDivider()

            // Show TEE and SW side by side or stacked
            if (teeList != null && hasAuthorizationItems(teeList)) {
                Text(
                    stringResource(R.string.tee_enforced),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.primary
                )
                AuthorizationListItems(teeList)
            }

            if (swList != null && hasAuthorizationItems(swList)) {
                if (teeList != null && hasAuthorizationItems(teeList)) {
                    Spacer(Modifier.height(8.dp))
                    HorizontalDivider()
                    Spacer(Modifier.height(8.dp))
                }
                Text(
                    stringResource(R.string.sw_enforced),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.tertiary
                )
                AuthorizationListItems(swList)
            }
        }
    }
}

fun hasAuthorizationItems(list: AuthorizationList): Boolean {
    return list.getPurposes() != null ||
            list.getAlgorithm() != null ||
            list.getKeySize() != null ||
            list.getDigests() != null ||
            list.getPaddingModes() != null ||
            list.getEcCurve() != null ||
            list.getRsaPublicExponent() != null ||
            list.getMgfDigests() != null ||
            list.getRollbackResistance() != null ||
            list.getEarlyBootOnly() != null ||
            list.getActiveDateTime() != null ||
            list.getOriginationExpireDateTime() != null ||
            list.getUsageExpireDateTime() != null ||
            list.getUsageCountLimit() != null ||
            list.getNoAuthRequired() != null ||
            list.getUserAuthType() != null ||
            list.getAuthTimeout() != null ||
            list.getAllowWhileOnBody() != null ||
            list.getTrustedUserPresenceReq() != null ||
            list.getTrustedConfirmationReq() != null ||
            list.getUnlockedDeviceReq() != null ||
            list.getAllApplications() != null ||
            list.getApplicationId() != null ||
            list.getCreationDateTime() != null ||
            list.getOrigin() != null ||
            list.getRollbackResistant() != null ||
            list.getRootOfTrust() != null ||
            list.getOsVersion() != null ||
            list.getOsPatchLevel() != null ||
            list.getAttestationApplicationId() != null ||
            list.getBrand() != null ||
            list.getDevice() != null ||
            list.getProduct() != null ||
            list.getSerialNumber() != null ||
            list.getImei() != null ||
            list.getSecondImei() != null ||
            list.getMeid() != null ||
            list.getManufacturer() != null ||
            list.getModel() != null ||
            list.getVendorPatchLevel() != null ||
            list.getBootPatchLevel() != null ||
            list.getDeviceUniqueAttestation() != null ||
            list.getIdentityCredentialKey() != null ||
            list.getModuleHash() != null
}

@Composable
fun AuthorizationListItems(list: AuthorizationList) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        list.getPurposes()?.let {
            AuthItem(stringResource(R.string.authorization_list_purpose), AuthorizationList.purposesToString(it))
        }
        list.getAlgorithm()?.let {
            AuthItem(stringResource(R.string.authorization_list_algorithm), AuthorizationList.algorithmToString(it))
        }
        list.getKeySize()?.let {
            AuthItem(stringResource(R.string.authorization_list_keySize), "$it")
        }
        list.getDigests()?.let {
            AuthItem(stringResource(R.string.authorization_list_digest), AuthorizationList.digestsToString(it))
        }
        list.getPaddingModes()?.let {
            AuthItem(stringResource(R.string.authorization_list_padding), AuthorizationList.paddingModesToString(it))
        }
        list.getEcCurve()?.let {
            AuthItem(stringResource(R.string.authorization_list_ecCurve), AuthorizationList.ecCurveAsString(it))
        }
        list.getRsaPublicExponent()?.let {
            AuthItem(stringResource(R.string.authorization_list_rsaPublicExponent), "$it")
        }
        list.getMgfDigests()?.let {
            AuthItem(stringResource(R.string.authorization_list_mgfDigest), AuthorizationList.digestsToString(it))
        }
        list.getRollbackResistance()?.let {
            AuthItem(stringResource(R.string.authorization_list_rollbackResistance), "")
        }
        list.getActiveDateTime()?.let {
            AuthItem(stringResource(R.string.authorization_list_activeDateTime), AuthorizationList.formatDate(it))
        }
        list.getOriginationExpireDateTime()?.let {
            AuthItem(stringResource(R.string.authorization_list_originationExpireDateTime), AuthorizationList.formatDate(it))
        }
        list.getUsageExpireDateTime()?.let {
            AuthItem(stringResource(R.string.authorization_list_usageExpireDateTime), AuthorizationList.formatDate(it))
        }
        list.getUsageCountLimit()?.let {
            AuthItem(stringResource(R.string.authorization_list_usageCountLimit), "$it")
        }
        list.getNoAuthRequired()?.let {
            AuthItem(stringResource(R.string.authorization_list_noAuthRequired), "")
        }
        list.getUserAuthType()?.let {
            AuthItem(stringResource(R.string.authorization_list_userAuthType), AuthorizationList.userAuthTypeToString(it))
        }
        list.getAuthTimeout()?.let {
            AuthItem(stringResource(R.string.authorization_list_authTimeout), "$it")
        }
        list.getAllowWhileOnBody()?.let {
            AuthItem(stringResource(R.string.authorization_list_allowWhileOnBody), "")
        }
        list.getTrustedUserPresenceReq()?.let {
            AuthItem(stringResource(R.string.authorization_list_trustedUserPresenceRequired), "")
        }
        list.getTrustedConfirmationReq()?.let {
            AuthItem(stringResource(R.string.authorization_list_trustedConfirmationRequired), "")
        }
        list.getUnlockedDeviceReq()?.let {
            AuthItem(stringResource(R.string.authorization_list_unlockedDeviceRequired), "")
        }
        list.getAllApplications()?.let {
            AuthItem(stringResource(R.string.authorization_list_allApplications), "")
        }
        list.getApplicationId()?.let {
            AuthItem(stringResource(R.string.authorization_list_applicationId), it)
        }
        list.getCreationDateTime()?.let {
            AuthItem(stringResource(R.string.authorization_list_creationDateTime), AuthorizationList.formatDate(it))
        }
        list.getOrigin()?.let {
            AuthItem(stringResource(R.string.authorization_list_origin), AuthorizationList.originToString(it))
        }
        list.getRollbackResistant()?.let {
            AuthItem(stringResource(R.string.authorization_list_rollbackResistant), "")
        }
        list.getRootOfTrust()?.let {
            AuthItem(stringResource(R.string.authorization_list_rootOfTrust), it.toString())
        }
        list.getOsVersion()?.let {
            AuthItem(stringResource(R.string.authorization_list_osVersion), "$it")
        }
        list.getOsPatchLevel()?.let {
            AuthItem(stringResource(R.string.authorization_list_osPatchLevel), "$it")
        }
        list.getAttestationApplicationId()?.let {
            AuthItem(stringResource(R.string.authorization_list_attestationApplicationId), it.toString())
        }
        list.getBrand()?.let {
            AuthItem(stringResource(R.string.authorization_list_attestationIdBrand), it)
        }
        list.getDevice()?.let {
            AuthItem(stringResource(R.string.authorization_list_attestationIdDevice), it)
        }
        list.getProduct()?.let {
            AuthItem(stringResource(R.string.authorization_list_attestationIdProduct), it)
        }
        list.getSerialNumber()?.let {
            AuthItem(stringResource(R.string.authorization_list_attestationIdSerial), it)
        }
        list.getImei()?.let {
            AuthItem(stringResource(R.string.authorization_list_attestationIdImei), it)
        }
        list.getSecondImei()?.let {
            AuthItem(stringResource(R.string.authorization_list_attestationIdSecondImei), it)
        }
        list.getMeid()?.let {
            AuthItem(stringResource(R.string.authorization_list_attestationIdMeid), it)
        }
        list.getManufacturer()?.let {
            AuthItem(stringResource(R.string.authorization_list_attestationIdManufacturer), it)
        }
        list.getModel()?.let {
            AuthItem(stringResource(R.string.authorization_list_attestationIdModel), it)
        }
        list.getVendorPatchLevel()?.let {
            AuthItem(stringResource(R.string.authorization_list_vendorPatchLevel), "$it")
        }
        list.getBootPatchLevel()?.let {
            AuthItem(stringResource(R.string.authorization_list_bootPatchLevel), "$it")
        }
        list.getEarlyBootOnly()?.let {
            AuthItem(stringResource(R.string.authorization_list_earlyBootOnly), "")
        }
        list.getDeviceUniqueAttestation()?.let {
            AuthItem(stringResource(R.string.authorization_list_deviceUniqueAttestation), "")
        }
        list.getIdentityCredentialKey()?.let {
            AuthItem(stringResource(R.string.authorization_list_identityCredentialKey), "")
        }
        list.getModuleHash()?.let {
            AuthItem(stringResource(R.string.authorization_list_moduleHash), it.joinToString("") { b -> "%02x".format(b) })
        }
    }
}

@Composable
fun AuthItem(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(1f)
        )
        if (value.isNotEmpty()) {
            Text(
                value,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Medium,
                modifier = Modifier.weight(1.5f)
            )
        }
    }
}

// Helper functions
private fun formatDate(date: Date?): String {
    return date?.let { DateFormat.getDateTimeInstance().format(it) } ?: "N/A"
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
