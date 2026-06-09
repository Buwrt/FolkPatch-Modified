package me.bmax.apatch.ui.screen

import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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

            // 1. Attestation status card
            AttestationStatusCard(viewModel)

            // 2. Action buttons
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Button(
                    onClick = { viewModel.generateAttestation() },
                    modifier = Modifier.weight(1f)
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

            // 3. KeyBox management card
            KeyBoxManagementCard(viewModel, keyboxPickerLauncher)

            // 4. Certificate root trust status
            viewModel.attestationData?.let { data ->
                CertificateRootTrustCard(data)
            }

            // 5. Bootloader status
            viewModel.attestationData?.let { data ->
                BootloaderStatusCard(data)
            }

            // 6. Certificate chain
            viewModel.attestationData?.let { data ->
                CertificateChainCard(data)
            }

            // 7. Attestation basic info
            viewModel.attestationData?.let { data ->
                AttestationInfoCard(data)
            }

            // 8. Authorization list
            viewModel.attestationData?.let { data ->
                AuthorizationListCard(data)
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

// ==================== Attestation Status Card ====================
@Composable
fun AttestationStatusCard(viewModel: KeyAttestationViewModel) {
    val hasData = viewModel.attestationData != null && viewModel.error == null
    val hasError = viewModel.error != null

    val containerColor = when {
        hasData -> MaterialTheme.colorScheme.primaryContainer
        hasError -> MaterialTheme.colorScheme.errorContainer
        else -> MaterialTheme.colorScheme.surfaceVariant
    }

    val icon = when {
        hasData -> Icons.Filled.CheckCircle
        hasError -> Icons.Filled.Error
        else -> Icons.Outlined.Info
    }

    val iconTint = when {
        hasData -> MaterialTheme.colorScheme.primary
        hasError -> MaterialTheme.colorScheme.error
        else -> MaterialTheme.colorScheme.onSurfaceVariant
    }

    val statusText = when {
        hasData -> stringResource(R.string.ka_status_verified)
        hasError -> stringResource(R.string.ka_status_error)
        else -> stringResource(R.string.ka_status_ready)
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = containerColor)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                icon,
                contentDescription = null,
                modifier = Modifier.size(48.dp),
                tint = iconTint
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

// ==================== Certificate Root Trust Card ====================
@Composable
fun CertificateRootTrustCard(data: AttestationData) {
    val certInfos = data.getCertificateInfos()
    val rootCert = certInfos.lastOrNull()
    val rootStatus = rootCert?.getIssuer() ?: RootPublicKey.Status.UNKNOWN

    // Determine if any cert in chain has error
    val hasChainError = certInfos.any { it.getStatus() != CertificateInfo.CERT_NORMAL }

    val (containerColor, iconTint, titleText, summaryText) = when {
        hasChainError -> {
            Quad(
                MaterialTheme.colorScheme.errorContainer,
                MaterialTheme.colorScheme.error,
                stringResource(R.string.cert_chain_not_trusted),
                stringResource(R.string.cert_chain_not_trusted_summary)
            )
        }
        rootStatus == RootPublicKey.Status.GOOGLE -> {
            Quad(
                MaterialTheme.colorScheme.primaryContainer,
                MaterialTheme.colorScheme.primary,
                stringResource(R.string.google_root_cert),
                stringResource(R.string.google_root_cert_summary)
            )
        }
        rootStatus == RootPublicKey.Status.GOOGLE_RKP -> {
            Quad(
                MaterialTheme.colorScheme.primaryContainer,
                MaterialTheme.colorScheme.primary,
                stringResource(R.string.google_root_cert_rkp),
                stringResource(R.string.google_root_cert_rkp_summary)
            )
        }
        rootStatus == RootPublicKey.Status.KNOX -> {
            Quad(
                MaterialTheme.colorScheme.primaryContainer,
                MaterialTheme.colorScheme.primary,
                stringResource(R.string.knox_root_cert),
                stringResource(R.string.knox_root_cert_summary)
            )
        }
        rootStatus == RootPublicKey.Status.OEM -> {
            Quad(
                MaterialTheme.colorScheme.primaryContainer,
                MaterialTheme.colorScheme.primary,
                stringResource(R.string.oem_root_cert),
                stringResource(R.string.oem_root_cert_summary)
            )
        }
        rootStatus == RootPublicKey.Status.AOSP -> {
            Quad(
                MaterialTheme.colorScheme.tertiaryContainer,
                MaterialTheme.colorScheme.tertiary,
                stringResource(R.string.aosp_root_cert),
                stringResource(R.string.aosp_root_cert_summary)
            )
        }
        rootStatus == RootPublicKey.Status.UNKNOWN -> {
            Quad(
                MaterialTheme.colorScheme.tertiaryContainer,
                MaterialTheme.colorScheme.tertiary,
                stringResource(R.string.unknown_root_cert),
                stringResource(R.string.unknown_root_cert_summary)
            )
        }
        else -> {
            Quad(
                MaterialTheme.colorScheme.surfaceVariant,
                MaterialTheme.colorScheme.onSurfaceVariant,
                stringResource(R.string.unknown_root_cert),
                stringResource(R.string.unknown_root_cert_summary)
            )
        }
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = containerColor)
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
                tint = iconTint
            )
            Spacer(Modifier.width(16.dp))
            Column {
                Text(
                    titleText,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = iconTint
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    summaryText,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface
                )
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

    val (containerColor, iconTint, titleText) = when {
        rot == null -> Triple(
            MaterialTheme.colorScheme.surfaceVariant,
            MaterialTheme.colorScheme.onSurfaceVariant,
            stringResource(R.string.bootloader_unknown)
        )
        !rot.isDeviceLocked && rot.verifiedBootState == RootOfTrust.KM_VERIFIED_BOOT_SELF_SIGNED -> Triple(
            MaterialTheme.colorScheme.surfaceVariant,
            MaterialTheme.colorScheme.onSurfaceVariant,
            stringResource(R.string.bootloader_user)
        )
        rot.isDeviceLocked -> Triple(
            MaterialTheme.colorScheme.primaryContainer,
            MaterialTheme.colorScheme.primary,
            stringResource(R.string.bootloader_locked)
        )
        else -> Triple(
            MaterialTheme.colorScheme.tertiaryContainer,
            MaterialTheme.colorScheme.tertiary,
            stringResource(R.string.bootloader_unlocked)
        )
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = containerColor)
    ) {
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
                    modifier = Modifier.size(48.dp),
                    tint = iconTint
                )
                Spacer(Modifier.width(16.dp))
                Column {
                    Text(
                        stringResource(R.string.ka_bootloader_status),
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = iconTint
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
                stringResource(R.string.cert_chain) + " (${certInfos.size})",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            Text(
                stringResource(R.string.cert_chain_description),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
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
            .padding(12.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                "#${index + 1} ${stringResource(R.string.cert_info)}",
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

        Text(
            stringResource(R.string.cert_subject) + " " + cert.subjectX500Principal.name,
            style = MaterialTheme.typography.bodySmall,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis
        )
        Text(
            stringResource(R.string.cert_not_before) + " " + formatDate(cert.notBefore),
            style = MaterialTheme.typography.bodySmall
        )
        Text(
            stringResource(R.string.cert_not_after) + " " + formatDate(cert.notAfter),
            style = MaterialTheme.typography.bodySmall
        )

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

// ==================== Attestation Info Card ====================
@Composable
fun AttestationInfoCard(data: AttestationData) {
    val attestation = data.getAttestation()

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Attestation Version
            AttestationInfoItem(
                title = stringResource(R.string.attestation),
                description = stringResource(R.string.attestation_version_description),
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
                description = stringResource(R.string.keymaster_version_description),
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
                description = stringResource(R.string.attestation_challenge_description),
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

            HorizontalDivider()

            // Unique ID
            val uniqueId = attestation.getUniqueId()
            AttestationInfoItem(
                title = stringResource(R.string.unique_id),
                description = stringResource(R.string.unique_id_description),
                summary = if (uniqueId != null && uniqueId.isNotEmpty()) {
                    uniqueId.joinToString("") { "%02x".format(it) }
                } else {
                    stringResource(R.string.empty)
                }
            )
        }
    }
}

@Composable
fun AttestationInfoItem(title: String, description: String, summary: String) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(
            title,
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.Bold
        )
        Text(
            description,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.height(4.dp))
        Text(
            summary,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium
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

            // Software Enforced
            if (swList != null && hasAuthorizationItems(swList)) {
                Text(
                    stringResource(R.string.sw_enforced),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.primary
                )
                AuthorizationListItems(swList)
                Spacer(Modifier.height(8.dp))
            }

            // TEE Enforced
            if (teeList != null && hasAuthorizationItems(teeList)) {
                if (swList != null && hasAuthorizationItems(swList)) {
                    HorizontalDivider()
                    Spacer(Modifier.height(8.dp))
                }
                Text(
                    stringResource(R.string.tee_enforced),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.primary
                )
                AuthorizationListItems(teeList)
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
        // Use the same order as original KeyAttestation authorizationItemTitles
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

private fun formatByteArray(bytes: ByteArray?): String {
    if (bytes == null) return "N/A"
    return bytes.take(8).joinToString("") { "%02X".format(it) } +
            if (bytes.size > 8) "..." else ""
}

// Simple Quad data class for 4 values
data class Quad<A, B, C, D>(val first: A, val second: B, val third: C, val fourth: D)

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
