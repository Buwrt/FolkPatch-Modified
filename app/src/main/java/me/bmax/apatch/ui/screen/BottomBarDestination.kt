package me.bmax.apatch.ui.screen

import androidx.annotation.StringRes
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Archive
import androidx.compose.material.icons.filled.AdminPanelSettings
import androidx.compose.material.icons.filled.Extension
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.outlined.Apps
import androidx.compose.material.icons.outlined.Archive
import androidx.compose.material.icons.outlined.AdminPanelSettings
import androidx.compose.material.icons.outlined.Extension
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.VerifiedUser
import androidx.compose.ui.graphics.vector.ImageVector
import com.ramcosta.composedestinations.generated.destinations.APModuleScreenDestination
import com.ramcosta.composedestinations.generated.destinations.ApplistDetectorScreenDestination
import com.ramcosta.composedestinations.generated.destinations.HomeScreenDestination
import com.ramcosta.composedestinations.generated.destinations.KeyAttestationScreenDestination
import com.ramcosta.composedestinations.generated.destinations.KPModuleScreenDestination
import com.ramcosta.composedestinations.generated.destinations.SettingScreenDestination
import com.ramcosta.composedestinations.generated.destinations.SuperUserScreenDestination
import com.ramcosta.composedestinations.spec.DirectionDestinationSpec
import me.bmax.apatch.R

enum class BottomBarDestination(
    val direction: DirectionDestinationSpec,
    @param:StringRes val label: Int,
    val iconSelected: ImageVector,
    val iconNotSelected: ImageVector,
    val kPatchRequired: Boolean,
    val aPatchRequired: Boolean,
) {
    Home(
        HomeScreenDestination,
        R.string.home,
        Icons.Filled.Home,
        Icons.Outlined.Home,
        false,
        false
    ),
    KeyAttestation(
        KeyAttestationScreenDestination,
        R.string.key_attestation,
        Icons.Filled.VerifiedUser,
        Icons.Outlined.VerifiedUser,
        false,
        false
    ),
    ApplistDetector(
        ApplistDetectorScreenDestination,
        R.string.applist_detector_title,
        Icons.Filled.Security,
        Icons.Outlined.Security,
        false,
        false
    ),
    KModule(
        KPModuleScreenDestination,
        R.string.kpm,
        Icons.Filled.Archive,
        Icons.Outlined.Archive,
        true,
        false
    ),
    SuperUser(
        SuperUserScreenDestination,
        R.string.su_title,
        Icons.Filled.AdminPanelSettings,
        Icons.Outlined.AdminPanelSettings,
        true,
        false
    ),
    AModule(
        APModuleScreenDestination,
        R.string.apm,
        Icons.Filled.Extension,
        Icons.Outlined.Extension,
        false,
        true
    ),
    Settings(
        SettingScreenDestination,
        R.string.settings,
        Icons.Filled.Settings,
        Icons.Outlined.Settings,
        false,
        false
    )
}
