package me.bmax.apatch.ui.screen

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import icu.nullptr.applistdetector.AbnormalEnvironment
import icu.nullptr.applistdetector.FileDetection
import icu.nullptr.applistdetector.IDetector
import icu.nullptr.applistdetector.MagiskApp
import icu.nullptr.applistdetector.PMCommand
import icu.nullptr.applistdetector.PMConventionalAPIs
import icu.nullptr.applistdetector.PMQueryIntentActivities
import icu.nullptr.applistdetector.PMSundryAPIs
import icu.nullptr.applistdetector.XposedModules
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import me.bmax.apatch.R
import me.bmax.apatch.ui.component.CheckCard
import me.bmax.apatch.ui.component.IconHintCard

typealias Detail = MutableList<Pair<String, IDetector.Result>>

val basicAppList = listOf(
    "com.topjohnwu.magisk",
    "io.github.vvb2060.magisk",
    "de.robv.android.xposed.installer",
    "org.meowcat.edxposed.manager",
    "org.lsposed.manager",
    "top.canyie.dreamland.manager",
    "me.weishu.exp",
    "com.android.vendinf",
    "moe.shizuku.redirectstorage"
)

@Destination<RootGraph>
@Composable
fun ApplistDetectorScreen() {
    val context = LocalContext.current
    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior()

    val snapShotList = remember {
        mutableStateListOf<Triple<IDetector, IDetector.Result?, Detail?>>(
            Triple(AbnormalEnvironment(context), null, null),
            Triple(PMCommand(context), null, null),
            Triple(PMConventionalAPIs(context), null, null),
            Triple(PMSundryAPIs(context), null, null),
            Triple(PMQueryIntentActivities(context), null, null),
            Triple(FileDetection(context, false), null, null),
            Triple(FileDetection(context, true), null, null),
            Triple(XposedModules(context), null, null),
            Triple(MagiskApp(context), null, null)
        )
    }

    suspend fun runDetector(id: Int, packages: Collection<String>?) {
        withContext(Dispatchers.IO) {
            val detail = mutableListOf<Pair<String, IDetector.Result>>()
            val result = snapShotList[id].first.run(packages, detail)
            snapShotList[id] = Triple(snapShotList[id].first, result, detail)
        }
    }

    LaunchedEffect(Unit) {
        runDetector(0, null)
        for (i in 1..6) runDetector(i, basicAppList)
        runDetector(7, null)
        runDetector(8, null)
    }

    Scaffold(
        topBar = { ApplistDetectorTopBar(scrollBehavior) },
        modifier = Modifier.nestedScroll(scrollBehavior.nestedScrollConnection)
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            IconHintCard()
            snapShotList.forEach { item ->
                CheckCard(
                    title = item.first.name,
                    result = item.second,
                    detail = item.third
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ApplistDetectorTopBar(scrollBehavior: androidx.compose.material3.TopAppBarScrollBehavior) {
    TopAppBar(
        title = { Text(stringResource(R.string.applist_detector_title)) },
        scrollBehavior = scrollBehavior,
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = MaterialTheme.colorScheme.surface,
            titleContentColor = MaterialTheme.colorScheme.onSurface
        )
    )
}
