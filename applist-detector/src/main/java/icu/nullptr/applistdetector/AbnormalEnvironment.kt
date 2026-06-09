package icu.nullptr.applistdetector

import android.content.Context
import android.os.Build
import java.io.File

/**
 * 异常环境检测器 - 纯Java实现
 * 检测Xposed、双开、TWRP等异常环境
 */
class AbnormalEnvironment(context: Context) : IDetector(context) {

    override val name = "异常环境检测"

    /**
     * 检测Xposed框架
     * 通过检查系统属性和堆栈跟踪
     */
    private fun detectXposed(): Boolean {
        return try {
            // 方法1: 检查系统属性
            val xposedProps = listOf(
                "ro.kernel.xposed",
                "persist.xposed.active",
                "xposed.active"
            )
            
            for (prop in xposedProps) {
                try {
                    val process = Runtime.getRuntime().exec("getprop $prop")
                    val result = process.inputStream.bufferedReader().readText().trim()
                    if (result.isNotEmpty() && result != "0" && result != "false") {
                        return true
                    }
                } catch (_: Exception) {}
            }
            
            // 方法2: 检查堆栈跟踪中的Xposed痕迹
            try {
                throw Exception("Xposed check")
            } catch (e: Exception) {
                for (element in e.stackTrace) {
                    if (element.className.contains("xposed", ignoreCase = true) ||
                        element.className.contains("edxposed", ignoreCase = true) ||
                        element.className.contains("lsposed", ignoreCase = true)) {
                        return true
                    }
                }
            }
            
            // 方法3: 检查Xposed相关文件
            val xposedFiles = listOf(
                "/system/framework/XposedBridge.jar",
                "/system/framework/xposed",
                "/data/adb/lspd",
                "/data/adb/edxposed",
                "/data/misc/lspd"
            )
            
            for (file in xposedFiles) {
                if (File(file).exists()) {
                    return true
                }
            }
            
            false
        } catch (_: Exception) {
            false
        }
    }

    /**
     * 检测双开/工作资料
     */
    private fun detectDual(): Boolean {
        return try {
            // 检查用户数量
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                val userManager = context.getSystemService(Context.USER_SERVICE) as? android.os.UserManager
                if (userManager != null) {
                    val users = userManager.userProfiles
                    if (users != null && users.size > 1) {
                        return true
                    }
                }
            }
            
            // 检查双开应用目录
            val dualPaths = listOf(
                "/data/data/com.excelliance.dualaidl",
                "/data/data/com.lbe.parallel",
                "/data/data/com.ludashi.dualspace",
                "/data/data/com.dualapp"
            )
            
            for (path in dualPaths) {
                if (File(path).exists()) {
                    return true
                }
            }
            
            false
        } catch (_: Exception) {
            false
        }
    }

    private fun detectFile(path: String): Result {
        var res = FileDetection.detect(path, true)
        if (res == Result.METHOD_UNAVAILABLE) res = FileDetection.detect(path, false)
        if (res == Result.FOUND) res = Result.SUSPICIOUS
        return res
    }

    override fun run(packages: Collection<String>?, detail: Detail?): Result {
        var result = Result.NOT_FOUND
        val add: (Pair<String, Result>) -> Unit = {
            result = result.coerceAtLeast(it.second)
            detail?.add(it)
        }
        
        add("Xposed框架" to if (detectXposed()) Result.FOUND else Result.NOT_FOUND)
        add("双开/工作资料" to if (detectDual()) Result.SUSPICIOUS else Result.NOT_FOUND)
        add("XPrivacyLua" to detectFile("/data/system/xlua"))
        add("TWRP恢复" to detectFile("/storage/emulated/0/TWRP"))
        
        return result
    }
}
