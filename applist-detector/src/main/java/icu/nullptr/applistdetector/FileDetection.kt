package icu.nullptr.applistdetector

import android.annotation.SuppressLint
import android.content.Context
import java.io.File

/**
 * 文件检测器 - 纯Java实现，不依赖native代码
 * 检测应用数据目录是否存在
 */
class FileDetection(context: Context, private val useSyscall: Boolean = false) : IDetector(context) {

    override val name = if (useSyscall) "Syscall File Detection" else "Libc File Detection"

    companion object {
        /**
         * 检测路径是否存在
         * 使用Java File API实现
         */
        @JvmStatic
        fun detect(path: String, useSyscall: Boolean = false): Result {
            return try {
                val file = File(path)
                when {
                    file.exists() -> Result.FOUND
                    else -> Result.NOT_FOUND
                }
            } catch (e: SecurityException) {
                Result.METHOD_UNAVAILABLE
            } catch (e: Exception) {
                Result.NOT_FOUND
            }
        }
    }

    @SuppressLint("SdCardPath")
    override fun run(packages: Collection<String>?, detail: Detail?): Result {
        if (packages == null) throw IllegalArgumentException("packages should not be null")

        var result = Result.NOT_FOUND
        for (packageName in packages) {
            val res = maxOf(
                Result.NOT_FOUND,
                detect("/data/data/$packageName", useSyscall),
                detect("/storage/emulated/0/Android/data/$packageName", useSyscall),
                detect("/storage/emulated/0/Android/media/$packageName", useSyscall),
                detect("/storage/emulated/0/Android/obb/$packageName", useSyscall)
            )
            result = result.coerceAtLeast(res)
            detail?.add(packageName to res)
        }
        return result
    }
}
