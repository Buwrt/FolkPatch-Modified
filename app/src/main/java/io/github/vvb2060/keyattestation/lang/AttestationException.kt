package io.github.vvb2060.keyattestation.lang

class AttestationException(code: Int, cause: Throwable) : RuntimeException(cause) {

    companion object {
        const val CODE_UNKNOWN = -1
        const val CODE_UNAVAILABLE = 0
        const val CODE_CANT_PARSE_CERT = 2
        const val CODE_STRONGBOX_UNAVAILABLE = 3
        const val CODE_DEVICEIDS_UNAVAILABLE = 4
        const val CODE_OUT_OF_KEYS = 5
        const val CODE_OUT_OF_KEYS_TRANSIENT = 6
        const val CODE_UNAVAILABLE_TRANSIENT = 7
        const val CODE_KEYS_NOT_PROVISIONED = 8
        const val CODE_RKP = 9
    }

    val title: String = when (code) {
        CODE_UNAVAILABLE -> "不可用"
        CODE_CANT_PARSE_CERT -> "证书解析失败"
        CODE_STRONGBOX_UNAVAILABLE -> "StrongBox 不可用"
        CODE_DEVICEIDS_UNAVAILABLE -> "设备ID不可用"
        CODE_OUT_OF_KEYS -> "密钥已耗尽"
        CODE_OUT_OF_KEYS_TRANSIENT -> "密钥暂时耗尽"
        CODE_UNAVAILABLE_TRANSIENT -> "暂时不可用"
        CODE_KEYS_NOT_PROVISIONED -> "密钥未预置"
        CODE_RKP -> "远程密钥配置失败"
        else -> "未知错误"
    }

    val description: String = when (code) {
        CODE_UNAVAILABLE -> "KeyStore 不可用"
        CODE_CANT_PARSE_CERT -> "无法解析认证证书"
        CODE_STRONGBOX_UNAVAILABLE -> "设备不支持 StrongBox"
        CODE_DEVICEIDS_UNAVAILABLE -> "设备不支持设备ID认证"
        CODE_OUT_OF_KEYS -> "已用完所有可用密钥"
        CODE_OUT_OF_KEYS_TRANSIENT -> "暂时用完可用密钥，请稍后重试"
        CODE_UNAVAILABLE_TRANSIENT -> "KeyStore 暂时不可用，请稍后重试"
        CODE_KEYS_NOT_PROVISIONED -> "设备密钥尚未预置"
        CODE_RKP -> "远程密钥配置服务出错"
        else -> "发生未知错误"
    }

    override fun fillInStackTrace() = this
}
