plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "icu.nullptr.applistdetector"
    compileSdk = 36

    defaultConfig {
        minSdk = 26
        targetSdk = 36
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            consumerProguardFiles("proguard-rules.pro")
        }
    }

    // 禁用native编译，使用纯Kotlin实现
    // externalNativeBuild.ndkBuild {
    //     path("src/main/cpp/Android.mk")
    // }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    kotlinOptions {
        jvmTarget = "21"
    }
}

dependencies {
    // 移除需要native的依赖
    // implementation("io.github.vvb2060.ndk:xposeddetector:2.2")
}
