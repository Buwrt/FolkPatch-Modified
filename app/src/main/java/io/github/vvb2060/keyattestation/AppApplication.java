package io.github.vvb2060.keyattestation;

import android.content.Context;

/**
 * AppApplication 用于为 KeyAttestation 库提供 Application 上下文。
 * 由于 FolkPatch 使用自己的 Application 类，这里作为简单的 Context 持有者。
 */
public class AppApplication {

    public static final String TAG = "KeyAttestation";

    private static Context appContext;

    public static Context getApp() {
        if (appContext == null) {
            try {
                Object activityThread = Class.forName("android.app.ActivityThread")
                        .getMethod("currentActivityThread").invoke(null);
                Context ctx = (Context) activityThread.getClass()
                        .getMethod("getApplication").invoke(activityThread);
                if (ctx != null) {
                    appContext = ctx.getApplicationContext();
                }
            } catch (Exception e) {
                throw new RuntimeException("Failed to get Application context", e);
            }
        }
        return appContext;
    }

    public static void init(Context context) {
        if (context != null) {
            appContext = context.getApplicationContext();
        }
    }
}
