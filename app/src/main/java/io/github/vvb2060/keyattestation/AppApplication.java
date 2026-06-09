package io.github.vvb2060.keyattestation;

import android.app.Application;
import android.content.Context;

/**
 * AppApplication 用于为 KeyAttestation 库提供 Application 上下文。
 * 由于 FolkPatch 使用自己的 Application 类，这里通过反射获取当前应用的 Application 实例。
 */
public class AppApplication extends Application {
    public static final String TAG = "KeyAttestation";
    private static AppApplication app;
    private static Context fallbackContext;

    public static AppApplication getApp() {
        if (app == null) {
            try {
                // 通过反射获取当前 ActivityThread 的 Application
                Object activityThread = Class.forName("android.app.ActivityThread")
                    .getMethod("currentActivityThread")
                    .invoke(null);
                Context context = (Context) activityThread.getClass()
                    .getMethod("getApplication")
                    .invoke(activityThread);

                if (context instanceof AppApplication) {
                    app = (AppApplication) context;
                } else if (context != null) {
                    // 使用 FolkPatch 的 Application 上下文，但包装为 AppApplication
                    app = new AppApplication();
                    // 通过反射调用 attachBaseContext
                    Application.class.getDeclaredMethod("attachBaseContext", Context.class)
                        .invoke(app, context.getApplicationContext());
                }
            } catch (Exception e) {
                // 如果反射失败，尝试使用 fallbackContext
                if (fallbackContext != null) {
                    app = new AppApplication();
                    try {
                        Application.class.getDeclaredMethod("attachBaseContext", Context.class)
                            .invoke(app, fallbackContext);
                    } catch (Exception ignored) {}
                }
            }
        }
        return app;
    }

    /**
     * 在 FolkPatch 的 Application.onCreate() 中调用此方法初始化
     */
    public static void init(Context context) {
        if (context != null) {
            fallbackContext = context.getApplicationContext();
            if (app == null && context instanceof AppApplication) {
                app = (AppApplication) context;
            }
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        app = this;
    }
}
