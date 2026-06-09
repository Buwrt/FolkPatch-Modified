package io.github.vvb2060.keyattestation;

import android.app.Application;
import android.content.Context;

public class AppApplication extends Application {
    public static final String TAG = "KeyAttestation";
    private static AppApplication app;

    public static AppApplication getApp() {
        if (app == null) {
            try {
                // 通过反射获取当前 Application 实例
                android.app.ActivityThread activityThread =
                    (android.app.ActivityThread) Class.forName("android.app.ActivityThread")
                        .getMethod("currentActivityThread")
                        .invoke(null);
                Context context = (Context) activityThread.getClass()
                    .getMethod("getApplication")
                    .invoke(activityThread);
                if (context instanceof AppApplication) {
                    app = (AppApplication) context;
                } else {
                    // 如果当前 Application 不是 AppApplication，创建代理
                    app = new AppApplication();
                    app.attachBaseContext(context);
                }
            } catch (Exception e) {
                throw new RuntimeException("Failed to get Application instance", e);
            }
        }
        return app;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        app = this;
    }
}
