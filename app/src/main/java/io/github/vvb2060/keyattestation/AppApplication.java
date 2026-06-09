package io.github.vvb2060.keyattestation;

import android.app.Application;

public class AppApplication extends Application {
    public static final String TAG = "KeyAttestation";
    public static AppApplication app;

    @Override
    public void onCreate() {
        super.onCreate();
        app = this;
    }
}
