package top.sevenshape.dr2cmodloader;

import android.content.Context;
import android.content.res.AssetManager;
import android.content.res.XModuleResources;
import android.os.Bundle;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

public class Xposed implements IXposedHookLoadPackage, IXposedHookZygoteInit {
    @Override
    public void handleLoadPackage(LoadPackageParam lpparam) {
        // In NPatch integrated mode this module is embedded into one host APK,
        // so the callback is already scoped to that host. Do not reject a
        // correctly generated coexisting build merely because its application
        // id is no longer com.noodlecake.drtc.
        log("load " + lpparam.packageName);

        XModuleResources modRes = XModuleResources.createInstance(MODULE_PATH, null);
        AssetManager xam = modRes.getAssets();

        XposedHelpers.findAndHookMethod(
                "com.noodlecake.drtc.DrtcGameActivity",
                lpparam.classLoader,
                "onCreate",
                Bundle.class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {

                        Context ctx = (Context) param.thisObject;
                        File modDir = ctx.getExternalFilesDir("");
                        if (modDir == null) {
                            error("✗ External files directory is unavailable",
                                    new IOException("getExternalFilesDir returned null"));
                            return;
                        }
                        File scriptFile = new File(modDir, "main.js");
                        File moduleStampFile = new File(modDir, ".dr2c-loader-module");
                        log("modDir: " + modDir.getAbsolutePath());
                        log("scriptFile: " + scriptFile.getAbsolutePath());

                        try {
                            File moduleFile = new File(MODULE_PATH);
                            String moduleStamp = MODULE_PATH + ":" + moduleFile.length()
                                    + ":" + moduleFile.lastModified();
                            String installedStamp = moduleStampFile.exists()
                                    ? readText(moduleStampFile) : "";
                            if (!moduleStamp.equals(installedStamp)) {
                                // Refresh the APK-owned bootstrap and assets
                                // once per APK update. Installed mods live in
                                // mods/ and are never touched.
                                Xposed.copyAssets(xam, "public", modDir);
                                writeText(moduleStampFile, moduleStamp);
                            } else {
                                log("loader assets already match embedded module");
                            }
                        } catch (Exception e) {
                            error("fail to copyAssets", e);
                        } finally {
                            log("execution end to copyAssets");
                        }
                        
                        log("if an exception occurs case reinstall dr2c apk");

                        try {
                            System.loadLibrary("frida-gadget");
                            log("✓ Frida Gadget loaded successfully");
                        } catch (Exception e) {
                            error("✗ Failed to load Frida Gadget: ", e);
                        }
                    }
                });
    }

    public static void copyAssets(AssetManager am, String assetPath, File destDir) throws IOException {
        String[] children = am.list(assetPath);
        if (children != null && children.length > 0) {
            
            if (!destDir.exists())
                destDir.mkdirs();
            for (String name : children) {
                String childAsset = assetPath.isEmpty() ? name : assetPath + "/" + name;
                copyAssets(am, childAsset, new File(destDir, name));
            }
        } else {
            
            File parent = destDir.getParentFile();
            if (parent != null && !parent.exists())
                parent.mkdirs();
            try (InputStream in = am.open(assetPath);
                    OutputStream out = new FileOutputStream(destDir)) {
                byte[] buf = new byte[8192];
                int len;
                while ((len = in.read(buf)) > 0)
                    out.write(buf, 0, len);
            }
        }
    }

    String readText(File f) throws IOException {
        try (FileInputStream in = new FileInputStream(f);
                ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buf = new byte[1024];
            int len;
            while ((len = in.read(buf)) > 0)
                out.write(buf, 0, len);
            return out.toString("UTF-8");
        }
    }

    void writeText(File f, String text) throws IOException {
        try (FileOutputStream out = new FileOutputStream(f)) {
            out.write(text.getBytes("UTF-8"));
        }
    }

    public final String TAG = "Xposed";

    public void log(String msg) {
        Log.i(TAG, msg);
    }

    public void error(String msg, Throwable tr) {
        Log.e(TAG, msg, tr);
    }

    private static String MODULE_PATH;

    @Override
    public void initZygote(IXposedHookZygoteInit.StartupParam startupParam) {
        MODULE_PATH = startupParam.modulePath;
    }
}
