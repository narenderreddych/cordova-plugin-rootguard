package com.rootguard.detection;

import org.apache.cordova.*;
import org.json.JSONArray;
import org.json.JSONException;

import android.os.Build;
import android.util.Log;

import java.io.*;
import java.net.*;
import java.util.concurrent.TimeUnit;

public class RootGuard extends CordovaPlugin {

    private static final String TAG = "RootGuard";
    private static final boolean ENABLE_LOGS = true;

    // Result states
    private static final int SAFE = 0;
    private static final int COMPROMISED = 1;
    private static final int UNKNOWN = 2;

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {

        if (!"checkSecurity".equals(action)) {
            return false;
        }

        cordova.getThreadPool().execute(() -> {
            try {

                // 🔐 Capability gate
                if (!isHeuristicDetectionSafe()) {
                    log("Modern Android detected — heuristic checks disabled");
                    callbackContext.success(UNKNOWN);
                    return;
                }

                boolean compromised = isDeviceRooted() || isFridaPresent();
                callbackContext.success(compromised ? COMPROMISED : SAFE);

            } catch (Exception e) {
                log("Detection error: " + e.getMessage());
                // Do NOT fail-safe to compromised on modern Android
                callbackContext.success(UNKNOWN);
            }
        });

        return true;
    }

    /**
     * Heuristic root / frida detection is only reliable up to Android 12.
     */
    private boolean isHeuristicDetectionSafe() {
        return Build.VERSION.SDK_INT <= Build.VERSION_CODES.S; // Android 12
    }

    // ------------------------------------------------------------------
    // Root Detection (Legacy Android only)
    // ------------------------------------------------------------------

    private boolean isDeviceRooted() {
        return checkRootFiles() || checkSuBinary();
    }

    private boolean checkRootFiles() {
        String[] paths = {
                "/system/app/Superuser.apk",
                "/system/xbin/su",
                "/system/bin/su",
                "/sbin/su",
                "/system/su",
                "/sbin/.magisk"
        };

        for (String path : paths) {
            try {
                if (new File(path).exists()) {
                    log("Root file found: " + path);
                    return true;
                }
            } catch (SecurityException ignored) {
                // Restricted access ≠ root
            }
        }
        return false;
    }

    private boolean checkSuBinary() {
        return runCommand(new String[]{"which", "su"});
    }

    // ------------------------------------------------------------------
    // Frida Detection (Legacy Android only)
    // ------------------------------------------------------------------

    private boolean isFridaPresent() {
        return checkFridaPorts() || checkFridaProcesses();
    }

    private boolean checkFridaPorts() {
        int[] ports = {27042, 27043};
        for (int port : ports) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress("127.0.0.1", port), 300);
                log("Frida port detected: " + port);
                return true;
            } catch (IOException ignored) {
            }
        }
        return false;
    }

    private boolean checkFridaProcesses() {
        return runCommand(new String[]{"pidof", "frida-server"});
    }

    // ------------------------------------------------------------------
    // Utility
    // ------------------------------------------------------------------

    /**
     * Runs a command safely.
     * Output present → suspicious
     * Timeout / missing binary → NOT compromised
     */
    private boolean runCommand(String[] command) {
        Process process = null;
        BufferedReader reader = null;

        try {
            process = new ProcessBuilder(command).start();

            if (!process.waitFor(400, TimeUnit.MILLISECONDS)) {
                process.destroy();
                return false; // timeout ≠ compromised
            }

            reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            return reader.readLine() != null;

        } catch (IOException e) {
            return false; // restricted / missing binary ≠ root
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        } finally {
            try {
                if (reader != null) reader.close();
            } catch (IOException ignored) {
            }
            if (process != null) process.destroy();
        }
    }

    private void log(String msg) {
        if (ENABLE_LOGS) {
            Log.d(TAG, msg);
        }
    }
}
