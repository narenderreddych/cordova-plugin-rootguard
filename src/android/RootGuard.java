
package com.rootguard.detection;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;
import org.json.JSONArray;
import org.json.JSONException;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

public class RootGuard extends CordovaPlugin {

    private static final String TAG = "RootGuard";
    private static final boolean ENABLE_LOGS = true;

    private static final int COMMAND_TIMEOUT_MS = 1000;
    private static final int SOCKET_TIMEOUT_MS = 350;

    /*
     * Optional signing-certificate pin.
     *
     * Set this to the SHA-256 fingerprint of your expected release
     * signing certificate, with or without colons.
     *
     * Leave empty to disable the signing check.
     * Do not use a debug certificate fingerprint for production.
     */
    private static final String EXPECTED_CERT_SHA256 = "";

    @Override
    public boolean execute(
            String action,
            JSONArray args,
            CallbackContext callbackContext
    ) throws JSONException {

        if (!"checkSecurity".equals(action)) {
            return false;
        }

        cordova.getThreadPool().execute(() -> {
            try {
                boolean compromised = isDeviceRooted()
                        || isFridaPresent()
                        || hasSuspiciousRuntimeIndicators()
                        || hasUnexpectedSigningCertificate();

                callbackContext.success(compromised ? 1 : 0);

            } catch (Exception e) {
                log("Security check failed unexpectedly: "
                        + e.getClass().getSimpleName());

                // Fail closed: do not silently allow an unexpected
                // detector exception. This can block legitimate devices.
                callbackContext.success(1);
            }
        });

        return true;
    }

    // ============================================================
    // ROOT / MAGISK / ZYGISK INDICATORS
    // ============================================================

    private boolean isDeviceRooted() {

        String[] rootPaths = {
                "/system/app/Superuser.apk",
                "/system/app/SuperSU.apk",
                "/system/xbin/su",
                "/system/bin/su",
                "/sbin/su",
                "/system/sd/xbin/su",
                "/system/bin/failsafe/su",
                "/data/local/xbin/su",
                "/data/local/bin/su",
                "/data/local/su",
                "/su/bin/su",
                "/vendor/bin/su",
                "/system/su",
                "/sbin/.magisk",
                "/debug_ramdisk/.magisk",
                "/data/adb/magisk",
                "/data/adb/zygisk"
        };

        for (String path : rootPaths) {
            if (new File(path).exists()) {
                log("Root-related artifact detected: " + path);
                return true;
            }
        }

        // /data/adb/modules is a Magisk-related indicator, but its
        // visibility and meaning depend on the device and configuration.
        if (new File("/data/adb/modules").exists()) {
            log("Magisk modules directory detected");
            return true;
        }

        if (hasSuspiciousBuildTags()) {
            return true;
        }

        if (hasSuspiciousSystemProperties()) {
            return true;
        }

        if (checkSuCommand()) {
            return true;
        }

        if (checkWritableSystemMounts()) {
            return true;
        }

        return false;
    }

    private boolean hasSuspiciousBuildTags() {

        String tags = Build.TAGS;
        String fingerprint = Build.FINGERPRINT;
        String buildType = Build.TYPE;

        if (tags != null) {
            String lowerTags = tags.toLowerCase(Locale.US);

            if (lowerTags.contains("test-keys")) {
                log("Test-keys build tag detected");
                return true;
            }
        }

        if (buildType != null) {
            if ("eng".equalsIgnoreCase(buildType)
                    || "userdebug".equalsIgnoreCase(buildType)) {
                log("Non-production Android build type detected");
                return true;
            }
        }

        if (fingerprint != null) {
            String lowerFingerprint =
                    fingerprint.toLowerCase(Locale.US);

            if (lowerFingerprint.contains("generic")
                    || lowerFingerprint.contains("userdebug")
                    || lowerFingerprint.contains("test-keys")) {
                log("Suspicious build fingerprint detected");
                return true;
            }
        }

        return false;
    }

    private boolean hasSuspiciousSystemProperties() {

        String output = runCommand("getprop");

        if (output == null || output.length() == 0) {
            log("System properties unavailable; no conclusion from getprop");
            return false;
        }

        String lower = output.toLowerCase(Locale.US);

        String[] suspiciousProperties = {
                "[ro.debuggable]: [1]",
                "[ro.secure]: [0]",
                "[ro.build.type]: [userdebug]",
                "[ro.build.type]: [eng]"
        };

        for (String property : suspiciousProperties) {
            if (lower.contains(property)) {
                log("Suspicious system property detected: " + property);
                return true;
            }
        }

        return false;
    }

    private boolean checkSuCommand() {

        String output = runCommand("which su");

        if (output != null) {
            String trimmed = output.trim();

            if (trimmed.length() > 0
                    && trimmed.contains("/")) {
                log("su executable reported by which");
                return true;
            }
        }

        String[] suPaths = {
                "/system/xbin/su",
                "/system/bin/su",
                "/sbin/su",
                "/vendor/bin/su",
                "/su/bin/su"
        };

        for (String path : suPaths) {
            if (new File(path).exists()) {
                log("su executable found: " + path);
                return true;
            }
        }

        return false;
    }

    private boolean checkWritableSystemMounts() {

        String output = runCommand("mount");

        if (output == null || output.length() == 0) {
            log("Mount information unavailable");
            return false;
        }

        String[] lines = output.split("\\n");

        for (String line : lines) {
            String lower = line.toLowerCase(Locale.US);

            boolean relevantMount =
                    lower.contains(" on /system ")
                    || lower.contains(" on /system/")
                    || lower.contains(" on /vendor ")
                    || lower.contains(" on /vendor/")
                    || lower.contains(" on /");

            if (!relevantMount) {
                continue;
            }

            // Check mount options rather than matching "rw" anywhere
            // in the line. This is an indicator, not definitive proof.
            int optionsStart = line.indexOf('(');
            int optionsEnd = line.indexOf(')');

            if (optionsStart >= 0 && optionsEnd > optionsStart) {
                String options = line.substring(
                        optionsStart + 1, optionsEnd
                );

                String[] tokens = options.split(",");

                for (String token : tokens) {
                    if ("rw".equals(token.trim())) {
                        log("Potentially writable system mount detected");
                        return true;
                    }
                }
            }
        }

        return false;
    }

    // ============================================================
    // FRIDA / RUNTIME INSTRUMENTATION INDICATORS
    // ============================================================

    private boolean isFridaPresent() {

        if (isPortOpen(27042) || isPortOpen(27043)) {
            log("Potential Frida server port detected");
            return true;
        }

        String maps = readProcFile("/proc/self/maps");

        if (maps != null) {
            String lower = maps.toLowerCase(Locale.US);

            String[] indicators = {
                    "frida",
                    "frida-agent",
                    "frida-gadget",
                    "gum-js-loop",
                    "gadget-"
            };

            for (String indicator : indicators) {
                if (lower.contains(indicator)) {
                    log("Runtime instrumentation indicator detected: "
                            + indicator);
                    return true;
                }
            }
        }

        String processOutput = runCommand("pidof frida-server");

        if (processOutput != null
                && processOutput.trim().length() > 0) {
            log("Frida server process detected");
            return true;
        }

        return false;
    }

    private boolean hasSuspiciousRuntimeIndicators() {

        String maps = readProcFile("/proc/self/maps");

        if (maps == null) {
            // A failed read alone is not proof of compromise.
            return false;
        }

        String lower = maps.toLowerCase(Locale.US);

        String[] indicators = {
                "libsubstrate",
                "libxposed",
                "lsposed",
                "zygisk"
        };

        for (String indicator : indicators) {
            if (lower.contains(indicator)) {
                log("Possible runtime modification indicator: "
                        + indicator);
                return true;
            }
        }

        return false;
    }

    private boolean isPortOpen(int port) {

        Socket socket = new Socket();

        try {
            socket.connect(
                    new InetSocketAddress("127.0.0.1", port),
                    SOCKET_TIMEOUT_MS
            );
            return true;

        } catch (Exception e) {
            return false;

        } finally {
            try {
                socket.close();
            } catch (Exception ignored) {
            }
        }
    }

    // ============================================================
    // OPTIONAL APK SIGNING-CERTIFICATE CHECK
    // ============================================================

    private boolean hasUnexpectedSigningCertificate() {

        if (EXPECTED_CERT_SHA256 == null
                || EXPECTED_CERT_SHA256.trim().length() == 0) {
            return false;
        }

        try {
            PackageManager pm = cordova.getActivity()
                    .getPackageManager();

            PackageInfo info = pm.getPackageInfo(
                    cordova.getActivity().getPackageName(),
                    PackageManager.GET_SIGNATURES
            );

            if (info.signatures == null
                    || info.signatures.length == 0) {
                log("Application signing certificate unavailable");
                return true;
            }

            String expected = EXPECTED_CERT_SHA256
                    .replace(":", "")
                    .trim()
                    .toLowerCase(Locale.US);

            for (android.content.pm.Signature signature
                    : info.signatures) {

                byte[] digest = MessageDigest.getInstance("SHA-256")
                        .digest(signature.toByteArray());

                String actual = toHex(digest);

                if (expected.equals(actual)) {
                    return false;
                }
            }

            log("Installed application signing certificate mismatch");
            return true;

        } catch (Exception e) {
            log("Unable to verify application signing certificate");
            return true;
        }
    }

    private String toHex(byte[] bytes) {

        StringBuilder result = new StringBuilder();

        for (byte b : bytes) {
            result.append(String.format(
                    Locale.US, "%02x", b & 0xff
            ));
        }

        return result.toString();
    }

    // ============================================================
    // HELPERS
    // ============================================================

    private String readProcFile(String path) {

        BufferedReader reader = null;

        try {
            reader = new BufferedReader(
                    new InputStreamReader(
                            new FileInputStream(path)
                    )
            );

            StringBuilder result = new StringBuilder();
            String line;

            while ((line = reader.readLine()) != null) {
                result.append(line).append('\n');
            }

            return result.toString();

        } catch (Exception e) {
            return null;

        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (Exception ignored) {
                }
            }
        }
    }

    /*
     * Runs a command with a timeout without relying on newer
     * Process.waitFor(timeout, TimeUnit) Android APIs.
     */
    private String runCommand(String command) {

        Process process = null;
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        Thread readerThread = null;

        try {
            process = new ProcessBuilder(
                    "/system/bin/sh", "-c", command
            ).redirectErrorStream(true).start();

            final Process runningProcess = process;
            final ByteArrayOutputStream capturedOutput = output;

            readerThread = new Thread(() -> {
                byte[] buffer = new byte[1024];

                try {
                    java.io.InputStream input =
                            runningProcess.getInputStream();

                    int count;

                    while ((count = input.read(buffer)) != -1) {
                        synchronized (capturedOutput) {
                            capturedOutput.write(buffer, 0, count);
                        }
                    }

                } catch (Exception ignored) {
                }
            });

            readerThread.setDaemon(true);
            readerThread.start();
            readerThread.join(COMMAND_TIMEOUT_MS);

            if (readerThread.isAlive()) {
                process.destroy();
                readerThread.join(100);
            }

            synchronized (output) {
                return output.toString("UTF-8");
            }

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;

        } catch (Exception e) {
            log("Command unavailable: " + command);
            return null;

        } finally {
            if (process != null) {
                try {
                    process.destroy();
                } catch (Exception ignored) {
                }
            }
        }
    }

    private void log(String message) {
        if (ENABLE_LOGS) {
            Log.d(TAG, message);
        }
    }
}
