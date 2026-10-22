
package com.rootguard.detection;

import android.os.Build;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class RootGuard extends CordovaPlugin {

    private static final int SAFE = 0;
    private static final int COMPROMISED = 1;
    private static final int UNKNOWN = 2;

    private static final int ANDROID_13 = 33;
    private static final int SOCKET_TIMEOUT_MS = 100;
    private static final int MAX_MAP_LINES = 20000;
    private static final int MAX_FDS = 512;
    private static final int MAX_TASKS = 512;
    private static final int MAX_TCP_LINES = 256;
    private static final int MAX_PORTS = 8;

    private enum State {
        DETECTED, CLEAR, UNAVAILABLE
    }

    private enum Strength {
        HIGH, MEDIUM
    }

    private static final class Signal {
        final String id;
        final String category;
        final State state;
        final Strength strength;

        Signal(
                String id,
                String category,
                State state,
                Strength strength
        ) {
            this.id = id;
            this.category = category;
            this.state = state;
            this.strength = strength;
        }
    }

    private static final class Assessment {
        final int status;
        final List<Signal> signals;
        final List<String> unknownReasons;

        Assessment(
                int status,
                List<Signal> signals,
                List<String> unknownReasons
        ) {
            this.status = status;
            this.signals = signals;
            this.unknownReasons = unknownReasons;
        }
    }

    @Override
    public boolean execute(
            String action,
            JSONArray args,
            CallbackContext callback
    ) throws JSONException {

        if (!"checkSecurity".equals(action)
                && !"checkSecurityStatus".equals(action)
                && !"checkSecurityDetailed".equals(action)) {
            return false;
        }

        cordova.getThreadPool().execute(() -> {
            Assessment assessment;

            try {
                assessment = assess();
            } catch (Exception | LinkageError exception) {
                List<String> reasons = new ArrayList<>();
                reasons.add("assessment_exception");

                assessment = new Assessment(
                        UNKNOWN,
                        new ArrayList<>(),
                        reasons
                );
            }

            try {
                if ("checkSecurity".equals(action)) {
                    // Preserve the existing JavaScript API:
                    // 1 = compromised; 0 = no compromise detected.
                    // UNKNOWN remains 0 for backward compatibility.
                    callback.success(
                            assessment.status == COMPROMISED ? 1 : 0
                    );

                } else if ("checkSecurityStatus".equals(action)) {
                    callback.success(assessment.status);

                } else {
                    callback.success(toJson(assessment));
                }
            } catch (Exception ignored) {
                // The Cordova callback may no longer be available.
            }
        });

        return true;
    }

    private Assessment assess() {
        List<Signal> signals = new ArrayList<>();

        signals.add(checkRootArtifacts());
        signals.add(checkSuOnPath());
        signals.add(checkBuildProvenance());

        signals.add(checkProcessMaps());
        signals.add(checkFileDescriptors());
        signals.add(checkThreadNames());

        signals.add(checkXposedRuntime());
        signals.add(checkFrameworkMaps());
        signals.add(checkMountInfo());

        signals.add(checkFridaProtocol());

        boolean highDetected = false;
        boolean criticalUnavailable = false;
        boolean rootCheckAvailable = false;
        boolean instrumentationUnavailable = false;

        int mediumDetected = 0;

        // Track independent medium-strength categories.
        Set<String> mediumCategories = new LinkedHashSet<>();

        for (Signal signal : signals) {
            if (signal.state == State.DETECTED) {
                if (signal.strength == Strength.HIGH) {
                    highDetected = true;
                } else {
                    mediumDetected++;
                    mediumCategories.add(signal.category);
                }
            }

            if ("root".equals(signal.category)
                    && signal.strength == Strength.HIGH
                    && signal.state != State.UNAVAILABLE) {
                rootCheckAvailable = true;
            }

            if ("instrumentation".equals(signal.category)
                    && signal.state == State.UNAVAILABLE) {
                instrumentationUnavailable = true;
            }

            if ("instrumentation_map".equals(signal.id)
                    && signal.state == State.UNAVAILABLE) {
                criticalUnavailable = true;
            }
        }

        List<String> unknownReasons = new ArrayList<>();

        int status;

        // Strong evidence is sufficient for local detection.
        if (highDetected) {
            status = COMPROMISED;

        } else if (mediumDetected >= 2
                && mediumCategories.size() >= 2) {
            // Require medium signals from independent categories.
            status = COMPROMISED;

        } else {
            if (mediumDetected > 0) {
                unknownReasons.add("insufficient_medium_evidence");
            }

            if (!rootCheckAvailable || criticalUnavailable) {
                unknownReasons.add("critical_check_unavailable");
            }

            if (instrumentationUnavailable) {
                unknownReasons.add("instrumentation_check_unavailable");
            }

            if (Build.VERSION.SDK_INT >= ANDROID_13) {
                unknownReasons.add(
                        "modern_android_local_integrity_unverifiable"
                );
            }

            status = unknownReasons.isEmpty() ? SAFE : UNKNOWN;
        }

        return new Assessment(status, signals, unknownReasons);
    }

    // ---------------------------------------------------------
    // ROOT ARTIFACTS
    // ---------------------------------------------------------

    private Signal checkRootArtifacts() {
        String[] paths = {
                "/system/app/Superuser.apk",
                "/system/bin/su",
                "/system/xbin/su",
                "/system/bin/.ext/.su",
                "/system/usr/we-need-root/su-backup",
                "/sbin/su",
                "/su/bin/su",
                "/sbin/.magisk",
                "/cache/magisk.log",
                "/data/adb/magisk",
                "/data/adb/ksu",
                "/data/adb/ap",
                "/debug_ramdisk"
        };

        try {
            for (String path : paths) {
                if (new File(path).exists()) {
                    return signal(
                            "root_artifact",
                            "root",
                            State.DETECTED,
                            Strength.HIGH
                    );
                }
            }

            return signal(
                    "root_artifact",
                    "root",
                    State.CLEAR,
                    Strength.HIGH
            );

        } catch (SecurityException ignored) {
            return signal(
                    "root_artifact",
                    "root",
                    State.UNAVAILABLE,
                    Strength.HIGH
            );
        }
    }

    private Signal checkSuOnPath() {
        String path = System.getenv("PATH");

        if (path == null || path.isEmpty()) {
            return signal(
                    "su_path",
                    "root",
                    State.UNAVAILABLE,
                    Strength.HIGH
            );
        }

        try {
            for (String directory : path.split(":")) {
                if (directory.isEmpty()) {
                    continue;
                }

                File candidate = new File(directory, "su");

                if (candidate.isFile() && candidate.canExecute()) {
                    return signal(
                            "su_path",
                            "root",
                            State.DETECTED,
                            Strength.HIGH
                    );
                }
            }

            return signal(
                    "su_path",
                    "root",
                    State.CLEAR,
                    Strength.HIGH
            );

        } catch (SecurityException ignored) {
            return signal(
                    "su_path",
                    "root",
                    State.UNAVAILABLE,
                    Strength.HIGH
            );
        }
    }

    private Signal checkBuildProvenance() {
        String tags = Build.TAGS == null
                ? ""
                : Build.TAGS.toLowerCase(Locale.US);

        String type = Build.TYPE == null
                ? ""
                : Build.TYPE.toLowerCase(Locale.US);

        boolean nonProduction =
                tags.contains("test-keys")
                || "eng".equals(type)
                || "userdebug".equals(type);

        return signal(
                "non_production_build",
                "build",
                nonProduction ? State.DETECTED : State.CLEAR,
                Strength.MEDIUM
        );
    }

    // ---------------------------------------------------------
    // PROCESS MEMORY MAPS
    // ---------------------------------------------------------

    private Signal checkProcessMaps() {
        try (BufferedReader reader = new BufferedReader(
                new FileReader("/proc/self/maps"))) {

            String line;
            int count = 0;

            while ((line = reader.readLine()) != null
                    && count++ < MAX_MAP_LINES) {

                if (containsInstrumentationMarker(line)) {
                    return signal(
                            "instrumentation_map",
                            "instrumentation",
                            State.DETECTED,
                            Strength.HIGH
                    );
                }
            }

            return signal(
                    "instrumentation_map",
                    "instrumentation",
                    State.CLEAR,
                    Strength.HIGH
            );

        } catch (Exception ignored) {
            return signal(
                    "instrumentation_map",
                    "instrumentation",
                    State.UNAVAILABLE,
                    Strength.HIGH
            );
        }
    }

    private Signal checkFrameworkMaps() {
        try (BufferedReader reader = new BufferedReader(
                new FileReader("/proc/self/maps"))) {

            String line;
            int count = 0;

            while ((line = reader.readLine()) != null
                    && count++ < MAX_MAP_LINES) {

                String value = line.toLowerCase(Locale.US);

                if (containsFrameworkMarker(value)) {
                    return signal(
                            "framework_library_map",
                            "instrumentation",
                            State.DETECTED,
                            Strength.HIGH
                    );
                }
            }

            return signal(
                    "framework_library_map",
                    "instrumentation",
                    State.CLEAR,
                    Strength.HIGH
            );

        } catch (Exception ignored) {
            return signal(
                    "framework_library_map",
                    "instrumentation",
                    State.UNAVAILABLE,
                    Strength.HIGH
            );
        }
    }

    // ---------------------------------------------------------
    // FILE DESCRIPTORS
    // ---------------------------------------------------------

    private Signal checkFileDescriptors() {
        File directory = new File("/proc/self/fd");
        File[] descriptors;

        try {
            descriptors = directory.listFiles();
        } catch (SecurityException ignored) {
            descriptors = null;
        }

        if (descriptors == null) {
            return signal(
                    "instrumentation_fd",
                    "instrumentation",
                    State.UNAVAILABLE,
                    Strength.HIGH
            );
        }

        int count = 0;

        for (File descriptor : descriptors) {
            if (count++ >= MAX_FDS) {
                break;
            }

            try {
                String path = descriptor.getCanonicalPath()
                        .toLowerCase(Locale.US);

                if (containsInstrumentationMarker(path)) {
                    return signal(
                            "instrumentation_fd",
                            "instrumentation",
                            State.DETECTED,
                            Strength.HIGH
                    );
                }
            } catch (Exception ignored) {
                // File descriptors can disappear during enumeration.
            }
        }

        return signal(
                "instrumentation_fd",
                "instrumentation",
                State.CLEAR,
                Strength.HIGH
        );
    }

    // ---------------------------------------------------------
    // THREAD DETECTION
    // ---------------------------------------------------------

    private Signal checkThreadNames() {
        File directory = new File("/proc/self/task");
        File[] tasks;

        try {
            tasks = directory.listFiles();
        } catch (SecurityException ignored) {
            tasks = null;
        }

        if (tasks == null) {
            return signal(
                    "instrumentation_thread",
                    "instrumentation",
                    State.UNAVAILABLE,
                    Strength.HIGH
            );
        }

        int count = 0;

        for (File task : tasks) {
            if (count++ >= MAX_TASKS) {
                break;
            }

            try (BufferedReader reader = new BufferedReader(
                    new FileReader(new File(task, "comm")))) {

                String name = reader.readLine();

                if (name == null) {
                    continue;
                }

                String value = name.trim().toLowerCase(Locale.US);

                if (containsInstrumentationMarker(value)
                        || value.contains("pool-frida")
                        || value.contains("gmain-frida")) {

                    return signal(
                            "instrumentation_thread",
                            "instrumentation",
                            State.DETECTED,
                            Strength.HIGH
                    );
                }

            } catch (Exception ignored) {
                // Threads can terminate while being enumerated.
            }
        }

        return signal(
                "instrumentation_thread",
                "instrumentation",
                State.CLEAR,
                Strength.HIGH
        );
    }

    // ---------------------------------------------------------
    // XPOSED / LSPOSED RUNTIME
    // ---------------------------------------------------------

    private Signal checkXposedRuntime() {
        String[] classNames = {
                "de.robv.android.xposed.XposedBridge",
                "de.robv.android.xposed.XposedHelpers"
        };

        Set<ClassLoader> loaders = new LinkedHashSet<>();

        loaders.add(getClass().getClassLoader());

        ClassLoader contextLoader =
                Thread.currentThread().getContextClassLoader();

        if (contextLoader != null) {
            loaders.add(contextLoader);
        }

        try {
            if (cordova != null && cordova.getActivity() != null) {
                ClassLoader activityLoader =
                        cordova.getActivity().getClassLoader();

                if (activityLoader != null) {
                    loaders.add(activityLoader);
                }
            }
        } catch (RuntimeException ignored) {
            // Activity may be unavailable during lifecycle changes.
        }

        for (ClassLoader loader : loaders) {
            if (loader == null) {
                continue;
            }

            for (String className : classNames) {
                try {
                    Class.forName(className, false, loader);

                    return signal(
                            "xposed_bridge_class",
                            "instrumentation",
                            State.DETECTED,
                            Strength.HIGH
                    );

                } catch (ClassNotFoundException ignored) {
                    // Not visible through this loader.
                } catch (LinkageError ignored) {
                    // A linkage failure alone is inconclusive.
                } catch (SecurityException ignored) {
                    // Restricted access is not proof of compromise.
                }
            }
        }

        return signal(
                "xposed_bridge_class",
                "instrumentation",
                State.CLEAR,
                Strength.HIGH
        );
    }

    // ---------------------------------------------------------
    // MOUNT TABLE
    // ---------------------------------------------------------

    private Signal checkMountInfo() {
        try (BufferedReader reader = new BufferedReader(
                new FileReader("/proc/self/mountinfo"))) {

            String line;
            int count = 0;

            while ((line = reader.readLine()) != null
                    && count++ < 4096) {

                String value = line.toLowerCase(Locale.US);

                if (value.contains("zygisk")
                        || value.contains("lsposed")
                        || value.contains("riru_core")
                        || value.contains("liblspd")) {

                    return signal(
                            "framework_mount_marker",
                            "instrumentation",
                            State.DETECTED,
                            Strength.HIGH
                    );
                }
            }

            return signal(
                    "framework_mount_marker",
                    "instrumentation",
                    State.CLEAR,
                    Strength.HIGH
            );

        } catch (Exception ignored) {
            return signal(
                    "framework_mount_marker",
                    "instrumentation",
                    State.UNAVAILABLE,
                    Strength.HIGH
            );
        }
    }

    // ---------------------------------------------------------
    // FRIDA PROTOCOL
    // ---------------------------------------------------------

    private Signal checkFridaProtocol() {
        Set<Integer> ports = new LinkedHashSet<>();

        ports.add(27042);
        ports.add(27043);
        ports.add(27044);
        ports.add(27045);

        addListeningPorts("/proc/self/net/tcp", ports);
        addListeningPorts("/proc/self/net/tcp6", ports);

        boolean unknownPortResponded = false;

        for (int port : ports) {
            boolean knownFridaPort =
                    port >= 27042 && port <= 27045;

            try (Socket socket = new Socket()) {
                socket.connect(
                        new InetSocketAddress("127.0.0.1", port),
                        SOCKET_TIMEOUT_MS
                );

                socket.setSoTimeout(SOCKET_TIMEOUT_MS);

                OutputStream output = socket.getOutputStream();

                output.write(new byte[]{0});
                output.write(
                        "AUTH\r\n".getBytes(StandardCharsets.US_ASCII)
                );
                output.flush();

                InputStream input = socket.getInputStream();

                byte[] response = new byte[96];
                int length = input.read(response);

                if (length > 0) {
                    String banner = new String(
                            response,
                            0,
                            length,
                            StandardCharsets.US_ASCII
                    ).toUpperCase(Locale.US);

                    if (banner.contains("REJECTED")
                            || banner.contains("AGREE")
                            || banner.contains("OK")) {

                        return signal(
                                "frida_protocol",
                                "instrumentation",
                                State.DETECTED,
                                knownFridaPort
                                        ? Strength.HIGH
                                        : Strength.MEDIUM
                        );
                    }

                    unknownPortResponded = true;
                }

            } catch (Exception ignored) {
                // Closed ports and timeouts are not evidence.
            }
        }

        // An open local port alone is not evidence of Frida.
        return signal(
                "frida_protocol",
                "instrumentation",
                unknownPortResponded
                        ? State.UNAVAILABLE
                        : State.CLEAR,
                Strength.MEDIUM
        );
    }

    private void addListeningPorts(
            String path,
            Set<Integer> ports
    ) {
        try (BufferedReader reader = new BufferedReader(
                new FileReader(path))) {

            String line;
            int count = 0;

            while ((line = reader.readLine()) != null
                    && count++ < MAX_TCP_LINES
                    && ports.size() < MAX_PORTS) {

                String[] columns = line.trim().split("\\s+");

                if (columns.length < 4
                        || !"0A".equals(columns[3])) {
                    continue;
                }

                String[] address = columns[1].split(":");

                if (address.length != 2) {
                    continue;
                }

                int port = Integer.parseInt(address[1], 16);

                if (port > 1024 && port <= 65535) {
                    ports.add(port);
                }
            }

        } catch (Exception ignored) {
            // Procfs visibility varies by Android version.
        }
    }

    // ---------------------------------------------------------
    // INDICATOR CLASSIFICATION
    // ---------------------------------------------------------

    private boolean containsInstrumentationMarker(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }

        String normalized = value.toLowerCase(Locale.US);

        return normalized.contains("frida")
                || normalized.contains("gum-js")
                || normalized.contains("linjector")
                || normalized.contains("/re.frida.")
                || normalized.contains("zygisk")
                || normalized.contains("lsposed")
                || normalized.contains("liblspd")
                || normalized.contains("liblsplant")
                || normalized.contains("xposed")
                || normalized.contains("edxposed")
                || normalized.contains("riru")
                || normalized.contains("substrate")
                || normalized.contains("sandhook")
                || normalized.contains("yahfa")
                || normalized.contains("dobby")
                || normalized.contains("shadowhook");
    }

    private boolean containsFrameworkMarker(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }

        String normalized = value.toLowerCase(Locale.US);

        return normalized.contains("zygisk")
                || normalized.contains("lsposed")
                || normalized.contains("liblspd")
                || normalized.contains("liblsplant")
                || normalized.contains("libxposed")
                || normalized.contains("edxposed")
                || normalized.contains("riru_core");
    }

    private Signal signal(
            String id,
            String category,
            State state,
            Strength strength
    ) {
        return new Signal(id, category, state, strength);
    }

    // ---------------------------------------------------------
    // JSON DIAGNOSTICS
    // ---------------------------------------------------------

    private JSONObject toJson(Assessment assessment) {
        JSONObject result = new JSONObject();

        JSONArray evidence = new JSONArray();
        JSONArray unavailable = new JSONArray();
        JSONArray unknownReasons = new JSONArray();

        try {
            for (String reason : assessment.unknownReasons) {
                unknownReasons.put(reason);
            }

            for (Signal signal : assessment.signals) {
                if (signal.state == State.DETECTED) {
                    evidence.put(signal.id);
                }

                if (signal.state == State.UNAVAILABLE) {
                    unavailable.put(signal.id);
                }
            }

            result.put("status", assessment.status);
            result.put("statusName", statusName(assessment.status));
            result.put("platform", "android");
            result.put("osVersion", Build.VERSION.RELEASE);
            result.put("apiLevel", Build.VERSION.SDK_INT);
            result.put("evidence", evidence);
            result.put("unavailableChecks", unavailable);
            result.put("unknownReasons", unknownReasons);
            result.put("localOnly", true);

        } catch (JSONException ignored) {
            // All values are JSON-compatible.
        }

        return result;
    }

    private String statusName(int status) {
        if (status == COMPROMISED) {
            return "COMPROMISED";
        }

        if (status == UNKNOWN) {
            return "UNKNOWN";
        }

        return "SAFE";
    }
}
