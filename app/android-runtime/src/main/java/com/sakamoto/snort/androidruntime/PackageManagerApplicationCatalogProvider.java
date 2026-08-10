package com.sakamoto.snort.androidruntime;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.LauncherActivityInfo;
import android.content.pm.LauncherApps;
import android.content.pm.PackageManager;
import android.os.Process;
import android.os.UserHandle;
import android.os.UserManager;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Android PackageManager/LauncherApps-backed catalog provider. */
public final class PackageManagerApplicationCatalogProvider implements ApplicationCatalogProvider {
    private final Context context;

    public PackageManagerApplicationCatalogProvider(Context context) {
        if (context == null) {
            throw new IllegalArgumentException("context is required");
        }
        this.context = context.getApplicationContext();
    }

    @Override
    public List<ApplicationCatalogEntry> listApplications() {
        Map<String, ApplicationCatalogEntry> bySubjectAndPackage = new LinkedHashMap<>();
        addLauncherProfiles(bySubjectAndPackage);
        addCurrentUserPackageManagerFallback(bySubjectAndPackage);
        ArrayList<ApplicationCatalogEntry> out =
                new ArrayList<>(bySubjectAndPackage.values());
        Collections.sort(out);
        return out;
    }

    private void addLauncherProfiles(Map<String, ApplicationCatalogEntry> out) {
        LauncherApps launcherApps = context.getSystemService(LauncherApps.class);
        UserManager userManager = context.getSystemService(UserManager.class);
        if (launcherApps == null || userManager == null) {
            return;
        }
        List<UserHandle> profiles;
        try {
            profiles = userManager.getUserProfiles();
        } catch (RuntimeException error) {
            return;
        }
        for (UserHandle profile : profiles) {
            List<LauncherActivityInfo> activities;
            try {
                activities = launcherApps.getActivityList(null, profile);
            } catch (RuntimeException error) {
                continue;
            }
            for (LauncherActivityInfo info : activities) {
                ApplicationInfo app = info.getApplicationInfo();
                if (app == null) {
                    continue;
                }
                add(out, app.packageName, app.uid, String.valueOf(info.getLabel()),
                        "launcher:" + app.packageName + "@u" + userId(app.uid),
                        userId(app.uid), profile.toString(), app.enabled);
            }
        }
    }

    private void addCurrentUserPackageManagerFallback(Map<String, ApplicationCatalogEntry> out) {
        PackageManager packageManager = context.getPackageManager();
        List<ApplicationInfo> apps;
        try {
            apps = packageManager.getInstalledApplications(
                    PackageManager.MATCH_DISABLED_COMPONENTS);
        } catch (RuntimeException error) {
            return;
        }
        for (ApplicationInfo app : apps) {
            String label;
            try {
                label = String.valueOf(packageManager.getApplicationLabel(app));
            } catch (RuntimeException error) {
                label = app.packageName;
            }
            add(out, app.packageName, app.uid, label,
                    "package:" + app.packageName + "@u" + userId(app.uid),
                    userId(app.uid), Process.myUserHandle().toString(), app.enabled);
        }
    }

    private static void add(Map<String, ApplicationCatalogEntry> out, String packageName,
                            int uid, String label, String iconToken, int userId,
                            String profileLabel, boolean available) {
        try {
            ApplicationSubjectId subjectId = ApplicationSubjectId.fromUid(uid);
            out.put(subjectId.encode() + "|" + packageName,
                    new ApplicationCatalogEntry(subjectId, packageName, label,
                            iconToken, userId, profileLabel, available));
        } catch (IllegalArgumentException ignored) {
            // PackageManager also reports platform/system identities. S50
            // product policy identity is intentionally Android application UID only.
        }
    }

    private static int userId(int uid) {
        return uid / ApplicationSubjectId.ANDROID_USER_OFFSET;
    }
}
