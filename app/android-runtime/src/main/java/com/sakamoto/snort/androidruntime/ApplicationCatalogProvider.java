package com.sakamoto.snort.androidruntime;

import java.util.List;

/** Backend-owned source of Android application instances. UI never owns this database. */
public interface ApplicationCatalogProvider {
    List<ApplicationCatalogEntry> listApplications();
}
