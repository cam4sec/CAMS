package de.upb.ra.data.appConfigModel;

import lombok.Data;

@Data
public class AppConfiguration {
    private String appClassPath;
    private String outputRootDir;
    private String appRootPackage;
}
