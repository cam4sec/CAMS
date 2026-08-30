package de.upb.ra.data.appConfigModel;

import lombok.Data;

import java.util.List;

@Data
public class SrmSources {
    private List<CustomSource> customSources;
    private boolean ignoreDefaultSrms;
    private boolean ignoreDefaultAnnotationSrms;
}
