package de.upb.ra.data.appConfigModel;

import lombok.Data;

import java.util.List;

@Data
public class SecurityAssessmentConfig {
    private String weaknessCategoriesInfoPath;
    private SrmSources srmSources;
    private CIAWeights ciaWeights;
    private RoleRanks roleRanks;
    private List<String> criticalityLevels;
}
