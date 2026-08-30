package de.upb.ra;

import de.fraunhofer.iem.JimpleProvider;
import de.upb.ra.data.appConfigModel.CIAWeights;
import de.upb.ra.metrics.WiSeM;
import de.upb.ra.securityCriticalityAssessmentModel.ImpactScore;
import lombok.Builder;
import lombok.Data;

import java.io.File;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Data
@Builder
public class CAMSConfiguration {
    private final JimpleProvider jimpleProvider;
    private final File outputRootDirectory;
    private final File appClassPath;
    private final Map<Integer, Map<String, WiSeM>> prioritizedOptimizedSrmMethodInfoMap;
    private final Map<String, ImpactScore> impactScoreMap;
    private final Map<String, Double> cweWeightsMap;
    private final Set<String> weaknessCategories;
    private final Map<String, String> cweToWeaknessCategoryMap;
    private final String rootPackage;
    private final CIAWeights ciaWeights;
    private final List<String> criticalityLevels;
    private final boolean isIgnoreDefaultAnnotationSrms;
}