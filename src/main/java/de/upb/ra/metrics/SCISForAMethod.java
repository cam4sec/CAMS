package de.upb.ra.metrics;

import de.upb.ra.data.appConfigModel.CIAWeights;
import de.upb.ra.data.outpuModel.InvokedSrmInfo;
import de.upb.ra.securityCriticalityAssessmentModel.CAMS;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.Setter;
import lombok.ToString;

import java.util.ArrayList;
import java.util.List;

@Data
public class SCISForAMethod {
    private final String applicationMethodSignature;

    private final CAMS CAMS;

    @Setter
    private double minMaxNormValue = -9.9;

    // Every SRM call site found in this method (signature, line, roles, CWEs, category).
    // Excluded from equals/hashCode so the HashSet order of methods (and the order of tied methods) stays as before.
    @Setter
    @EqualsAndHashCode.Exclude
    @ToString.Exclude
    private List<InvokedSrmInfo> invokedSrms = new ArrayList<>();

    public double getSCIScore(CIAWeights weights) {
        return CAMS.getSCIScore(
                weights.getConfidentiality(),
                weights.getIntegrity(),
                weights.getAvailability()
        );
    }
}
