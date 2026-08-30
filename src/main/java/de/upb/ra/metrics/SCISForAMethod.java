package de.upb.ra.metrics;

import de.upb.ra.data.appConfigModel.CIAWeights;
import de.upb.ra.securityCriticalityAssessmentModel.CAMS;
import lombok.Data;
import lombok.Setter;

@Data
public class SCISForAMethod {
    private final String applicationMethodSignature;

    private final CAMS CAMS;

    @Setter
    private double minMaxNormValue = -9.9;

    public double getSCIScore(CIAWeights weights) {
        return CAMS.getSCIScore(
                weights.getConfidentiality(),
                weights.getIntegrity(),
                weights.getAvailability()
        );
    }
}
