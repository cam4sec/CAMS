package de.upb.ra.securityCriticalityAssessmentModel;

import lombok.Data;
import lombok.val;

/**
 * Security Critical Assessment Model (SCAM)
 *
 * @author Ranjith Krishnamurthy
 */
@Data
public class CAMS {
    private final SecurityCharacteristics securityCharacteristics;

    public double getRawWSRMF() {
        return securityCharacteristics.getRawWiSeM();
    }

    public double getSCIScore(double confidentialityWeight,
                              double integrityWeight,
                              double availabilityWeight
    ) {
        val summedWeight = confidentialityWeight + integrityWeight + availabilityWeight;

        if (summedWeight == 0) {
            return 0.0;
        }

        return ((securityCharacteristics.getConfidentialityRating() * confidentialityWeight) +
                (securityCharacteristics.getIntegrityRating() * integrityWeight) +
                (securityCharacteristics.getAvailabilityRating() * availabilityWeight)) / summedWeight;
    }
}