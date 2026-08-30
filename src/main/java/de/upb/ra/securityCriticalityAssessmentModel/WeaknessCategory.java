package de.upb.ra.securityCriticalityAssessmentModel;

import lombok.Data;

@Data
public class WeaknessCategory {
    // Name of the weakness category
    private final String categoryName;

    // Low level measure, i.e. WiSeM measure grouped by related CWEs that belongs to this weakness category
    private final LowLevelMeasure lowLevelMeasure;

    // Impact of this weakness category to each of the security characteristics (CIA)
    private final ImpactScore securityCharacteristicsImpactScore;
    //TODO: add list of CWEs that comes under this property

    public double getWeaknessCategoryRating() {
        return lowLevelMeasure.getNormalizedSecurityExposureScore();
    }
}
