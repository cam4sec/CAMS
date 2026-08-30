package de.upb.ra.securityCriticalityAssessmentModel;

import de.upb.ra.metrics.WiSeM;
import lombok.Data;
import lombok.val;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Data
public class SecurityCharacteristics {
    private final Map<String, WeaknessCategory> weaknessCategories;
    private final Set<String> weaknessCategoriesName;
    private final Map<String, ImpactScore> weaknessCategoriesImpactScore;

    public double getRawWiSeM() {
        val allSrms = new HashSet<WiSeM>();
        for (val weaknessCategory : weaknessCategories.values()) {
            allSrms.addAll(weaknessCategory.getLowLevelMeasure().getWiSeMS());
        }

        return allSrms.stream()
                .mapToDouble(srm -> srm.getTaintSpecificAggregatedWeight().weight() * srm.getCweSpecificAggregatedWeight())
                .sum();
    }

    public double getConfidentialityRating() {
        double rating = 0.0;
        double addedWeights = 0.0;

//        if (weaknessCategories.size() == 1) {
//            val prop = weaknessCategories.entrySet().iterator().next().getValue();
//            val impactScore = prop.getSecurityCharacteristicsImpactScore().getConfidentialityImpactScore();
//            val propRating = prop.getPropertyRating();
//
//            return propRating * impactScore;
//        }

        for (val weaknessCategory : weaknessCategories.values()) {
            val impactScore = weaknessCategory.getSecurityCharacteristicsImpactScore().confidentialityImpactScore();
            rating += weaknessCategory.getWeaknessCategoryRating() * impactScore;
//            addedWeights += prop.getSecurityCharacteristicsImpactScore().getConfidentialityImpactScore();
        }

        for (val weaknessCategoriesNam : weaknessCategoriesName) {
            addedWeights += weaknessCategoriesImpactScore.get(weaknessCategoriesNam).confidentialityImpactScore();
        }

        return rating / addedWeights;
    }

    public double getIntegrityRating() {
        double rating = 0.0;
        double addedWeights = 0.0;

//        if (weaknessCategories.size() == 1) {
//            val prop = weaknessCategories.entrySet().iterator().next().getValue();
//            val impactScore = prop.getSecurityCharacteristicsImpactScore().getIntegrityImpactScore();
//            val propRating = prop.getPropertyRating();
//
//            return propRating * impactScore;
//        }

        for (val weaknessCategory : weaknessCategories.values()) {
            val impactScore = weaknessCategory.getSecurityCharacteristicsImpactScore().integrityImpactScore();
            rating += weaknessCategory.getWeaknessCategoryRating() * impactScore;
//            addedWeights += prop.getSecurityCharacteristicsImpactScore().getIntegrityImpactScore();
        }

        for (val categoryName : weaknessCategoriesName) {
            addedWeights += weaknessCategoriesImpactScore.get(categoryName).integrityImpactScore();
        }

        return rating / addedWeights;
    }

    public double getAvailabilityRating() {
        double rating = 0.0;
        double addedWeights = 0.0;

//        if (weaknessCategories.size() == 1) {
//            val prop = weaknessCategories.entrySet().iterator().next().getValue();
//            val impactScore = prop.getSecurityCharacteristicsImpactScore().getAvailabilityImpactScore();
//            val propRating = prop.getPropertyRating();
//
//            return propRating * impactScore;
//        }

        for (val weaknessCategory : weaknessCategories.values()) {
            val impactScore = weaknessCategory.getSecurityCharacteristicsImpactScore().availabilityImpactScore();
            rating += weaknessCategory.getWeaknessCategoryRating() * impactScore;
//            addedWeights += prop.getSecurityCharacteristicsImpactScore().getAvailabilityImpactScore();
        }

        for (val categoryName : weaknessCategoriesName) {
            addedWeights += weaknessCategoriesImpactScore.get(categoryName).availabilityImpactScore();
        }

        return rating / addedWeights;
    }
}
