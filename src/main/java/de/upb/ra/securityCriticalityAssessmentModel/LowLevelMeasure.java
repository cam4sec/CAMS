package de.upb.ra.securityCriticalityAssessmentModel;

import de.upb.ra.metrics.WiSeM;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import lombok.val;

import java.util.List;

@Data
public class LowLevelMeasure {
    private final List<WiSeM> wiSeMS;
    @Getter
    @Setter
    private double normalizedSecurityExposureScore = 0.0;

    public double getSecurityExposureScore() {
        return getWeightedSrmFrequency();
    }

    public double getLogNormalizedSecurityExposureScore() {
        val weightedSrmFrequency = getWeightedSrmFrequency();

        if (weightedSrmFrequency == 0.0) {
            return 0.0;
        }

        return Math.log(getSecurityExposureScore());
    }

    public double getWeightedSrmFrequency() {
        val res = wiSeMS.stream()
                .mapToDouble(srm -> srm.getTaintSpecificAggregatedWeight().weight() * srm.getCweSpecificAggregatedWeight())
                .sum();

        return res;
    }

    public int getSourceFreq() {
        return (int) wiSeMS.stream()
                .map(invokedSrm -> invokedSrm.getTaintSpecificAggregatedWeight().srmCategory())
                .filter("SOURCE"::equalsIgnoreCase)
                .count();
    }

    public int getSinkFreq() {
        return (int) wiSeMS.stream()
                .map(invokedSrm -> invokedSrm.getTaintSpecificAggregatedWeight().srmCategory())
                .filter("SINK"::equalsIgnoreCase)
                .count();
    }

    public int getSanitizerFreq() {
        return (int) wiSeMS.stream()
                .map(invokedSrm -> invokedSrm.getTaintSpecificAggregatedWeight().srmCategory())
                .filter("SANITIZER"::equalsIgnoreCase)
                .count();
    }

    public int getPropagatorFreq() {
        return (int) wiSeMS.stream()
                .map(invokedSrm -> invokedSrm.getTaintSpecificAggregatedWeight().srmCategory())
                .filter("PROPAGATOR"::equalsIgnoreCase)
                .count();
    }
}
