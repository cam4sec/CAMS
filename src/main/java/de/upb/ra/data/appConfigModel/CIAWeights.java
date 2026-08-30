package de.upb.ra.data.appConfigModel;

import java.math.BigDecimal;
import java.math.RoundingMode;

import lombok.Data;

@Data
public class CIAWeights {
    private double confidentiality;
    private double integrity;
    private double availability;

    public double getConfidentiality() {
        return roundToTwoDecimalPlaces(confidentiality);
    }

    public double getIntegrity() {
        return roundToTwoDecimalPlaces(integrity);
    }

    public double getAvailability() {
        return roundToTwoDecimalPlaces(availability);
    }

    public double getWeightedSum() {
        return roundToTwoDecimalPlaces(getConfidentiality() + getIntegrity() + getAvailability());
    }

    public static double roundToTwoDecimalPlaces(double value) {
        return BigDecimal.valueOf(value).setScale(2, RoundingMode.UP).doubleValue();
    }
}
