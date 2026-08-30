package de.upb.ra.metrics;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Getter;
import lombok.val;

import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;

@Getter
@JsonFormat(shape = JsonFormat.Shape.OBJECT)
public enum TaintSpecificSrm {
    SOURCE("SOURCE"),       // Gets the second-highest weight
    SINK("SINK"),         // Gets the highest weight
    SANITIZER("SANITIZER"),    // Gets the third-highest weight
    PROPAGATOR("PROPAGATOR");    // Gets the second-highest weight

    private final String srmCategory;

    TaintSpecificSrm(String srmCategory) {
        this.srmCategory = srmCategory;
    }

    public double getSrmWeight() {
        return switch (this) {
            case SOURCE -> TaintSpecificSrmUtil.getSourceWeight();
            case SINK -> TaintSpecificSrmUtil.getSinkWeight();
            case SANITIZER -> TaintSpecificSrmUtil.getSanitizerWeight();
            case PROPAGATOR -> TaintSpecificSrmUtil.getPropagatorWeight();
        };
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new HashMap<>();
        map.put("srmCategory", srmCategory);
        return map;
    }

    public static void updateRank(int sourceRank, int sinkRank, int sanitizerRank, int propagatorRank) {
        TaintSpecificSrmUtil.updateRank(sourceRank, sinkRank, sanitizerRank, propagatorRank);
    }
}

class TaintSpecificSrmUtil {
    public static int sourceRank = 2;
    public static int sinkRank = 1;
    public static int propagatorRank = 4;
    public static int sanitizerRank = 3;

    public static void updateRank(int sourceRank, int sinkRank, int sanitizerRank, int propagatorRank) {
        TaintSpecificSrmUtil.sourceRank = sourceRank;
        TaintSpecificSrmUtil.sinkRank = sinkRank;
        TaintSpecificSrmUtil.propagatorRank = propagatorRank;
        TaintSpecificSrmUtil.sanitizerRank = sanitizerRank;
    }

    public static double getSourceWeight() {
        val smartSmartedWeights = getSmartSmarterWeights();

        return smartSmartedWeights.get(sourceRank);
    }

    public static double getSinkWeight() {
        val smartSmartedWeights = getSmartSmarterWeights();
        return smartSmartedWeights.get(sinkRank);
    }

    public static double getPropagatorWeight() {
        val smartSmartedWeights = getSmartSmarterWeights();
        return smartSmartedWeights.get(propagatorRank);
    }

    public static double getSanitizerWeight() {
        val smartSmartedWeights = getSmartSmarterWeights();
        return smartSmartedWeights.get(sanitizerRank);
    }

    private static Map<Integer, Double> getSmartSmarterWeights() {
        val temp = Arrays.asList(sourceRank, sinkRank, sanitizerRank, propagatorRank);
        temp.sort(Comparator.naturalOrder());
        var numOfUniqueRankElements = temp.get(temp.size() - 1);

        if (propagatorRank == 0) {
            numOfUniqueRankElements = temp.get(temp.size() - 1) + 1;
        }

        val TwoElemWeights = Map.ofEntries(
                Map.entry(0, 0.0),
                Map.entry(1, 7.500),
                Map.entry(2, 2.500)
        );

        val ThreeElemWeights = Map.ofEntries(
                Map.entry(0, 0.0),
                Map.entry(1, 6.111),
                Map.entry(2, 2.778),
                Map.entry(3, 1.111)
        );

        val FourElemWeights = Map.ofEntries(
                Map.entry(0, 0.0),
                Map.entry(1, 5.208),
                Map.entry(2, 2.708),
                Map.entry(3, 1.458),
                Map.entry(4, 0.625)
        );

        if (numOfUniqueRankElements == 2) {
            return TwoElemWeights;
        }

        if (numOfUniqueRankElements == 3) {
            if (propagatorRank == 0) {
                return TwoElemWeights;
            }
            return ThreeElemWeights;
        }

        if (propagatorRank == 0) {
            return ThreeElemWeights;
        }

        return FourElemWeights;
    }
}
