package de.upb.ra.metrics;

import lombok.Data;
import lombok.val;

import java.util.*;

@Data
public class WiSeM {
    private final String invokedMethodSignature;
    private final Set<TaintSpecificScoredSrm> taintSpecificScoredSrms;  // This provides weight of the SRM role
    private final Set<CweSpecificScoredSrm> cweSpecificScoredSrms;      // This provides weight of the CWE severity score
    private double taintSpecificAggregatedWeight;
    private double cweSpecificAggregatedWeight;

    public AggregatedSrm getTaintSpecificAggregatedWeight() {
        val res = taintSpecificScoredSrms.stream()
                .map(srm -> new AggregatedSrm(
                        srm.getTaintSpecificSrm().getSrmCategory(),
                        srm.getTaintSpecificSrm().getSrmWeight() * srm.getConfidenceScore()))
                .max(Comparator.comparingDouble(AggregatedSrm::weight))
                .orElse(new AggregatedSrm("No Category", 0.0));

        if (res.srmCategory().equalsIgnoreCase("PROPAGATOR")) {
            return new AggregatedSrm("No Category", 0.0);
        }

        return res;
    }

    public double getCweSpecificAggregatedWeight() {
        return cweSpecificScoredSrms.stream()
                .mapToDouble(srm -> srm.getCweSpecificSrm().getCweWeight() * srm.getConfidenceScore())
                .max()
                .orElse(0.0);
    }

    public String getWeaknessCategoryForTheCwe(Map<String, String> cweToWeaknessCategoryMap) {
        val cwe = cweSpecificScoredSrms.stream().findFirst().get().getCweSpecificSrm().getCweName();

        return cweToWeaknessCategoryMap.get(cwe);
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new HashMap<>();
        map.put("methodSignature", invokedMethodSignature);
        map.put("taintSpecificAggregatedWeight", taintSpecificAggregatedWeight);
        map.put("cweSpecificAggregatedWeight", cweSpecificAggregatedWeight);
        map.put("taintSpecificScoredSrms", new ArrayList<>(taintSpecificScoredSrms));
        map.put("cweSpecificScoredSrms", new ArrayList<>(cweSpecificScoredSrms));
        return map;
    }
}
