package de.upb.ra.metrics;

import lombok.Data;

import java.util.HashMap;
import java.util.Map;

@Data
public class CweSpecificScoredSrm {
    private final CweSpecificSrm cweSpecificSrm;
    private final double confidenceScore;

    public Map<String, Object> toMap() {
        Map<String, Object> map = new HashMap<>();
        map.put("cweSpecificSrm", cweSpecificSrm);
        map.put("confidenceScore", confidenceScore);
        return map;
    }
}
