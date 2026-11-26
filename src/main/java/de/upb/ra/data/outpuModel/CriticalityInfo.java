package de.upb.ra.data.outpuModel;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CriticalityInfo {
    private String methodSignature;
    private double scis;
    private Map<String, Double> categoryRatings;
    private String criticalityLevel;
    private List<InvokedSrmInfo> invokedSrms;

    public Map<String, Object> toMap() {
        Map<String, Object> map = new LinkedHashMap<>();  // Use LinkedHashMap to preserve order
        map.put("methodSignature", methodSignature);
        map.put("scis", scis);
        map.put("categoryRatings", categoryRatings);
        map.put("criticalityLevel", criticalityLevel);
        map.put("invokedSrms", invokedSrms);
        return map;
    }
}
