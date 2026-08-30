package de.upb.ra.metrics;

import lombok.Data;

@Data
public class CweSpecificSrm {
    private final String cweName;
    private final double cweWeight;
}
