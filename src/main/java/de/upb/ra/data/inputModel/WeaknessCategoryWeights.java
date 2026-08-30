package de.upb.ra.data.inputModel;

import lombok.Data;

import java.util.List;

@Data
public class WeaknessCategoryWeights {
    private String category_name;
    private double confidentiality_impact;
    private double integrity_impact;
    private double availability_impact;
    private List<CweWeight> cwe_weights;
}
