package de.upb.ra.data.inputModel;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class CweWeight {
    private String cwe;
    private double penalized_weight;
    private int cve_count;
    private String latest_date;
    private String oldest_date;
}
