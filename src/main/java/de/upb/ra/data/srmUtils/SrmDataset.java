package de.upb.ra.data.srmUtils;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
public class SrmDataset {
    private String version;
    private List<SrmMethodInfo> methods;
}