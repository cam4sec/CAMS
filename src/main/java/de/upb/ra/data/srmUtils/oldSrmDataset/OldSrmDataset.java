package de.upb.ra.data.srmUtils.oldSrmDataset;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
public class OldSrmDataset {
    private String version;
    private List<OldSrmMethodInfo> methods;
}