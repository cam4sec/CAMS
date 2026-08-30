package de.upb.ra.data.appConfigModel;

import lombok.Data;

@Data
public class RoleRanks {
    private int source;
    private int sink;
    private int propagator;
    private int sanitizer;
}
