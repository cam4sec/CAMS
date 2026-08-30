package de.upb.ra.data.appConfigModel;

import lombok.Data;

@Data
public class CustomSource {
    private int priority;
    private String path;
    private String type; // Enum could be used here if SECUCHECK or SWAN are fixed
}
