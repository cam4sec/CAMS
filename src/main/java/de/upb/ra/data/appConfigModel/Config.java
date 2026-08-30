package de.upb.ra.data.appConfigModel;

import lombok.Data;

@Data
public class Config {
    private AppConfiguration appConfiguration;
    private SecurityAssessmentConfig securityAssessmentConfig;
}
