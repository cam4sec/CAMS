package de.upb.ra.securityCriticalityAssessmentModel;

public record ImpactScore(double confidentialityImpactScore,
                          double integrityImpactScore,
                          double availabilityImpactScore
) { }
