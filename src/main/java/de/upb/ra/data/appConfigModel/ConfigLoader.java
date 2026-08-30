package de.upb.ra.data.appConfigModel;

import de.upb.ra.metrics.TaintSpecificSrm;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

@Slf4j
public class ConfigLoader {
    public static Config load(File jsonFile) {
        Yaml yaml = new Yaml();

        try (InputStream input = new FileInputStream(jsonFile)) {
            return checkForMandatoryField(checkForMandatoryField(yaml.loadAs(input, Config.class)));
        } catch (Exception e) {
            log.error(e.getMessage());
            System.exit(1);
        }

        return null;
    }

    private static Config checkForMandatoryField(Config config) {
        logNullErrorAndExit(config.getAppConfiguration(), "appConfiguration");
        logNullErrorAndExit(config.getAppConfiguration().getAppClassPath(), "appConfiguration.appClassPath");
        logNullErrorAndExit(config.getAppConfiguration().getOutputRootDir(), "appConfiguration.outputRootDir");

        logNullErrorAndExit(config.getSecurityAssessmentConfig(), "securityAssessmentConfig");
        logNullErrorAndExit(config.getSecurityAssessmentConfig().getWeaknessCategoriesInfoPath(), "securityAssessmentConfig.weaknessCategoriesInfoPath");

        logNullErrorAndExit(config.getSecurityAssessmentConfig().getCriticalityLevels(), "securityAssessmentConfig.criticalityLevels");
        logNullErrorAndExit(config.getSecurityAssessmentConfig().getSrmSources(), "securityAssessmentConfig.srmSources");
        logNullErrorAndExit(config.getSecurityAssessmentConfig().getSrmSources().isIgnoreDefaultSrms(), "securityAssessmentConfig.srmSources.ignoreDefaultSrms");
        logNullErrorAndExit(config.getSecurityAssessmentConfig().getSrmSources().isIgnoreDefaultAnnotationSrms(), "securityAssessmentConfig.srmSources.ignoreDefaultAnnotationSrms");
        if (config.getSecurityAssessmentConfig().getRoleRanks() != null) {
            validateAndUpdateRoleRanks(config);
        }

        checkForCustomSources(config.getSecurityAssessmentConfig().getSrmSources());

        validateCIAWeights(config);

        return config;
    }

    private static void validateAndUpdateRoleRanks(Config config) {
        val roleRanks = config.getSecurityAssessmentConfig().getRoleRanks();
        
        // Extract the ranks into a list
        List<Integer> ranks = Arrays.asList(roleRanks.getSource(), roleRanks.getSink(), roleRanks.getSanitizer(), roleRanks.getPropagator());

        // Sort the ranks
        ranks.sort(Comparator.naturalOrder());

        // Check for consecutive order and at least two different ranks
        List<Integer> uniqueRanks = ranks.stream().distinct().sorted().toList();

        if (uniqueRanks.size() < 2) {
            log.error("There must be at least two different rank numbers.");
            System.exit(1);
        }

        if (uniqueRanks.size() == 2 && config.getSecurityAssessmentConfig().getRoleRanks().getPropagator() == 0) {
            log.error("Not possible to have two unique role ranks with a propagator as 0 rank.");
            System.exit(1);
        }

        for (int i = 0; i < uniqueRanks.size() - 1; i++) {
            if (uniqueRanks.get(i) + 1 != uniqueRanks.get(i + 1)) {
                log.error("Role ranks must be in consecutive order starting from 1 without missing any number.");
                System.exit(1);
            }
        }

        TaintSpecificSrm.updateRank(
                roleRanks.getSource(),
                roleRanks.getSink(),
                roleRanks.getSanitizer(),
                roleRanks.getPropagator()
        );
    }

    private static void validateCIAWeights(Config config) {
        val ciaWeights = config.getSecurityAssessmentConfig().getCiaWeights();

        val temp = CIAWeights.roundToTwoDecimalPlaces(Math.abs(ciaWeights.getWeightedSum() - 1.0));

        if (temp > 0.02) {
            log.error("The sum of CIA weights should be very close to 1. Current sum: {}", ciaWeights.getWeightedSum());
            System.exit(1);
        }
    }

    private static void checkForCustomSources(SrmSources srmSources) {
        val customSources = srmSources.getCustomSources();
        val isIgnoreDefaultSource = srmSources.isIgnoreDefaultSrms();

        if (customSources == null || customSources.isEmpty()) {
            if (isIgnoreDefaultSource) {
                log.error("Can not ignore default srm source without providing a custom srm source.");
                System.exit(1);
            }
        }
    }
    private static void logNullErrorAndExit(Object o, String key) {
        if (o == null) {
            log.error("{} is null and must be provided", key);
            System.exit(1);
        }
    }
}
