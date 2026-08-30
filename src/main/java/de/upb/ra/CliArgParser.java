package de.upb.ra;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.fraunhofer.iem.JimpleProviderBuilder;
import de.upb.ra.data.inputModel.WeaknessCategoryWeights;
import de.upb.ra.data.appConfigModel.Config;
import de.upb.ra.data.appConfigModel.ConfigLoader;
import de.upb.ra.data.appConfigModel.SrmSources;
import de.upb.ra.metrics.WiSeM;
import de.upb.ra.securityCriticalityAssessmentModel.ImpactScore;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.*;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.Callable;

/**
 * Command Line Arguments parser for Picocli.
 * The main logic of the app starts from the run method.
 *
 * @author Ranjith K
 */
@Slf4j
@Command(name = "cams", mixinStandardHelpOptions = true, version = "cams 0.1",
        description = "Criticality Assessment Model for SECurity: Security Critical Indicator")
public class CliArgParser implements Callable<Integer> {
    @Option(
            names = {"-c", "--config-path"},
            description = "Configuration file path in YAML format.",
            required = true
    )
    private File configPath;

    private final Map<Integer, Map<String, WiSeM>> prioritizedOptimizedSrmMethodInfoMap = new HashMap<>();

    private final Map<String, ImpactScore> impactScoreMap = new HashMap<>();

    private final Map<String, Double> cweWeightsMap = new HashMap<>();

    private final Set<String> weaknessCategories = new HashSet<>();

    private final Map<String, String> cweToCategoryMap = new HashMap<>();

    /**
     * First parses the command line arguments and then kicks off the main logic of the app.
     *
     * @return Return Code, 0 mean success.
     * @throws Exception Exception if fails to parse the command line arguments.
     */
    @Override
    public Integer call() throws Exception {
        log.info("Reading the given configuration file");
        val config = ConfigLoader.load(configPath);

        log.info("Parsing the given arguments...");
        int parseCode = parseArgs(config);

        if (parseCode != 0) {
            return parseCode;
        }

        log.info("Loading the given app class path to the JimpleProvider");
        long startTime = System.nanoTime();
        val jimpleProviderBuilder = new JimpleProviderBuilder();
        val jimpleProvider = jimpleProviderBuilder
                .appClassPath(new File(config.getAppConfiguration().getAppClassPath()).getAbsolutePath())
                .build();
        long endTime = System.nanoTime();
        long duration = endTime - startTime;
        log.info("Time taken (nanoseconds) for jimple provider only: {}", duration);
        log.info("Time taken (milliseconds): {}", duration / 1_000_000);


        val secuMetricsConfig = CAMSConfiguration.builder()
                .jimpleProvider(jimpleProvider)
                .appClassPath(new File(config.getAppConfiguration().getAppClassPath()))
                .outputRootDirectory(new File(config.getAppConfiguration().getOutputRootDir()))
                .prioritizedOptimizedSrmMethodInfoMap(this.prioritizedOptimizedSrmMethodInfoMap)
                .impactScoreMap(Map.copyOf(this.impactScoreMap))
                .cweWeightsMap(Map.copyOf(this.cweWeightsMap))
                .weaknessCategories(this.weaknessCategories)
                .cweToWeaknessCategoryMap(this.cweToCategoryMap)
                .rootPackage(config.getAppConfiguration().getAppRootPackage())
                .ciaWeights(config.getSecurityAssessmentConfig().getCiaWeights())
                .criticalityLevels(config.getSecurityAssessmentConfig().getCriticalityLevels())
                .isIgnoreDefaultAnnotationSrms(config.getSecurityAssessmentConfig().getSrmSources().isIgnoreDefaultAnnotationSrms())
                .build();

        val combinedSrmMethodInfoMap = new HashMap<String, WiSeM>();

        for (val entry : this.prioritizedOptimizedSrmMethodInfoMap.entrySet()) {
            // Get the inner map and merge it into the combined map
            combinedSrmMethodInfoMap.putAll(entry.getValue());
        }

        log.info("Total srm method info size: {}", combinedSrmMethodInfoMap.size());
        // AllMethodSaver.saveMethodsIntoTwoCategories(jimpleProvider, combinedSrmMethodInfoMap);

        val additionalInfo = new HashMap<Object, Object>();
        additionalInfo.put("Srms", combinedSrmMethodInfoMap);
        additionalInfo.put("totalNumberOfSrm", combinedSrmMethodInfoMap.size());
        FileUtils.writeToJsonFile(
                new File(config.getAppConfiguration().getOutputRootDir(), "additional_info.json"),
                additionalInfo
        );

        new CAMSRunner(secuMetricsConfig).run();

        long endTime_1 = System.nanoTime();
        long duration_1 = endTime_1 - startTime;
        log.info("Time taken (nanoseconds) for complete steps: {}", duration_1);
        log.info("Time taken (milliseconds): {}", duration_1 / 1_000_000);

        return 0;
    }

    /**
     * Parses the given command line arguments and validates the arguments.
     *
     * @return Returns 0 if successful otherwise 1
     */
    public int parseArgs(Config config) {
        log.info("Verifying the given app class path existence.");
        val appClassFile = new File(config.getAppConfiguration().getAppClassPath());
        if (!isDirectoryExist(appClassFile, false)) {
            return 1;
        }

        log.info("Verifying the given output root directory existence.");
        val outputRootDirFile = new File(config.getAppConfiguration().getOutputRootDir());
        if (!isDirectoryExist(outputRootDirFile, true)) {
            return 1;
        }

        if (config.getSecurityAssessmentConfig().getWeaknessCategoriesInfoPath().endsWith(".json")) {
            // Already generated weakness categories and its weights.
            val objectMapper = new ObjectMapper();
            try {
                // Path to your JSON file
                File file = new File(config.getSecurityAssessmentConfig().getWeaknessCategoriesInfoPath());

                // Deserialize JSON into Weakness Categories object
                List<WeaknessCategoryWeights> items = objectMapper.readValue(
                        file, new com.fasterxml.jackson.core.type.TypeReference<List<WeaknessCategoryWeights>>(){}
                );

                storeGivenWeights(items);

            } catch (IOException e) {
                log.error("Failed to read the provided Weakness Categories file " + e.getMessage());
                System.exit(1);
            }
        }


        if (config.getSecurityAssessmentConfig().getSrmSources().getCustomSources() != null) {
            addCustomSrmSources(config.getSecurityAssessmentConfig().getSrmSources());
        }

        if (!config.getSecurityAssessmentConfig().getSrmSources().isIgnoreDefaultSrms()) {
            log.info("Loading the default Srms");
            if (!addTheDefaultSrms()) {
                log.error("Failed to load the default SRMs");
                System.exit(1);
            }
        }

        return 0;
    }

    private void addCustomSrmSources(SrmSources srmSources) {
        for (val srmSource : srmSources.getCustomSources()) {
            if (srmSource.getType().equalsIgnoreCase("secucheck")) {
                addSecuCheckSrmSources(srmSource.getPath());
            } else if (srmSource.getType().equalsIgnoreCase("swan")) {
                val file = new File(srmSource.getPath());
                try (InputStream in = new FileInputStream(file)) {
                    addTheSrmsFromSwanJson(in, file.getAbsolutePath());
                } catch (IOException e) {
                    log.error("Failed to load the SWAN SRM {}", e.getMessage());
                    System.exit(1);
                }
            }

        }
    }

    private void addSecuCheckSrmSources(String path) {
        log.info("Verifying the given secucheck srm directory existence.");
        val srmPath = new File(path);
        if (!isDirectoryExist(srmPath, false)) {
            log.error("Failed to load the SRM from because of invalid path: {}", path);
            System.exit(1);
        }

        val fluentTqlProcessor = new FluentTqlProcessor();
        if (!fluentTqlProcessor.processFluentTQLSpecificationsPath(srmPath.getAbsolutePath(), this.cweWeightsMap)) {
            log.error("Failed to load the SecuCheck SRM: {}", path);
            System.exit(1);
        }

        prioritizedOptimizedSrmMethodInfoMap.put(
                prioritizedOptimizedSrmMethodInfoMap.size() + 1,
                fluentTqlProcessor.getOptimizedSrmMethodInfoMap()
        );
    }

    private static int getKey(int priority) {
        return priority + 1;
    }

    private void storeGivenWeights(List<WeaknessCategoryWeights> weaknessCategoriesWeights) {
        for (val categoryWeight : weaknessCategoriesWeights) {
            this.weaknessCategories.add(categoryWeight.getCategory_name());

            for (val cweWeights : categoryWeight.getCwe_weights()) {
                this.cweToCategoryMap.put(cweWeights.getCwe(), categoryWeight.getCategory_name());
                this.cweWeightsMap.put(cweWeights.getCwe(), cweWeights.getPenalized_weight());
            }

            this.impactScoreMap.put(
                    categoryWeight.getCategory_name(),
                    new ImpactScore(
                            categoryWeight.getConfidentiality_impact(),
                            categoryWeight.getIntegrity_impact(),
                            categoryWeight.getAvailability_impact()
                    )
            );
        }
    }

    /**
     * Checks the given file exists, isRegular and  the extension of the file is equals to the given extension
     *
     * @param file      File to be checked
     * @param extension Extension of the file that are expected
     * @return True if all checks pass otherwise fails
     */
    private boolean isRegularFile(File file, String extension) {
        if (!file.exists()) {
            log.error("The given file does not exist: " + file.getAbsolutePath());
            return false;
        }

        if (!Files.isRegularFile(file.toPath())) {
            log.error("The given file is not a regular file: " + file.getAbsolutePath());
            return false;
        }

        if (!file.getAbsolutePath().endsWith(extension)) {
            log.error("The given file is not a Json file: " + file.getAbsolutePath());
            return false;
        }

        return true;
    }

    /**
     * Checks the given file exists, isDirectory. If the ifNotPresentCreate is true then it creates the directory if the given path does not exist.
     *
     * @param file               File that needs to be checked
     * @param ifNotPresentCreate If this is true, it creates the directory when the given path does not exist.
     * @return True if everything pass otherwise false.
     */
    private boolean isDirectoryExist(File file, boolean ifNotPresentCreate) {
        if (!file.exists()) {
            if (!ifNotPresentCreate) {
                log.error("The given directory does not exist: " + file.getAbsolutePath());
                return false;
            }

            if (!file.mkdirs()) {
                log.error("Failed to create the directory: " + file.getAbsolutePath());
                return false;
            }
        }

        if (!file.isDirectory()) {
            log.error("The given path is not a directory: " + file.getAbsolutePath());
            return false;
        }

        return true;
    }

    /**
     * Adds the default SRMs such as SRM dataset used by Swan and some of the SRM detected by SWAN on some libraries will be added to
     * prioritizedOptimizedSrmMethodInfoMap, which will be used for SCL calculation.
     *
     * @return True if successfully added otherwise false
     */
    private boolean addTheDefaultSrms() {
        String[] defaultSrmFiles = {
                "default_srms/swan_training_dataset/srm-catalog.json",
                "default_srms/swan_training_dataset/srm-owasp-benchmark-catalog.json",
                "default_srms/swan_training_dataset/srm-owasp-webgoat-catalog.json",
        };

        try {
            for (String defaultSrmFile : defaultSrmFiles) {
                try (InputStream in = getClass().getClassLoader().getResourceAsStream(defaultSrmFile)) {
                    if (!addTheSrmsFromSwanJson(in, defaultSrmFile)) {
                        return false;
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error accessing resource directory while adding default srms: {}", e.getMessage());
            e.printStackTrace();
            return false;
        }

        return true;
    }

    /**
     * Adds the default SRMs such as SRM dataset used by Swan and some of the SRM detected by SWAN on some libraries will be added to
     * prioritizedOptimizedSrmMethodInfoMap, which will be used for SCL calculation.
     *
     * @return True if successfully added otherwise false
     */
    private boolean addTheSrmsFromSwanJson(InputStream jsonFileStream, String jsonFileName) {
        try {
            if (jsonFileStream == null) {
                    log.error("Default SRM file not found: {}", jsonFileName);
                    return false;
                }

                val dataReader = new DataReader(cweWeightsMap);
                val swanDetectedSrms = dataReader.loadASwanPredictionDataFile(jsonFileName, jsonFileStream);
                prioritizedOptimizedSrmMethodInfoMap.put(
                    prioritizedOptimizedSrmMethodInfoMap.size() + 1,
                    swanDetectedSrms
                );
        } catch (Exception e) {
            log.error("Error accessing resource directory while adding default srms: {}", e.getMessage());
            e.printStackTrace();
            return false;
        }

        return true;
    }
}
