package de.upb.ra;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import de.upb.ra.data.outpuModel.CriticalityInfo;
import de.upb.ra.methodSigUtil.SootMethodSignatureParser;
import de.upb.ra.metrics.SCISForAllMethodsInApp;
import de.upb.ra.securityCriticalityAssessmentModel.LowLevelMeasure;
import de.upb.ra.securityCriticalityAssessmentModel.QuantileClassificationWithEqualFreq;
import de.upb.ra.securityCriticalityAssessmentModel.CAMS;
import de.upb.ra.xlsxUtils.ExcelWriter;
import lombok.extern.slf4j.Slf4j;
import lombok.val;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public class CAMSRunner {
    private final CAMSConfiguration config;

    public CAMSRunner(CAMSConfiguration secumetricsConfiguration) {
        this.config = secumetricsConfiguration;
    }

    /**
     * Runs the security critical indicator calculator
     *
     * @throws IOException Exception when it fails to read sem grep result file.
     */
    public void run() throws Exception {
        log.info("Computing the Security Critical Indicator Score...");
        val sclCalculator = new SCLCalculator(config);

        log.info("Computing WiSeM---Weighted Security-Relevant Method Frequency");
        long startTime = System.nanoTime();
        val sclForAllMethodsInAAppWithBaseScore = sclCalculator.computeWiSeM(config.getPrioritizedOptimizedSrmMethodInfoMap());

        log.info("Normalizing Security Criticality Indicator Scores (SCIS).");
        sclForAllMethodsInAAppWithBaseScore.normalizeAndGetSCIS(config.getWeaknessCategories());
        val methodToScoreMap = storeDataInExcelAndGetMap(sclForAllMethodsInAAppWithBaseScore, "result_with_only_base_metric.xlsx");
        storeRankedMethodsInDescending(sclForAllMethodsInAAppWithBaseScore, methodToScoreMap);
        printData(sclForAllMethodsInAAppWithBaseScore);

        long endTime = System.nanoTime();
        long duration = endTime - startTime;
        log.info("Time taken (nanoseconds) for computing metrics only: {}", duration);
        log.info("Time taken (milliseconds): {}", duration / 1_000_000);

        log.info("Storing the information with only base metrics to scl_with_only_base.json");
        sclCalculator.writeWiSeMsToFile(sclForAllMethodsInAAppWithBaseScore, "scl_with_only_base.json");
    }

    private void storeRankedMethodsInDescending(SCISForAllMethodsInApp SCISForAllMethodsInApp, Map<String, Double> methodToScoreMap) throws Exception {
        List<CriticalityInfo> rankedMethods = new ArrayList<>();
        List<CriticalityInfo> rankedRawWSRMF  = new ArrayList<>();
        val methodToLevelMap = QuantileClassificationWithEqualFreq.discretize(
                filterZeros(methodToScoreMap),
                config.getCriticalityLevels().size(),
                true,
                config.getCriticalityLevels()
        );

        for (val sclForAClass : SCISForAllMethodsInApp.getSclForAllClasses()) {
            for (val sclForAMethod : sclForAClass.getSclForAllMethods()) {
                val signature = sclForAMethod.getApplicationMethodSignature();
                val scis = sclForAMethod.getSCIScore(config.getCiaWeights());

                val rawWSRMF = sclForAMethod.getCAMS().getRawWSRMF();
                val weaknessCategoryRatings = new HashMap<String, Double>();
                for (val item : sclForAMethod.getCAMS().getSecurityCharacteristics().getWeaknessCategories().entrySet()) {
                    weaknessCategoryRatings.put(
                            item.getKey(),
                            item.getValue().getWeaknessCategoryRating()
                    );
                }

                rankedMethods.add(new CriticalityInfo(
                        signature,
                        scis,
                        weaknessCategoryRatings,
                        methodToLevelMap.getOrDefault(signature, "NA"))
                );
                rankedRawWSRMF.add(new CriticalityInfo(
                        signature,
                        rawWSRMF,
                        weaknessCategoryRatings,
                        methodToLevelMap.getOrDefault(signature, "NA"))
                );
            }
        }


        val sortedScis = getSortedListFromUnSortedList(rankedMethods);
        val sortedScisWithZeros = getSortedListFromUnSortedListIncludingZeros(rankedMethods);
        val sortedRawWSRMF = getSortedListFromUnSortedList(rankedRawWSRMF);

        storeValues(sortedScis, "scis_observation.yml");
        storeValues(sortedScisWithZeros, "scis_observation_incl_zeros.yml");
        storeValues(sortedRawWSRMF, "raw_wsrmf_observation.yml");
    }

    private Map<Integer, CriticalityInfo> getSortedListFromUnSortedList(List<CriticalityInfo> map) {
        val temp = map.stream()
                .filter(entry -> entry.getScis() != 0.0)
                .sorted(Comparator.comparingDouble(CriticalityInfo::getScis).reversed())
                .toList();

        val result = new LinkedHashMap<Integer, CriticalityInfo>();
        for (int i = 0; i < temp.size(); i++) {
            result.put(i + 1, temp.get(i));
        }

        return result;
    }

    private Map<Integer, CriticalityInfo> getSortedListFromUnSortedListIncludingZeros(List<CriticalityInfo> map) {
        val temp = map.stream()
                .sorted(Comparator.comparingDouble(CriticalityInfo::getScis).reversed())
                .toList();

        val result = new LinkedHashMap<Integer, CriticalityInfo>();
        for (int i = 0; i < temp.size(); i++) {
            result.put(i + 1, temp.get(i));
        }

        return result;
    }

    private Map<String, Double> filterZeros(Map<String, Double> map) {
        return map.entrySet().stream()
                .filter(entry -> entry.getValue() != 0.0)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    private void storeValues(Map<Integer, CriticalityInfo> observation, String fileName) {
        ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        try {
            System.out.println("Writing " + fileName + " to " + new File(fileName).getAbsolutePath());
            mapper.writeValue(new File(config.getOutputRootDirectory(), fileName), observation);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private Map<String, Double> storeDataInExcelAndGetMap(SCISForAllMethodsInApp SCISForAllMethodsInApp, String fileName) {
        val excelWrite = new ExcelWriter(config.getOutputRootDirectory().getAbsolutePath() + File.separator + fileName, config.getWeaknessCategories().stream().toList());
        val resultMap = new HashMap<String, Double>();

        for (val sclForAClass : SCISForAllMethodsInApp.getSclForAllClasses()) {
            for (val sclForAMethod : sclForAClass.getSclForAllMethods()) {
                val sigParser = new SootMethodSignatureParser(sclForAMethod.getApplicationMethodSignature());
                val methodName = sigParser.getClassName().split("\\.")[sigParser.getClassName().split("\\.").length - 1] + "." + sigParser.getMethodName(); // 1 item
                val scis = sclForAMethod.getSCIScore(config.getCiaWeights()); // 2 item

                resultMap.put(sclForAMethod.getApplicationMethodSignature(), scis);

                var summedLowLevelMeasure = 0.0; // 6 item

                for (val weaknessCategories : sclForAMethod.getCAMS().getSecurityCharacteristics().getWeaknessCategories().entrySet()) {
                    summedLowLevelMeasure += weaknessCategories.getValue().getLowLevelMeasure().getSecurityExposureScore();
                }

                val fqMethodSig = sigParser.getClassName() + ": " + sigParser.getReturnType() + " " + sigParser.getMethodName() + "(" + String.join(",", sigParser.getParametersType()) + ")";
                excelWrite.addDataToSheet(
                        fqMethodSig,
                        scis,
                        summedLowLevelMeasure,
                        getCategoryToLowLevelMeasure(sclForAMethod.getCAMS())
                );
            }
        }

        excelWrite.save();

        return resultMap;
    }

    private Map<String, LowLevelMeasure> getCategoryToLowLevelMeasure(CAMS cams) {
        val res = new HashMap<String, LowLevelMeasure>();

        for (val entry : cams.getSecurityCharacteristics().getWeaknessCategories().entrySet()) {
            val categoryName = entry.getKey();
            val lowLevelMeasure = entry.getValue().getLowLevelMeasure();

            res.put(categoryName, lowLevelMeasure);
        }

        return res;
    }

    private void printData(SCISForAllMethodsInApp sclForAllMethodsInAApp) {
            for (val sclForAClass : sclForAllMethodsInAApp.getSclForAllClasses()) {
                for (val sclForAMethod : sclForAClass.getSclForAllMethods()) {
                    val secChar = sclForAMethod.getCAMS().getSecurityCharacteristics();
                    // System.out.println(sclForAMethod.getApplicationMethodSignature() + "-" + secChar.getConfidentialityRating() + "-" + secChar.getIntegrityRating() + "-" + secChar.getAvailabilityRating());
                    val sigParser = new SootMethodSignatureParser(sclForAMethod.getApplicationMethodSignature());

                    //System.out.println(sigParser.getClassName().split("\\.")[sigParser.getClassName().split("\\.").length - 1] + "." + sigParser.getMethodName() + "-" + sclForAMethod.getSCIScore(config.getCiaWeights()));

//                for (val prop : secChar.getSecurityProperties().values()) {
//                    System.out.println(prop.getPropertyRating());
//                }
                }
            }
    }

    private List<String> getSortedListFromMap(Map<String, Double> map) {
        return map.entrySet()
                .stream()
                .sorted(Map.Entry.<String, Double>comparingByValue(Comparator.reverseOrder()))
                .map(Map.Entry::getKey)  // only take the key
                .collect(Collectors.toList()); // keep order
    }

    private Map<String, Double> getSortedMap(Map<String, Double> map) {
        return map.entrySet()
                .stream()
                .sorted(Map.Entry.<String, Double>comparingByValue(Comparator.reverseOrder()))
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        Map.Entry::getValue,
                        (e1, e2) -> e1, // in case of key collision, which we won't have here
                        LinkedHashMap::new // maintain the order
                ));
    }
}