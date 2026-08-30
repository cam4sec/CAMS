package de.upb.ra;

import de.upb.ra.metrics.*;
import de.upb.ra.data.srmUtils.SrmDatasetReader;
import iem.fraunhofer.srm.catalog.Category;
import iem.fraunhofer.srm.catalog.Method;
import lombok.extern.slf4j.Slf4j;
import lombok.val;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Stream;

/**
 * Data reader for the given Srm Json file
 *
 * @author Ranjith K
 */
@Slf4j
public class DataReader {
    private final Map<String, Double> cweWeights;

    public DataReader(Map<String, Double> cweWeights) {
        this.cweWeights = cweWeights;
    }

    public Map<String, WiSeM> loadASwanPredictionDataFile(String resourceName, InputStream srmCatalogStream) {
        log.info("Loading from " + resourceName);
        return getOptimizedSrmMethodInfoFrom(new SrmDatasetReader(srmCatalogStream));
    }

    public Map<String, WiSeM> loadAllSwanPredictionDataFiles(File rootDir) throws FileNotFoundException {
        List<File> jsonFiles = new ArrayList<>();

        if (!rootDir.exists()) {
            log.error("Given path does not exist: " + rootDir.getAbsolutePath());
            System.exit(-1);
        }

        if (!rootDir.isDirectory()) {
            log.error("Given path is not a directory: " + rootDir.getAbsolutePath());
            System.exit(-1);
        }

        try (Stream<Path> paths = Files.list(rootDir.toPath())) {
            jsonFiles.addAll(
                    paths.filter(Files::isRegularFile)
                            .filter(file -> file.toString().endsWith(".json"))
                            .map(Path::toFile)
                            .toList()
            );
        } catch (IOException ex) {
            ex.printStackTrace();
            System.exit(-1);
        }

        Map<String, WiSeM> data = new HashMap<>();

        for (File jsonFile : jsonFiles) {
            val returnedData = loadASwanPredictionDataFile(jsonFile.getAbsolutePath(), new FileInputStream(jsonFile));
            log.info("Loaded " + returnedData.size() + " records from " + jsonFile);
            data.putAll(returnedData);
        }

        return data;
    }

    private Set<TaintSpecificScoredSrm> getTaintSpecificScoredFrom(Set<Category> srms) {
        val taintSpecificScoredSrms = new HashSet<TaintSpecificScoredSrm>();


        for (Category category : srms) {
            if (!(category == Category.SOURCE) &&
                    !(category == Category.SINK) &&
                    !(category == Category.SANITIZER) &&
                    !(category == Category.PROPAGATOR)) {
                continue;
            }

            val srm = category.name();
            val temp = srm.split(":");

            if (temp.length == 1) {
                taintSpecificScoredSrms.add(new TaintSpecificScoredSrm(
                        TaintSpecificSrm.valueOf(temp[0].toUpperCase()),
                        1.0)
                );
            } else if (temp.length == 2) {
                try {
                    TaintSpecificSrm taintType = TaintSpecificSrm.valueOf(temp[0].toUpperCase());
                    taintSpecificScoredSrms.add(new TaintSpecificScoredSrm(
                            taintType,
                            Double.parseDouble(temp[1])
                    ));
                } catch (IllegalArgumentException e) {
                    log.warn("Invalid TaintSpecificSrm type: " + temp[0]);
                    continue;
                }
            }
        }

        return taintSpecificScoredSrms;
    }

    private Set<CweSpecificScoredSrm> getCweSpecificScoredFrom(Set<Category> srms) {
        val cweSpecificScoredSrms = new HashSet<CweSpecificScoredSrm>();

        for (Category category : srms) {
            val srm = category.name();
            val temp = srm.split(":");
            val cwe = temp[0].toUpperCase().replace("-", "").replace("CWE", "CWE-");

            if (!cweWeights.containsKey(cwe)) {
                return null;
            }

            if (temp.length == 1) {
                cweSpecificScoredSrms.add(new CweSpecificScoredSrm(
                        new CweSpecificSrm(cwe, cweWeights.get(cwe)),
                        1.0)
                );
            } else if (temp.length == 2) {
                cweSpecificScoredSrms.add(new CweSpecificScoredSrm(
                        new CweSpecificSrm(cwe, cweWeights.get(cwe)),
                        Double.parseDouble(temp[1])
                ));
            }
        }

        return cweSpecificScoredSrms;
    }

    private Map<String, WiSeM> getOptimizedSrmMethodInfoFrom(SrmDatasetReader oldSrmDatasetReader) {
        val optimizedSrmMethodInfoMap = new HashMap<String, WiSeM>();
        for (Method oldSrmMethodInfo : oldSrmDatasetReader.getSrmDataset().values()) {
            // Split the string at the dot
            String[] parts = oldSrmMethodInfo.getName().split("\\.");

            // Extract className and methodName
            String className = String.join(".", java.util.Arrays.copyOfRange(parts, 0, parts.length - 1));
            String methodName = parts[parts.length - 1];

            val methodSig = className + ": " + oldSrmMethodInfo.getReturnType() + " " +
                    methodName + "(" + String.join(",", oldSrmMethodInfo.getParameters()) +
                    ")";
            val taintSpecificScoredSrms = getTaintSpecificScoredFrom(oldSrmMethodInfo.getSrm());
            val cweSpecificScoredSrms = getCweSpecificScoredFrom(oldSrmMethodInfo.getCwe());

            if (cweSpecificScoredSrms == null) {
                continue;
            }

            if (taintSpecificScoredSrms.isEmpty() || cweSpecificScoredSrms.isEmpty()) {
                continue;
            }

            optimizedSrmMethodInfoMap.put(methodSig, new WiSeM(methodSig, taintSpecificScoredSrms, cweSpecificScoredSrms));
        }

        return optimizedSrmMethodInfoMap;
    }
}
