package de.upb.ra;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.upb.ra.metrics.*;
import de.upb.ra.securityCriticalityAssessmentModel.LowLevelMeasure;
import de.upb.ra.securityCriticalityAssessmentModel.CAMS;
import de.upb.ra.securityCriticalityAssessmentModel.SecurityCharacteristics;
import de.upb.ra.securityCriticalityAssessmentModel.WeaknessCategory;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import soot.SootMethod;
import soot.tagkit.AnnotationTag;
import soot.tagkit.Tag;
import soot.tagkit.VisibilityAnnotationTag;

import java.io.File;
import java.io.IOException;
import java.util.*;

@Slf4j
public class SCLCalculator {
    private final CAMSConfiguration config;

    public SCLCalculator(CAMSConfiguration secumetricsConfiguration) {
        this.config = secumetricsConfiguration;
    }

    private WiSeM getMatchedSrm(Map<Integer, Map<String, WiSeM>> srms, String methodSig) {
        int index = 1;

        for (int i = index; i <= srms.size(); i++) {
            if (srms.get(i).containsKey(methodSig)) {
                return srms.get(i).get(methodSig);
            }
        }

        return null;
    }

    private static boolean hasResponseBody(SootMethod method) {
        for (Tag tag : method.getTags()) {
            if (tag instanceof VisibilityAnnotationTag vat) {
                for (AnnotationTag at : vat.getAnnotations()) {
                    if (at.getType().equals("Lorg/springframework/web/bind/annotation/ResponseBody;")) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    public SCISForAllMethodsInApp computeWiSeM(Map<Integer, Map<String, WiSeM>> srms) {
        val sclForAllMethodsInApp = new SCISForAllMethodsInApp(); // Complete methods in the app

        for (val appClass : config.getJimpleProvider().getAllApplicationClasses()) {
            if (config.getRootPackage() != null && !appClass.getName().startsWith(config.getRootPackage())) {
                continue;
            }

            val sclForAClass = new SecurityCriticalityForAClass(appClass.getName()); // all methods in a class

            for (val classMethod : new ArrayList<>(appClass.getMethods())) {
                // Weakness Category to its associated invoked SRM in the current method
                HashMap<String, List<WiSeM>> categoryToInvokedSrmMap = new HashMap<>();

                //TODO: Check for ResponseBody (also RequestParam) annotation here and add that to the basemetricinfo
                if (!config.isIgnoreDefaultAnnotationSrms() && hasResponseBody(classMethod)) {
                    if (config.getCweToWeaknessCategoryMap().containsKey("CWE-80")) {

                        val srm = new WiSeM(
                                "@ResponseBody",
                                Set.of(new TaintSpecificScoredSrm(TaintSpecificSrm.SINK, 1.0)),
                                Set.of(new CweSpecificScoredSrm(new CweSpecificSrm("CWE-80", config.getCweWeightsMap().get("CWE-80")), 1.0))
                        );

                        val category = config.getCweToWeaknessCategoryMap().get("CWE-80");
                        categoryToInvokedSrmMap.putIfAbsent(category, new ArrayList<>());
                        categoryToInvokedSrmMap.get(category).add(srm);
                    }

                }

                for (val invokedMethod : config.getJimpleProvider().getAllInvokedMethodSignature(appClass.getName(), classMethod.getSignature())) {
                    val sig = invokedMethod.getInvokedMethodSignature().replaceFirst("^<", "").replaceFirst(">$", "");

                    val matchedSrm = getMatchedSrm(srms, sig);
                    if (matchedSrm != null) {
                        // Get the weakness category key once and reuse it
                        String category = matchedSrm.getWeaknessCategoryForTheCwe(config.getCweToWeaknessCategoryMap());

                        categoryToInvokedSrmMap.putIfAbsent(category, new ArrayList<>());
                        categoryToInvokedSrmMap.get(category).add(matchedSrm);
                    }
                }

                val methodName = classMethod.getSignature().replaceFirst("^<", "").replaceFirst(">$", "");
                SCISForAMethod sclForAMethod = new SCISForAMethod(
                        methodName,
                        getCAMS(categoryToInvokedSrmMap)
                );
                sclForAClass.add(sclForAMethod);
            }

            if (sclForAClass.getSclForAllMethods().size() > 0) {
                sclForAllMethodsInApp.add(sclForAClass);
            }
        }

        return sclForAllMethodsInApp;
    }

    private CAMS getCAMS(Map<String, List<WiSeM>> categoryToInvokedSrmMap) {
        val weaknessCategories = new HashMap<String, WeaknessCategory>();

        for (val categoryToInvokedSrm : categoryToInvokedSrmMap.entrySet()) {
            val lowLevelMeasure = new LowLevelMeasure(categoryToInvokedSrm.getValue());
            val weaknessCategory = new WeaknessCategory(categoryToInvokedSrm.getKey(), lowLevelMeasure, config.getImpactScoreMap().get(categoryToInvokedSrm.getKey()));
            weaknessCategories.put(categoryToInvokedSrm.getKey(), weaknessCategory);
        }

        val securityCharacteristics = new SecurityCharacteristics(weaknessCategories, config.getWeaknessCategories(), config.getImpactScoreMap());
        return new CAMS(securityCharacteristics);
    }

    public void writeWiSeMsToFile(SCISForAllMethodsInApp sclForAllMethods, String fileName) {
        ObjectMapper objectMapper = new ObjectMapper();

        try {
            // Write object to JSON file
            val file = new File(config.getOutputRootDirectory(), fileName);
            objectMapper.writeValue(file, sclForAllMethods);
            log.info("Object has been written to the file: " + file);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
