package de.upb.ra;

import de.fraunhofer.iem.secucheck.FluentTQLClassLoader.ErrorModel;
import de.fraunhofer.iem.secucheck.FluentTQLClassLoader.JarClassLoaderUtils;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.CWE;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.MethodSet;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.QueriesSet;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.ReportMessage;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.dsl.exception.DuplicateTaintFlowQueryIDException;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.MethodPackage.Method;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.Query.TaintFlowQuery;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.SpecificationInterface.FluentTQLUserInterface;
import de.fraunhofer.iem.secucheck.InternalFluentTQL.fluentInterface.TaintFlowPackage.FlowParticipant;
import de.fraunhofer.iem.secucheck.JarUtility;
import de.fraunhofer.iem.secucheck.FluentTQLClassLoader.Errors;
import de.upb.ra.metrics.*;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import lombok.val;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * Loads the given fluentTql specification into {@link WiSeM}
 *
 * @author Ranjith K
 */
@Slf4j
public class FluentTqlProcessor {
    /**
     * HashMap, contains the FluentTQL specification file name and its corresponding FluentTQLUserInterface object.
     */
    private final HashMap<String, FluentTQLUserInterface> fluentTQLSpecs = new HashMap<>();

    private final HashMap<String, Double> cweWeights = new HashMap<>();

    @Getter
    private final Map<String, WiSeM> optimizedSrmMethodInfoMap = new HashMap<>();

    public boolean processFluentTQLSpecificationsPath(String specPath, Map<String, Double> cweWeights) {
        this.cweWeights.putAll(cweWeights);

        if (specPath == null || "".equals(specPath)) {
            log.error("FluentTQL Specification's path is invalid.");
            //isFirstPageDone = false;
            return false;
        }

        File file = new File(specPath);

        if (file.exists()) {
            if (file.isDirectory()) {
                File out = new File(file.getAbsolutePath() + System.getProperty("file.separator") + "fluentTQLTemp");

                File[] files = JarUtility.extractJar(file, out);

                if (files.length == 0) {
                    log.error("Given Path does not have any Jar files.\n" +
                                    "FluentTQL scans upto:\n" +
                                    "Max sub-directories in current dir = 20\n" +
                                    "Max depth of sub-directories = 20");
                    //isFirstPageDone = false;
                    JarUtility.deleteDir(out);
                    return false;
                }

                JarClassLoaderUtils jarClassLoaderUtils = new JarClassLoaderUtils();

                try {
                    fluentTQLSpecs.putAll(jarClassLoaderUtils.loadAppAndGetFluentTQLSpecification(out.getAbsolutePath()));
                } catch (DuplicateTaintFlowQueryIDException e) {
                    log.error(e.getMessage());
                    JarUtility.deleteDir(out);
                    return false;
                }

                JarUtility.deleteDir(out);

                createErrorText(jarClassLoaderUtils.getErrorModel(), out.getAbsolutePath());

                if (fluentTQLSpecs.size() > 0) {
                    storeCompleteTaintFlowQueries();
                    return true;
                } else {
                    log.warn("No FluentTQL specifications present in the given path.");
                    return false;
                }
            } else {
                log.error("Given FluentTQL Specification's path is not a directory. \nPlease give valid directory name.");
                return false;
            }
        } else {
            log.error("Given FluentTQL Specification's path does not exist.");
            return false;
        }
    }

    private List<CweSpecificScoredSrm> getCweSpecificScoredSrms(Set<String> cwes) {
        List<CweSpecificScoredSrm> scoredCwes = new ArrayList<>();

        for (val cwe : cwes) {
            val processedCwe = cwe
                    .toUpperCase()
                    .replace("-", "")
                    .replace("CWE", "CWE-");

            if (!cweWeights.containsKey(processedCwe)) {
                continue;
            }

            scoredCwes.add(new CweSpecificScoredSrm(new CweSpecificSrm(cwe, cweWeights.get(cwe)),1.0));
        }

        return scoredCwes;
    }

    private void processMethod(Method method, String taintSpecificSrm, ReportMessage reportedMessage) {
        TaintSpecificScoredSrm taintSpecificSrmWithScore = new TaintSpecificScoredSrm(TaintSpecificSrm.valueOf(taintSpecificSrm.toUpperCase()), 1.0);

        //TODO: Handle Source methods here because sources' CWE is custom ATTACK_SURFACE which is not yet supported in new model
        val cwes = getCweSpecificScoredSrms(method.getAssociatedCwes());

        if (cwes.isEmpty() && reportedMessage == null) {
            // CWE is not known since reportedMessage is null and could not find cwe info in method.
            return;
        }

        if (reportedMessage != null && (cwes.isEmpty() || !taintSpecificSrm.equalsIgnoreCase("SOURCE"))) {
            val reportedCwe = reportedMessage.getCwe().name()
                    .toUpperCase()
                    .replace("-", "")
                    .replace("CWE", "CWE-");

            if (cweWeights.containsKey(reportedCwe)) {
                val cweInReportedMessage = new CweSpecificScoredSrm(
                        new CweSpecificSrm(reportedCwe, cweWeights.get(reportedCwe)), 1.0
                );

                cwes.add(cweInReportedMessage);
            } else if (cwes.isEmpty()){
                // Still could not find the CWE that is present in our current weakness category.
                //TODO: Handle unknown CWEs
                return;
            }
        }

        if (optimizedSrmMethodInfoMap.containsKey(method.getSignature())) {
            optimizedSrmMethodInfoMap.get(method.getSignature())
                    .getTaintSpecificScoredSrms().add(taintSpecificSrmWithScore);

            optimizedSrmMethodInfoMap.get(method.getSignature())
                    .getCweSpecificScoredSrms().addAll(cwes);
        } else {
            optimizedSrmMethodInfoMap.put(
                    method.getSignature(),
                    new WiSeM(
                            method.getSignature(),
                            new HashSet<>(List.of(taintSpecificSrmWithScore)),
                            new HashSet<>(cwes)
                    )
            );
        }
    }

    private void processFlowParticipant(FlowParticipant flowParticipant, String taintSpecificSrm, ReportMessage reportedMessage) {
        if (flowParticipant instanceof Method) {
            processMethod((Method) flowParticipant, taintSpecificSrm, reportedMessage);
        } else if (flowParticipant instanceof MethodSet) {
            for (val method : ((MethodSet) flowParticipant).getMethods()) {
                processMethod(method, taintSpecificSrm, reportedMessage);
            }
        }
    }

    private void processTFQuery(TaintFlowQuery taintFlowQuery) {
        for (val taintFlow : taintFlowQuery.getTaintFlows()) {
            processFlowParticipant(taintFlow.getFrom(), "source", new ReportMessage("This is source", CWE.ATTACK_SURFACE));
            processFlowParticipant(taintFlow.getTo(), "sink", taintFlowQuery.getReportMessage());

            for (val sanitizer : taintFlow.getNotThrough()) {
                processFlowParticipant(sanitizer, "sanitizer", taintFlowQuery.getReportMessage());
            }

            for (val requiredPropagator : taintFlow.getThrough()) {
                processFlowParticipant(requiredPropagator, "propagator", taintFlowQuery.getReportMessage());
            }
        }
    }

    private void storeCompleteTaintFlowQueries() {
        for (val fluentInterface : fluentTQLSpecs.values()) {
            for (val spec : fluentInterface.getFluentTQLSpecification()) {
                if (spec instanceof TaintFlowQuery) {
                    processTFQuery((TaintFlowQuery) spec);
                } else if (spec instanceof QueriesSet) {
                    val queriesSet = (QueriesSet) spec;
                    for (val tfQuery : queriesSet.getTaintFlowQueries()) {
                        processTFQuery(tfQuery);
                    }
                }
            }
        }
    }

    /**
     * This method creates a FluentTQLError.txt with the errors found while processing the FluentTQL specifications
     *
     * @param errors Errors
     */
    private static void createErrorText(Errors errors, String outRootDir) {
        if (errors.getErrors().size() > 0) {
            File file = new File(outRootDir + System.getProperty("file.separator") + "FluentTQLError.txt");

            try {
                if (file.exists()) {
                    file.delete();
                    file.createNewFile();
                }

                BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(file));

                bufferedWriter.write("FluentTQL:     " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()) + "\n");

                for (ErrorModel errorModel : errors.getErrors()) {
                    bufferedWriter.append(errorModel.toString());
                }

                bufferedWriter.close();
            } catch (IOException e) {
                log.warn(e.getMessage());
            }
            log.warn("There some errors while processing some specifications. Please check the below file for more details.\n" +
                    file.getAbsolutePath());
        }
    }
}
