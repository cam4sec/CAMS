package de.upb.ra.data.srmUtils;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.val;

import java.util.Collections;
import java.util.List;

@Data
@NoArgsConstructor
public class SrmMethodInfo {
    private String name;
    private List<String> parameters;
    private String signature;
    private String framework;
    private String link;
    private String comment;
    private String discovery;
    private DataInOut dataIn;
    private DataInOut dataOut;
    private List<String> srm;
    private List<String> cwe;
    private boolean known;
    private String body;
    private Javadoc javadoc;
    private boolean applicationMethod;
    @JsonProperty("return")
    private String returnType;
    @JsonProperty("interface")
    private boolean _interface;
    @JsonProperty("jar")
    private String jar;
    private Artifacts artifacts;
    private List<Usage> usages;

    public static SrmMethodInfo getInstance(String methodName,
                                            String methodSig,
                                            String returnType,
                                            List<String> params,
                                            boolean isInterface,
                                            boolean isApplicationMethod,
                                            String jarName,
                                            String methodBody,
                                            Javadoc javadoc,
                                            List<Usage> usages) {
        val newSrmMethodInfo = new SrmMethodInfo();

        newSrmMethodInfo.setSrm(Collections.<String>emptyList());
        newSrmMethodInfo.setApplicationMethod(isApplicationMethod);
        newSrmMethodInfo.setCwe(Collections.<String>emptyList());
        newSrmMethodInfo.setBody(methodBody);
        newSrmMethodInfo.setComment("");
        newSrmMethodInfo.set_interface(isInterface);
        newSrmMethodInfo.setDataIn(DataInOut.defaultDataInOut());
        newSrmMethodInfo.setDataOut(DataInOut.defaultDataInOut());
        newSrmMethodInfo.setDiscovery("");
        newSrmMethodInfo.setFramework("");
        val artifacts = new Artifacts();
        artifacts.setSources(jarName);
        newSrmMethodInfo.setArtifacts(artifacts);
        newSrmMethodInfo.setJavadoc(javadoc);
        newSrmMethodInfo.setKnown(false);
        newSrmMethodInfo.setLink("");
        newSrmMethodInfo.setJar(jarName);
        newSrmMethodInfo.setName(methodName);
        newSrmMethodInfo.setParameters(params);
        newSrmMethodInfo.setReturnType(returnType);
        newSrmMethodInfo.setSignature(methodSig);
        newSrmMethodInfo.setUsages(usages);

        return newSrmMethodInfo;
    }

    public SrmMethodInfo cloneObject() {
        val newSrmMethodInfo = new SrmMethodInfo();

        newSrmMethodInfo.setSrm(this.srm);
        newSrmMethodInfo.setApplicationMethod(this.applicationMethod);
        newSrmMethodInfo.setCwe(this.cwe);
        newSrmMethodInfo.setBody(this.body);
        newSrmMethodInfo.setComment(this.comment);
        newSrmMethodInfo.set_interface(this._interface);
        newSrmMethodInfo.setDataIn(this.dataIn.cloneObject());
        newSrmMethodInfo.setDataOut(this.dataOut.cloneObject());
        newSrmMethodInfo.setDiscovery(this.discovery);
        newSrmMethodInfo.setFramework(this.framework);
        newSrmMethodInfo.setArtifacts(this.artifacts);
        newSrmMethodInfo.setUsages(this.usages);
        newSrmMethodInfo.setJavadoc(this.javadoc.cloneObject());
        newSrmMethodInfo.setKnown(this.known);
        newSrmMethodInfo.setLink(this.link);
        newSrmMethodInfo.setName(this.name);
        newSrmMethodInfo.setParameters(this.parameters);
        newSrmMethodInfo.setReturnType(this.returnType);
        newSrmMethodInfo.setSignature(this.signature);

        return newSrmMethodInfo;
    }

    @JsonIgnore
    public String getMethodSigWithOutSpaceBetweenParams() {
        return returnType + " " + name + "(" + String.join(",", parameters) + ")";
    }

    @Data
    @NoArgsConstructor
    public static class DataInOut {
        private List<String> parameters;
        @JsonProperty("return")
        private boolean returnFlag;

        public DataInOut cloneObject() {
            val newDataInOut = new DataInOut();

            newDataInOut.setParameters(this.parameters);
            newDataInOut.setReturnFlag(this.returnFlag);

            return newDataInOut;
        }

        public static DataInOut defaultDataInOut() {
            val dataInOut = new DataInOut();
            dataInOut.setReturnFlag(false);
            dataInOut.setParameters(Collections.<String>emptyList());

            return dataInOut;
        }
    }

    @Data
    @NoArgsConstructor
    public static class Javadoc {
        private String method;
        @JsonProperty("class")
        private String classDoc;

        public Javadoc cloneObject() {
            val newJavadoc = new Javadoc();

            newJavadoc.setMethod(this.method);
            newJavadoc.setClassDoc(this.classDoc);

            return newJavadoc;
        }
    }

    @Data
    @NoArgsConstructor
    public static class Artifacts {
        private String identifier;
        private String sources;
        private String compiled;

        public Artifacts cloneObject() {
            val newArtifacts = new Artifacts();

            newArtifacts.setIdentifier(this.identifier);
            newArtifacts.setSources(this.sources);
            newArtifacts.setCompiled(this.compiled);

            return newArtifacts;
        }
    }

    @Data
    @NoArgsConstructor
    public static class Usage {
        private String path;
        private int lineNumber;

        public Usage cloneObject() {
            val newUsage = new Usage();

            newUsage.setPath(this.path);
            newUsage.setLineNumber(this.lineNumber);

            return newUsage;
        }
    }
}