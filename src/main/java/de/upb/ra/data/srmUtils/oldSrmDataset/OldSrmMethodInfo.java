package de.upb.ra.data.srmUtils.oldSrmDataset;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.val;

import java.util.Collections;
import java.util.List;
import java.util.Set;

@Data
@NoArgsConstructor
public class OldSrmMethodInfo {
    private String name;
    private List<String> parameters;
    private String signature;
    private String framework;
    private String link;
    private String comment;
    private String discovery;
    private DataInOut dataIn;
    private DataInOut dataOut;
    private Set<String> srm;
    private Set<String> cwe;
    private boolean known;
    private String body;
    private Javadoc javadoc;
    private boolean applicationMethod;
    @JsonProperty("return")
    private String returnType;
    @JsonProperty("interface")
    private boolean _interface;
    private String jar;

    public static OldSrmMethodInfo getInstance(String methodName,
                                               String methodSig,
                                               String returnType,
                                               List<String> params,
                                               boolean isInterface,
                                               boolean isApplicationMethod,
                                               String jarName,
                                               String methodBody,
                                               Javadoc javadoc) {
        val newSrmMethodInfo = new OldSrmMethodInfo();

        newSrmMethodInfo.setSrm(Collections.emptySet());
        newSrmMethodInfo.setApplicationMethod(isApplicationMethod);
        newSrmMethodInfo.setCwe(Collections.emptySet());
        newSrmMethodInfo.setBody(methodBody);
        newSrmMethodInfo.setComment("");
        newSrmMethodInfo.set_interface(isInterface);
        newSrmMethodInfo.setDataIn(DataInOut.defaultDataInOut());
        newSrmMethodInfo.setDataOut(DataInOut.defaultDataInOut());
        newSrmMethodInfo.setDiscovery("");
        newSrmMethodInfo.setFramework("");
        newSrmMethodInfo.setJar(jarName);
        newSrmMethodInfo.setJavadoc(javadoc);
        newSrmMethodInfo.setKnown(false);
        newSrmMethodInfo.setLink("");
        newSrmMethodInfo.setName(methodName);
        newSrmMethodInfo.setParameters(params);
        newSrmMethodInfo.setReturnType(returnType);
        newSrmMethodInfo.setSignature(methodSig);

        return newSrmMethodInfo;
    }

    public OldSrmMethodInfo cloneObject() {
        val newSrmMethodInfo = new OldSrmMethodInfo();

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
        newSrmMethodInfo.setJar(this.jar);
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
        return this.signature
                .replaceAll("\\(\\s+", "\\(")   // Removes space after opening parenthesis
                .replaceAll(",\\s+", ",")       // Removes space after commas
                .replaceAll("\\s+\\)", "\\)");  // Removes space before closing parenthesis
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
            dataInOut.setParameters(Collections.emptyList());

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
}
