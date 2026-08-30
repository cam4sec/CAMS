package de.upb.ra.methodSigUtil;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import lombok.val;

import java.util.regex.Pattern;

/**
 * Parser to parse the given method signature string
 *
 * @author Ranjith K
 * @date 19.07.24
 */
@Slf4j
@Getter
public class SootMethodSignatureParser {
    private String methodName;
    private String className;
    private String returnType;
    private String[] parametersType;

    public SootMethodSignatureParser(String methodSignature) {
        // Regular expression to match the method signature
        val regex = "^([^:]+):\\s+([^\\s]+)\\s+([^\\(]+)\\(([^\\)]*)\\)$";
        val pattern = Pattern.compile(regex);
        val matcher = pattern.matcher(methodSignature);

        if (matcher.find()) {
            // Extract the class name
            this.className = matcher.group(1);
            this.returnType = matcher.group(2);
            this.methodName = matcher.group(3);

            // Extract the parameters
            val params = matcher.group(4);
            this.parametersType = params.isEmpty() ? new String[0] : params.split(",\\s*");
        } else {
            log.error("Method signature could not be parsed for " + methodSignature);
        }
    }
}
