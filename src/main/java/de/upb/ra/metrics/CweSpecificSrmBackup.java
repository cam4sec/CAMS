package de.upb.ra.metrics;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@JsonFormat(shape = JsonFormat.Shape.OBJECT)
public enum CweSpecificSrmBackup {
    // Related to command injection
    CWE77("CWE77", "Command Injection: Improper Neutralization of Special Elements used in a Command", 8.50),
    CWE78("CWE78", "Command Injection: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')", 8.50),


    CWE90("CWE90", "LDAP Injection: Improper Neutralization of Special Elements used in an LDAP Query",6.53),
    CWE117("CWE117", "Log Injection: Improper Output Neutralization for Logs", 5.74),
    CWE943("CWE943", "NoSql Injection, etc.: Improper Neutralization of Special Elements in Data Query Logic", 9.15),
    CWE601("CWE601", "Open Redirect: URL Redirection to Untrusted Site", 5.93),
    CWE22("CWE22", "Path Traversal: Improper Limitation of a Pathname to a Restricted Directory", 6.36),
    CWE89("CWE89", "SQL InjectionImproper Neutralization of Special Elements used in an SQL Command", 7.35),
    CWE501("CWE501", "Trust Boundary Violation", 7.65),
    CWE643("CWE643", "XPath Injection: Improper Neutralization of Data within XPath Expressions", 5.37),
    CWE79("CWE79", "Cross-site Scripting: Improper Neutralization of Input During Web Page Generation", 4.20),
    ATTACK_SURFACE("ATTACK_SURFACE", "Input that comes from outside world", 4.0),

    // Related to XML Injection
    CWE91("CWE91", "XML Injection: aka Blind XPath Injection", 7.59),
    CWE116("CWE116", "XML Injection: Improper Encoding or Escaping of Output", 7.59),
    CWE611("CWE611", "XML Injection: Improper Restriction of XML External Entity Reference ('XXE')", 7.59),
    CWE776("CWE776", "XML Injection: Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')", 7.59),

    CWE_UNKNOWN("CWE_UNKNOWN", "CWE_UNKNOWN: Provided CWE is not yet supposted. Taking default weight", 4.0);

    public static CweSpecificSrmBackup fromStringOrDefault(String value) {
        try {
            return CweSpecificSrmBackup.valueOf(value);
        } catch (IllegalArgumentException | NullPointerException e) {
            log.warn("Unknown CWE: " + value);
            return CWE_UNKNOWN;
        }
    }

    @Getter
    private final String category;

    @Getter
    private final String categoryName;

    @Getter
    private final double categoryWeight;

    CweSpecificSrmBackup(String category, String categoryName, double categoryWeight) {
        this.category = category;
        this.categoryName = categoryName;
        this.categoryWeight = categoryWeight;
    }

    public Map<String, Object> toMap() {
        Map<String, Object> map = new HashMap<>();
        map.put("category", category);
        map.put("categoryName", categoryName);
        map.put("categoryWeight", categoryWeight);
        return map;
    }

    private List<CweSpecificSrmBackup> getTheCategoryWeightFromPackage(String packageName) {
        if (packageName.startsWith("<java.sql")) {
            return List.of(CWE89);
        }

        if (packageName.startsWith("<java.lang.Process") || packageName.startsWith("<java.lang.Runtime")) {
            return List.of(CWE77);
        }

        if (packageName.startsWith("<com.unboundid.ldap")) {
            return List.of(CWE90);
        }

        if (packageName.startsWith("<java.util.logging")) {
            return List.of(CWE117);
        }

        if (packageName.startsWith("<java.io")) {
            return List.of(CWE22);
        }

        if (packageName.startsWith("<javax.servlet")) {
            return List.of(CWE601, CWE501, CWE79);
        }

        return Collections.emptyList();
    }
}
