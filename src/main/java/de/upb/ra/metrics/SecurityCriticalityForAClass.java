package de.upb.ra.metrics;

import lombok.Data;
import lombok.Getter;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

@Data
public class SecurityCriticalityForAClass {
    private final String clazz;
    private final Set<SCISForAMethod> sclForAllMethods = Collections.synchronizedSet(new HashSet<>());
    @Getter
    private HashMap<String, Double> classLevelMinSCl;
    @Getter
    private HashMap<String, Double> classLevelMaxSCl;

    public void add(SCISForAMethod sclForAMethod) {
        this.sclForAllMethods.add(sclForAMethod);
    }
}
