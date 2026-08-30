package de.upb.ra.metrics;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import lombok.val;
import org.apache.commons.math3.stat.descriptive.moment.Mean;
import org.apache.commons.math3.stat.descriptive.moment.StandardDeviation;
import org.apache.commons.math3.stat.descriptive.rank.Median;

import java.util.*;

@Data
public class SCISForAllMethodsInApp {
    private final Set<SecurityCriticalityForAClass> sclForAllClasses = Collections.synchronizedSet(new HashSet<>());

    @Getter
    @Setter
    private HashMap<String, Double> globalMinSCIS = new HashMap<>();

    @Getter
    @Setter
    private HashMap<String, Double> globalMaxSCIS = new HashMap<>();

    public void add(SecurityCriticalityForAClass sclForAClass) {
        this.sclForAllClasses.add(sclForAClass);
    }

    private Map<String, Boolean> getDataForNormalization() {
        val categoryToOutliers = new HashMap<String, Boolean>();
        val categoryToData = new HashMap<String, List<Double>>();

        for (val sclForAClass : sclForAllClasses) {
            for (val sclForAMethod : sclForAClass.getSclForAllMethods()) {
                for (val category : sclForAMethod.getCAMS().getSecurityCharacteristics().getWeaknessCategories().entrySet()) {
                    val categoryName = category.getKey();

                    categoryToData.putIfAbsent(categoryName, new ArrayList<>());
                    categoryToData.get(categoryName).add(category.getValue().getLowLevelMeasure().getSecurityExposureScore());
                }
            }
        }

        for (val categoryData : categoryToData.entrySet()) {
            if (detectOutliersZScore(categoryData.getValue().stream().mapToDouble(Double::doubleValue).toArray())) {
                System.out.println("Outliers detected for the weakness category = " + categoryData.getKey());
                categoryToOutliers.put(categoryData.getKey(), true);
            } else {
                System.out.println("Outliers not detected for the weakness category = " + categoryData.getKey());
                categoryToOutliers.put(categoryData.getKey(), false);
            }
        }

        return categoryToOutliers;
    }

    // Method to detect outliers using Z-score
    public boolean detectOutliersZScore(double[] data) {
        // Calculate mean and standard deviation
        Mean mean = new Mean();
        StandardDeviation stdDev = new StandardDeviation();

        double dataMean = mean.evaluate(data);
        double dataStdDev = stdDev.evaluate(data);

        for (double value : data) {
            double zScore = (value - dataMean) / dataStdDev;
            System.out.println("Z score = " + zScore);
            if (Math.abs(zScore) > 3) {  // Threshold is typically 3
                return true;  // Outlier found
            }
        }

        return false;  // No outliers found
    }

    // Method to detect outliers using IQR
    public boolean detectOutliersIQR(double[] data) {
        Arrays.sort(data);

        // Calculate Q1 and Q3 (Quartiles)
        Median median = new Median();
        double Q1 = median.evaluate(Arrays.copyOfRange(data, 0, data.length / 2));
        double Q3 = median.evaluate(Arrays.copyOfRange(data, (data.length + 1) / 2, data.length));

        double IQR = Q3 - Q1;

        // Calculate lower and upper bounds
        double lowerBound = Q1 - 1.5 * IQR;
        double upperBound = Q3 + 1.5 * IQR;

        // Check for outliers
        for (double value : data) {
            if (value < lowerBound || value > upperBound) {
                return true;  // Outlier found
            }
        }
        return false;  // No outliers found
    }

    private void computeMinMax(Set<String> categoriesName) {
        for (val categoryName : categoriesName) {
            globalMinSCIS.put(categoryName, 999999.9);
            globalMaxSCIS.put(categoryName, -999999.9);

        }

        for (val sclForAClass : sclForAllClasses) {
            HashMap<String, Double> classLevelMin = new HashMap<>();
            HashMap<String, Double> classLevelMax = new HashMap<>();

            for (val categoryName : categoriesName) {
                classLevelMin.put(categoryName, 999999.9);
                classLevelMax.put(categoryName, -999999.9);

            }

            for (val sclForAMethod : sclForAClass.getSclForAllMethods()) {
                for (val categoryName : categoriesName) {
                    val category = sclForAMethod.getCAMS().getSecurityCharacteristics().getWeaknessCategories().get(categoryName);

                    double secExposureScore = 0.0;

                    if (category != null) {
                        // secExposureScore = propToOutliers.get(prop.getPropertyName())? prop.getLowLevelMeasure().getLogNormalizedSecurityExposureScore() : prop.getLowLevelMeasure().getSecurityExposureScore();
                        secExposureScore = category.getLowLevelMeasure(). getLogNormalizedSecurityExposureScore();
                    }

                    if (secExposureScore > classLevelMax.get(categoryName)) {
                        classLevelMax.put(categoryName, secExposureScore);
                    }

                    if (secExposureScore < classLevelMin.get(categoryName)) {
                        classLevelMin.put(categoryName, secExposureScore);
                    }
                }
            }

            sclForAClass.setClassLevelMinSCl(classLevelMin);
            sclForAClass.setClassLevelMaxSCl(classLevelMax);

            for (val categoryName : categoriesName) {
                if (classLevelMax.get(categoryName) > globalMaxSCIS.get(categoryName)) {
                    globalMaxSCIS.put(categoryName, classLevelMax.get(categoryName));
                }

                if (classLevelMin.get(categoryName) < globalMinSCIS.get(categoryName)) {
                    globalMinSCIS.put(categoryName, classLevelMin.get(categoryName));
                }
            }
        }
    }

    public Set<SecurityCriticalityForAClass> normalizeAndGetSCIS(Set<String> categoriesName) {
        // val propToOutliers = getDataForNormalization();
        computeMinMax(categoriesName);

        for (val sclForAClass : this.sclForAllClasses) {
            for (val sclForAMethod : sclForAClass.getSclForAllMethods()) {
                //Todo: avoid divide by zero problem here

                for (val category : sclForAMethod.getCAMS().getSecurityCharacteristics().getWeaknessCategories().values()) {
                    // val secExpoScore = propToOutliers.get(prop.getPropertyName())? prop.getLowLevelMeasure().getLogNormalizedSecurityExposureScore() : prop.getLowLevelMeasure().getSecurityExposureScore();
                    val secExpoScore = category.getLowLevelMeasure().getLogNormalizedSecurityExposureScore();
                    val globalDifference = (globalMaxSCIS.get(category.getCategoryName()) + 1) - globalMinSCIS.get(category.getCategoryName());

                    val normalizedScl = ((secExpoScore - globalMinSCIS.get(category.getCategoryName())) / globalDifference);

                    sclForAMethod.setMinMaxNormValue(normalizedScl);
                    category.getLowLevelMeasure().setNormalizedSecurityExposureScore(normalizedScl);
                }
            }
        }

        return this.sclForAllClasses;
    }
}
