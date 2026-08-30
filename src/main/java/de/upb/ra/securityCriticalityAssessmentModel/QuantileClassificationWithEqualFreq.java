package de.upb.ra.securityCriticalityAssessmentModel;

import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instances;
import weka.filters.Filter;
import weka.filters.unsupervised.attribute.Discretize;

import java.util.*;

public class QuantileClassificationWithEqualFreq {

    /**
     * Discretize scores into qualitative labels.
     *
     * @param nameToScore     map of method name -> score (insertion order preserved if LinkedHashMap)
     * @param bins            desired number of bins (e.g., 3 for Low/Med/High)
     * @param equalFrequency  false = equal-width (cut), true = equal-frequency (qcut-like)
     * @param labels          labels for bins (index 0 is lowest bin). If null, auto-generates.
     * @return LinkedHashMap preserving input order: method name -> label
     */
    public static LinkedHashMap<String, String> discretize(
            Map<String, Double> nameToScore,
            int bins,
            boolean equalFrequency,
            List<String> labels
    ) throws Exception {

        // Preserve input order (use LinkedHashMap for predictable output order)
        List<Map.Entry<String, Double>> entries = new ArrayList<>(nameToScore.entrySet());

        // Build a 1-column WEKA dataset of the scores
        ArrayList<Attribute> attrs = new ArrayList<>();
        attrs.add(new Attribute("score"));
        Instances data = new Instances("scores", attrs, entries.size());
        for (Map.Entry<String, Double> e : entries) {
            DenseInstance inst = new DenseInstance(1);
            inst.setValue(0, e.getValue());
            data.add(inst);
        }

        // Configure Discretize
        Discretize disc = new Discretize();
        disc.setBins(bins);
        disc.setUseEqualFrequency(equalFrequency); // true => quantile/equal-frequency
        disc.setUseBinNumbers(true);               // output "0","1",... so we can map to labels
        disc.setAttributeIndices("first-last");
        disc.setInputFormat(data);

        // Apply filter
        Instances binned = Filter.useFilter(data, disc);

        // If labels not provided, generate defaults
        int actualBins = binned.attribute(0).numValues(); // may be < requested if duplicates force fewer bins
        if (labels == null || labels.size() < actualBins) {
            labels = new ArrayList<>();
            for (int i = 0; i < actualBins; i++) labels.add("Category " + (i + 1));
        }

        // Build output map (preserve original order)
        LinkedHashMap<String, String> out = new LinkedHashMap<>();
        for (int i = 0; i < binned.numInstances(); i++) {
            String method = entries.get(i).getKey();
            // For nominal attrs, value(0) returns the *index* of the chosen nominal value
            int binIdx = (int) binned.instance(i).value(0);  // 0-based index into binnedAttr's values

            String label;
            if (labels != null && binIdx < labels.size()) {
                label = labels.get(binIdx);
            } else {
                // If you want WEKA's own bin label (e.g., "(1.0-5.5]" or "B1of3"), use:
                // label = binnedAttr.value(binIdx);
                label = "Bin " + binIdx;
            }
            out.put(method, label);
        }

        return out;
    }
}
