package de.upb.ra.data.srmUtils.oldSrmDataset;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.val;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class OldSrmDatasetReader {
    private final String srmDatasetFilePath;
    private final OldSrmDataset srmDataset;

    public OldSrmDatasetReader(String srmDatasetFilePath) {
        this.srmDatasetFilePath = srmDatasetFilePath;
        this.srmDataset = getSrmDataset();
    }

    public OldSrmDataset getSrmDataset() {
        if (srmDataset != null)
            return srmDataset;

        ObjectMapper objectMapper = new ObjectMapper();

        try {
            // Read the JSON file and map it to the SrmMethodData class
            File jsonFile = new File(this.srmDatasetFilePath);

            return objectMapper.readValue(jsonFile, OldSrmDataset.class);
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(-1);
        }

        return null;
    }

    public Map<String, OldSrmMethodInfo> getSigToMethodInfo() {
        val result = new HashMap<String, OldSrmMethodInfo>();

        for (val srmMethodInfo : this.srmDataset.getMethods()) {
            if (result.containsKey(srmMethodInfo.getMethodSigWithOutSpaceBetweenParams())) {
                System.out.println("Key already there");
                System.exit(-1);
            }


            result.put(srmMethodInfo.getMethodSigWithOutSpaceBetweenParams(), srmMethodInfo);
        }

        return result;
    }
}
