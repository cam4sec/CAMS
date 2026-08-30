package de.upb.ra.data.srmUtils;

import com.fasterxml.jackson.databind.ObjectMapper;
import iem.fraunhofer.srm.catalog.Catalog;
import iem.fraunhofer.srm.catalog.CatalogLoader;
import iem.fraunhofer.srm.catalog.Method;
import lombok.val;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

public class SrmDatasetReader {
    private final InputStream srmCatalogStream;
    private Catalog srmCatalog;
    private final Map<String, Method> srmMethodInfoList;

    public SrmDatasetReader(InputStream srmCatalogStream) {
        this.srmCatalogStream = srmCatalogStream;
        this.srmMethodInfoList = new HashMap<>();
    }

    public Map<String, Method> getSrmDataset() {
        if (srmCatalog != null)
            return srmMethodInfoList;

        ObjectMapper objectMapper = new ObjectMapper();

        try {
            CatalogLoader catalogLoader = new CatalogLoader();
            this.srmCatalog = catalogLoader.importFile(this.srmCatalogStream);

            for (val srmMethodInfo : srmCatalog.getMethods()) {
                srmMethodInfoList.put(srmMethodInfo.getCompactMethodSig(), srmMethodInfo);
            }

            return srmMethodInfoList;
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(-1);
        }

        return null;
    }

    public Map<String, Method> getSigToMethodInfo() {
        val result = new HashMap<String, Method>();

        for (val srmMethodInfo : this.srmCatalog.getMethods()) {
            if (result.containsKey(srmMethodInfo.getCompactMethodSig())) {
                System.out.println("Key already there");
                System.exit(-1);
            }


            result.put(srmMethodInfo.getCompactMethodSig(), srmMethodInfo);
        }

        return result;
    }
}